'use strict';

rpc.exports = {
  /**
   * Get module info (base address and size).
   */
  getModuleInfo: function(moduleName) {
    var m = Process.findModuleByName(moduleName);
    if (!m) throw new Error("Module not found: " + moduleName);
    return {
      name: m.name,
      path: m.path || "",
      base: m.base.toString(),
      size: m.size
    };
  },

  /**
   * Robust chunked memory dump that tolerates unreadable pages.
   *
   * Strategy:
   *   1. Enumerate readable ranges in the process and intersect them with the
   *      module's [base, base+size) extent.
   *   2. Emit a 'meta' message with total_size + readable_size + gap_count.
   *   3. Emit a 'gap' message for every unreadable hole inside the module.
   *   4. Dump each readable subrange in chunks using a 3-method fallback;
   *      if a particular chunk still fails (race with munmap, etc.) emit
   *      a runtime 'gap' for that chunk and continue.
   *   5. Emit a terminal 'chunk' with final=true so the Python wait completes.
   *
   * Message format:
   *   {type: 'meta',  module, total_size, readable_size, gap_count}
   *   {type: 'gap',   module, offset, size}
   *   {type: 'chunk', module, seq, offset, final} + binary data
   *   {type: 'error', module, message}  (only for fatal errors)
   *
   * @param {string} moduleName - Module to dump
   * @param {number} chunkSize - Bytes per chunk (default: 65536)
   * @returns {boolean} true if any bytes were read, false otherwise
   */
  dumpModuleChunks: function(moduleName, chunkSize) {
    var m = Process.findModuleByName(moduleName);
    if (!m) throw new Error("Module not found: " + moduleName);
    var total = m.size;
    var base = m.base;
    var modEnd = base.add(total);

    // 1. Enumerate readable ranges (fall back to non-Sync if unavailable).
    var ranges = [];
    try {
      var enumerate = Process.enumerateRangesSync || Process.enumerateRanges;
      ranges = enumerate({ protection: 'r--', coalesce: true });
    } catch (e) {
      ranges = [];
    }

    // 2. Intersect each range with [base, base+total).
    var readable = [];
    for (var i = 0; i < ranges.length; i++) {
      var r = ranges[i];
      var rStart = r.base;
      var rEnd = r.base.add(r.size);
      var iStart = rStart.compare(base) > 0 ? rStart : base;
      var iEnd = rEnd.compare(modEnd) < 0 ? rEnd : modEnd;
      if (iEnd.compare(iStart) > 0) {
        readable.push({
          offset: iStart.sub(base).toUInt32(),
          size: iEnd.sub(iStart).toUInt32()
        });
      }
    }
    readable.sort(function(a, b) { return a.offset - b.offset; });

    // If range enumeration produced nothing, fall back to "treat the whole
    // module as readable" — preserves prior behaviour on Frida builds that
    // don't expose enumerateRanges* with this protection mask.
    if (readable.length === 0) {
      readable.push({ offset: 0, size: total });
    }

    // 3. Compute gaps inside module extent.
    var gaps = [];
    var cursor = 0;
    for (var j = 0; j < readable.length; j++) {
      if (readable[j].offset > cursor) {
        gaps.push({ offset: cursor, size: readable[j].offset - cursor });
      }
      cursor = readable[j].offset + readable[j].size;
    }
    if (cursor < total) gaps.push({ offset: cursor, size: total - cursor });

    var readableBytes = 0;
    for (var k = 0; k < readable.length; k++) readableBytes += readable[k].size;

    // 4. Meta message first so Python can pre-zero the output file.
    send({
      type: 'meta',
      module: moduleName,
      total_size: total,
      readable_size: readableBytes,
      gap_count: gaps.length
    });

    // 5. Static gaps (from range enumeration) emitted before chunk stream.
    for (var g = 0; g < gaps.length; g++) {
      send({ type: 'gap', module: moduleName, offset: gaps[g].offset, size: gaps[g].size });
    }

    var haveReadByteArray = (typeof Memory.readByteArray === 'function');

    function tryRead(addr, size) {
      if (haveReadByteArray) {
        try { return Memory.readByteArray(addr, size); } catch (e1) {}
      }
      try { return addr.readByteArray(size); } catch (e2) {}
      try {
        var arr = new Uint8Array(size);
        for (var ii = 0; ii < size; ii++) arr[ii] = Memory.readU8(addr.add(ii));
        return arr.buffer;
      } catch (e3) {}
      return null;
    }

    // 6. Dump each readable subrange chunk-by-chunk.
    var seq = 0;
    var anyBytes = false;
    for (var rIdx = 0; rIdx < readable.length; rIdx++) {
      var off = readable[rIdx].offset;
      var rem = readable[rIdx].size;
      while (rem > 0) {
        var sz = rem < chunkSize ? rem : chunkSize;
        var buf = tryRead(base.add(off), sz);
        if (buf === null) {
          // Runtime gap: enumeration said readable but the read still faulted.
          send({ type: 'gap', module: moduleName, offset: off, size: sz });
        } else {
          send({ type: 'chunk', module: moduleName, seq: seq, offset: off, final: false }, buf);
          seq += 1;
          anyBytes = true;
        }
        off += sz;
        rem -= sz;
      }
    }

    // 7. Terminal sentinel so Python's done.set() fires.
    send({ type: 'chunk', module: moduleName, seq: seq, offset: total, final: true }, new ArrayBuffer(0));
    return anyBytes;
  },

  /**
   * Read a file from the device filesystem via Frida.
   * Used for iOS extraction where adb is not available.
   *
   * @param {string} filePath - Path to file on device
   * @param {number} chunkSize - Bytes per chunk
   * @returns {boolean} true on success
   */
  readFileChunks: function(filePath, chunkSize) {
    try {
      var f = new File(filePath, 'rb');
    } catch (e) {
      send({ type: 'error', module: filePath, message: 'Cannot open file: ' + e.message });
      return false;
    }

    var seq = 0;
    while (true) {
      try {
        var data = f.readBytes(chunkSize);
        if (data.byteLength === 0) {
          send({ type: 'chunk', module: filePath, seq: seq, offset: -1, final: true }, new ArrayBuffer(0));
          break;
        }
        var isFinal = data.byteLength < chunkSize;
        send({ type: 'chunk', module: filePath, seq: seq, offset: -1, final: isFinal }, data);
        if (isFinal) break;
        seq++;
      } catch (e) {
        send({ type: 'error', module: filePath, message: 'Read error: ' + e.message });
        send({ type: 'chunk', module: filePath, seq: seq, offset: -1, final: true, failed: true }, new ArrayBuffer(0));
        f.close();
        return false;
      }
    }
    f.close();
    return true;
  }
};
