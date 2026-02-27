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
   * Robust chunked memory dump with multiple fallback methods.
   * Sends chunks via send() with binary data payload.
   *
   * Message format:
   *   {type: 'chunk', module, seq, offset, final} + binary data
   *   {type: 'error', module, message} for errors
   *
   * @param {string} moduleName - Module to dump
   * @param {number} chunkSize - Bytes per chunk (default: 65536)
   * @returns {boolean} true on success, false on failure
   */
  dumpModuleChunks: function(moduleName, chunkSize) {
    var m = Process.findModuleByName(moduleName);
    if (!m) throw new Error("Module not found: " + moduleName);
    var total = m.size;
    var base = m.base;
    var offset = 0;
    var seq = 0;

    var haveReadByteArray = (typeof Memory.readByteArray === 'function');

    while (offset < total) {
      var size = chunkSize;
      if (offset + size > total) size = total - offset;
      var isFinal = (offset + size) >= total;
      var chunkRead = false;

      // Method 1: Memory.readByteArray (fastest)
      if (!chunkRead && haveReadByteArray) {
        try {
          var buf = Memory.readByteArray(base.add(offset), size);
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: isFinal }, buf);
          chunkRead = true;
        } catch (e1) {}
      }

      // Method 2: Per-byte read with Memory.readU8
      if (!chunkRead) {
        try {
          var arr = new Uint8Array(size);
          for (var i = 0; i < size; i++) {
            arr[i] = Memory.readU8(base.add(offset + i));
          }
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: isFinal }, arr.buffer);
          chunkRead = true;
        } catch (e2) {}
      }

      // Method 3: NativePointer.readByteArray
      if (!chunkRead) {
        try {
          var buf2 = base.add(offset).readByteArray(size);
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: isFinal }, buf2);
          chunkRead = true;
        } catch (e3) {}
      }

      if (!chunkRead) {
        send({
          type: 'error',
          module: moduleName,
          message: 'Memory read failed at offset ' + offset + '. Module may not be readable.'
        });
        send({
          type: 'chunk',
          module: moduleName,
          seq: seq,
          offset: offset,
          final: true,
          failed: true
        }, new ArrayBuffer(0));
        return false;
      }

      offset += size;
      seq += 1;
    }
    return true;
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
