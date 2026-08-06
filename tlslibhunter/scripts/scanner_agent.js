'use strict';

// --- Tuning constants ---
// Giant/obfuscated native libs (cronet, webview, monochrome, mapbox, llvm) are
// scanned in bounded windows rather than in one unbounded pass. We never
// deny-list them: they may statically link a renamed TLS library.
var SCAN_CHUNK_SIZE = 48 * 1024 * 1024;     // 48 MB scan window
var MAX_WRITABLE_RANGE = 64 * 1024 * 1024;  // cap for writable (heap/stack) ranges
var SCAN_TIMEOUT_MS = 120000;               // safety net so a hung native scan can't deadlock the RPC
var MAX_PLAUSIBLE_MODULE_RANGE = 64 * 1024 * 1024;  // floor for the per-module range cap; see moduleScanRegions
var MAX_SPLIT_MATCHES = 4096;               // cap on retained split-constant addresses per range

/**
 * The memory regions that actually belong to *m*, as [{base, size}].
 *
 * `Module.enumerateRanges('r')` is the natural primitive, and the module-level
 * API is the right choice because dyld-shared-cache segments are genuinely
 * non-contiguous (libboringssl's __TEXT sits ~2 GB away from its __DATA_CONST).
 * But on Apple platforms it also reports, for EVERY cache image, one enormous
 * read-only range that belongs to the cache as a whole rather than to the
 * module. Measured on macOS 26.3.1 arm64, every single image carried the same
 * 587.3 MB region at 0x206aa4000:
 *
 *     module                       m.size    range total   section total
 *     libcoretls_cfhelpers.dylib   6.1 KB    587.4 MB      5.0 KB
 *     libcoretls.dylib            93.7 KB    587.4 MB     95.8 KB
 *     libboringssl.dylib         851.6 KB    588.2 MB    922.7 KB
 *     6 modules, total                        3.5 GB      31.2 MB
 *
 * Scanning that region once per module per pattern is what made a six-module
 * scan read ~106 GB and take ~113 s: a 6.1 KB module was scanning 587.4 MB,
 * 119,264x its own size. It cannot pay for itself either — it is shared, so it
 * is not attributable to any one module, and a TLS implementation is not in it.
 *
 * So we drop ranges that are implausibly large for the module in question and
 * keep everything else. That is deliberately more conservative than switching to
 * `Module.enumerateSections()`: sections are exact, and on every module measured
 * they agreed with this filter to within a few percent — but they only describe
 * memory the section headers know about, and this tool exists partly to find TLS
 * code inside packed or stripped libraries whose payload may be mapped without
 * appearing in any section header. Filtering keeps those; sections would not.
 *
 * The floor matters as much as the multiple: `m.size` is only the primary
 * mapping (on the shared cache, only __TEXT), so a small module must still be
 * allowed its normal data segments. Hence the cap never drops below
 * MAX_PLAUSIBLE_MODULE_RANGE.
 *
 * @param {Module} m - Module instance (from Process.findModuleByName)
 * @returns {{regions: Array, skippedBytes: number, skippedCount: number}}
 */
function moduleScanRegions(m) {
  var cap = m.size * 4;
  if (cap < MAX_PLAUSIBLE_MODULE_RANGE) {
    cap = MAX_PLAUSIBLE_MODULE_RANGE;
  }

  var regions = [];
  var skippedBytes = 0;
  var skippedCount = 0;
  var ranges = m.enumerateRanges('r');
  for (var i = 0; i < ranges.length; i++) {
    if (ranges[i].size > cap) {
      skippedBytes += ranges[i].size;
      skippedCount++;
      continue;
    }
    regions.push({ base: ranges[i].base, size: ranges[i].size });
  }

  if (skippedCount > 0) {
    // Never silent: dropping a range is a coverage decision, so say so. The
    // caller also gets the counts back for the Python side to surface.
    console.log('[tlslibhunter] ' + m.name + ': skipped ' + skippedCount +
      ' oversized range(s), ' + skippedBytes + ' bytes (cap ' + cap +
      ', module size ' + m.size + ') - shared/unattributable memory');
  }

  return { regions: regions, skippedBytes: skippedBytes, skippedCount: skippedCount };
}

/**
 * Number of bytes a Frida hex pattern will match, so a chunked scan can overlap
 * consecutive windows by enough to catch a match that straddles the boundary.
 *
 * Frida patterns are space-separated bytes, where each byte is two hex nibbles
 * or a wildcard ('??' or '?'). A ':' introduces a mask suffix, which does not
 * change the match length. Returns 0 for anything unparseable, which callers
 * treat as "no overlap" — the pre-existing behaviour.
 *
 * @param {string} pattern - Frida hex pattern, e.g. "41 42 ?? 44"
 * @returns {number} match length in bytes
 */
function patternByteLength(pattern) {
  if (typeof pattern !== 'string') {
    return 0;
  }
  var body = pattern.split(':')[0];        // drop any mask suffix
  var tokens = body.trim().split(/\s+/);
  var count = 0;
  for (var i = 0; i < tokens.length; i++) {
    if (tokens[i].length > 0) {
      count++;
    }
  }
  return count;
}

/**
 * Targeted export presence check. Replaces full Module.enumerateExports() walks,
 * which on Android can SIGSEGV the target process when a module is APK-embedded
 * or giant and the linker leaves PROT_NONE gaps between PT_LOAD segments
 * (frida-gum PR #1094 / issue #1099). findExportByName performs a bounded
 * lookup, touching far less memory, and any per-module resolution fault is
 * contained by the try/catch instead of killing the process.
 *
 * @param {Module} m - Module instance (from Process.findModuleByName)
 * @param {string} symbolName - Export symbol to look up
 * @returns {boolean} true if the symbol is an export of the module
 */
function lookupExport(m, symbolName) {
  try {
    var p = m.findExportByName(symbolName);  // frida 17.x instance method, null on miss
    return p !== null && !p.isNull();
  } catch (e) {
    return false;  // resolution fault on a malformed module -> treat as "not present"
  }
}

/**
 * Scan a single (base, size) for one pattern, chunking ranges larger than
 * SCAN_CHUNK_SIZE so giant libraries are scanned bounded rather than in one
 * unbounded pass. Uses async Memory.scan; onError skips a faulting sub-range
 * but the overall Promise ALWAYS resolves (never rejects) so callers can await
 * without per-call try/catch.
 *
 * @param {NativePointer} base
 * @param {number|UInt64} size
 * @param {string} pattern - hex/Memory.scan match pattern
 * @param {Object} [opts]
 * @param {number} [opts.stopAfter=0] - resolve early once this many matches are
 *   collected (0 = unlimited). Mirrors the old "one match per range is enough".
 * @returns {Promise<Object[]>} resolves to [{address: NativePointer, size: Number}]
 */
function scanRange(base, size, pattern, opts) {
  opts = opts || {};
  var stopAfter = opts.stopAfter || 0;

  // Overlap consecutive windows by (match length - 1) bytes so a pattern lying
  // across a chunk boundary is still found. Without this, every 48 MB boundary
  // was a blind spot: the scan simply advanced by chunkSize and any match
  // spanning the seam was silently lost. Matches are deduped by address below,
  // so the re-scanned bytes cannot produce duplicates.
  var overlap = patternByteLength(pattern) - 1;
  if (overlap < 0) {
    overlap = 0;
  }
  // Guarantee forward progress even for an absurdly long pattern: half a window
  // of overlap still advances by half a window per iteration. Real patterns are
  // tens of bytes, so this never binds in practice.
  if (overlap > SCAN_CHUNK_SIZE / 2) {
    overlap = Math.floor(SCAN_CHUNK_SIZE / 2);
  }

  return new Promise(function (resolve) {
    var matches = [];
    var seen = {};
    var totalSize = (typeof size === 'number') ? size : size.toNumber();
    // Offset past which nothing has been scanned yet. Tracked as an absolute
    // offset rather than a "remaining" countdown: with overlapping windows a
    // countdown double-counts the overlap and leaves a spurious sliver window
    // at the end of every range.
    var scannedTo = 0;
    var settled = false;
    var truncated = false;

    var timer = setTimeout(function () {
      if (!settled) {
        // Do NOT hide this: resolving with partial matches used to look exactly
        // like "this module has no TLS library". Flag it so the caller can
        // report an incomplete scan instead of a negative result.
        truncated = true;
        settled = true;
        console.log('[tlslibhunter] scan of ' + base + ' (' + (totalSize - scannedTo) +
          ' of ' + totalSize + ' bytes still unscanned) hit the ' + SCAN_TIMEOUT_MS +
          ' ms safety net; results for this range are INCOMPLETE');
        settle();
      }
    }, SCAN_TIMEOUT_MS);

    // scanRange historically resolved to a plain array, and callers index it and
    // read .length. Keep that shape and carry the flag as a property so no
    // caller has to change to stay correct.
    function settle() {
      matches.truncated = truncated;
      resolve(matches);
    }

    function finish() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      settle();
    }

    function scanNextChunk() {
      if (settled) return;
      if (scannedTo >= totalSize) { finish(); return; }
      if (stopAfter > 0 && matches.length >= stopAfter) { finish(); return; }

      // Start each window (overlap) bytes before the end of the previous one, so
      // a match lying across the seam falls wholly inside this window.
      var chunkStart = scannedTo > 0 ? scannedTo - overlap : 0;
      if (chunkStart < 0) {
        chunkStart = 0;
      }
      var chunkSize = totalSize - chunkStart;
      if (chunkSize > SCAN_CHUNK_SIZE) {
        chunkSize = SCAN_CHUNK_SIZE;
      }
      var chunkBase = base.add(chunkStart);  // NativePointer arithmetic
      scannedTo = chunkStart + chunkSize;

      Memory.scan(chunkBase, chunkSize, pattern, {
        onMatch: function (address, matchSize) {
          // Dedupe: the overlap region is scanned twice by design.
          var key = address.toString();
          if (!seen[key]) {
            seen[key] = true;
            matches.push({ address: address, size: matchSize });
          }
          if (stopAfter > 0 && matches.length >= stopAfter) {
            return 'stop';  // cancel this chunk early
          }
        },
        onError: function (reason) {
          // Bad sub-range (PROT_NONE gap, race with unmap, SIGBUS-backed page):
          // skip it and continue with the next chunk via onComplete.
        },
        onComplete: function () {
          // onComplete fires after any onError(s); always advance.
          scanNextChunk();
        }
      });
    }

    scanNextChunk();
  });
}

/**
 * Convenience: resolve to true if the pattern occurs at least once in the range.
 *
 * A false result is ambiguous when the underlying scan was cut short by the
 * safety net, so callers that care can pass an accumulator and have
 * `.truncated` set — "not found" and "did not finish looking" must not be
 * reported as the same thing.
 *
 * @param {object} [acc] - optional accumulator; `acc.truncated` is OR-ed in
 * @returns {Promise<boolean>}
 */
function scanRangeHasMatch(base, size, pattern, acc) {
  return scanRange(base, size, pattern, { stopAfter: 1 }).then(function (m) {
    if (acc && m.truncated) {
      acc.truncated = true;
    }
    return m.length > 0;
  });
}

/**
 * First pair (l, r) with |l - r| <= maxDistance, or null.
 *
 * Replaces a `leftMatches x rightMatches` nested loop. That loop did break on
 * the first hit, so it was cheap when a pair existed — but the common case for a
 * non-matching module is that NO pair exists, and then it ran the full product
 * over two unbounded match lists. Sorting both sides and sweeping them together
 * makes the no-match case O(n log n) instead of O(n*m).
 *
 * It also fixes an overflow: the old code computed
 * `Math.abs(l.sub(r).toInt32())`, and toInt32() wraps once the two addresses are
 * more than 2 GB apart — which is routine on the dyld shared cache, where a
 * module's __TEXT and __DATA_CONST sit ~2 GB apart. A wrapped difference can
 * look arbitrarily small, so distant pairs could be reported as adjacent. Here
 * proximity is decided by pointer comparison first, so the subtraction only ever
 * runs on pairs already known to be within maxDistance.
 *
 * Works on anything exposing NativePointer's `compare`, `add` and
 * `sub().toInt32()`, so it is testable with plain stubs.
 *
 * @param {Array} leftAddrs
 * @param {Array} rightAddrs
 * @param {number} maxDistance
 * @returns {?{left: object, right: object, distance: number}}
 */
function findNearbyPair(leftAddrs, rightAddrs, maxDistance) {
  if (!leftAddrs || !rightAddrs || leftAddrs.length === 0 || rightAddrs.length === 0) {
    return null;
  }

  function byAddress(a, b) { return a.compare(b); }
  var left = leftAddrs.slice().sort(byAddress);
  var right = rightAddrs.slice().sort(byAddress);

  var i = 0, j = 0;
  while (i < left.length && j < right.length) {
    var l = left[i];
    var r = right[j];
    // Within maxDistance in either direction? Pure pointer compares, no
    // subtraction, so no 32-bit wraparound.
    var lNearR = l.add(maxDistance).compare(r) >= 0;
    var rNearL = r.add(maxDistance).compare(l) >= 0;
    if (lNearR && rNearL) {
      return { left: l, right: r, distance: Math.abs(l.sub(r).toInt32()) };
    }
    // Advance whichever side is behind; the other cannot get closer.
    if (l.compare(r) < 0) { i++; } else { j++; }
  }
  return null;
}

rpc.exports = {
  /**
   * Enumerate all loaded modules in the process.
   * Returns array of {name, path, base, size} objects.
   */
  enumerateModules: function() {
    var mods = Process.enumerateModules();
    var out = [];
    for (var i = 0; i < mods.length; i++) {
      var m = mods[i];
      out.push({
        name: m.name,
        path: m.path || "",
        base: m.base.toString(),
        size: m.size
      });
    }
    return out;
  },

  /**
   * Kernel-level scan: enumerate ALL readable ranges, then match them to
   * the target module's address space. This is the approach from scanner.js
   * which bypasses issues with standard module-range enumeration.
   *
   * @param {string} moduleName - Name of the module to scan
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scan
   * @returns {Object[]} Array of match objects with pattern, address, offset, protection, occurrences
   */
  scanModuleKernelLevel: async function(moduleName, hexPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    // Use Module.enumerateRanges instead of Process.enumerateRanges + manual
    // filtering. Frida's module-level API correctly handles dyld shared cache
    // modules where segments are non-contiguous in virtual memory. The oversized
    // shared-cache range it also reports is filtered out by moduleScanRegions.
    var moduleRanges = moduleScanRegions(m).regions;

    var found = [];
    for (var r = 0; r < moduleRanges.length; r++) {
      var range = moduleRanges[r];
      for (var p = 0; p < hexPatterns.length; p++) {
        var results = await scanRange(range.base, range.size, hexPatterns[p], { stopAfter: 1 });
        if (results.length > 0) {
          found.push({
            pattern: hexPatterns[p],
            address: results[0].address.toString(),
            offset: results[0].address.sub(m.base).toString(),
            protection: range.protection,
            occurrences: results.length
          });
          // One match per range is enough to identify the module
          break;
        }
      }
    }
    return found;
  },

  /**
   * Standard module scan (fallback / simpler approach).
   * Uses module base + size directly instead of kernel memory maps.
   */
  scanModuleForPatterns: async function(moduleName, patterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }
    var found = [];
    for (var i = 0; i < patterns.length; i++) {
      var pat = patterns[i];
      var res = await scanRange(m.base, m.size, pat);
      if (res.length > 0) {
        found.push({ pattern: pat, occurrences: res.length });
      }
    }
    return found;
  },

  /**
   * Check if specific export symbols exist in a module.
   * Used for library type identification.
   *
   * @param {string} moduleName - Module to check
   * @param {string[]} symbolNames - Export symbol names to look for
   * @returns {string[]} Array of found symbol names
   */
  checkExports: function(moduleName, symbolNames) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      return [];
    }
    // Targeted lookups instead of a full enumerateExports() walk (see lookupExport).
    var found = [];
    for (var j = 0; j < symbolNames.length; j++) {
      if (lookupExport(m, symbolNames[j])) {
        found.push(symbolNames[j]);
      }
    }
    return found;
  },

  /**
   * Batch check export symbols across multiple modules in a single RPC call.
   * Returns a map of module names to their found TLS export symbols.
   *
   * @param {string[]} moduleNames - Array of module names to check
   * @param {string[]} symbolNames - Export symbol names to look for
   * @returns {Object} Map of {moduleName: [foundSymbols]} (only modules with matches)
   */
  batchCheckExports: function(moduleNames, symbolNames) {
    var results = {};
    for (var i = 0; i < moduleNames.length; i++) {
      var modName = moduleNames[i];
      var m = Process.findModuleByName(modName);
      if (!m) continue;
      // Targeted per-symbol lookups instead of enumerateExports(): this is the
      // call that previously SIGSEGV'd the target on giant/APK-embedded libs.
      var found = [];
      for (var s = 0; s < symbolNames.length; s++) {
        if (lookupExport(m, symbolNames[s])) {
          found.push(symbolNames[s]);
        }
      }
      if (found.length > 0) {
        results[modName] = found;
      }
    }
    return results;
  },

  /**
   * Lightweight batch probe: scan multiple modules for TLS derivation labels.
   * Uses early-exit (stops after first match per module) for speed.
   * Intended as a fast pre-filter before expensive full scanning.
   *
   * @param {string[]} moduleNames - Array of module names to probe
   * @param {string[]} probePatterns - Small set of hex patterns (TLS derivation labels)
   * @returns {string[]} Array of module names that had at least one pattern match
   */
  batchProbeModules: async function(moduleNames, probePatterns) {
    var hits = [];
    for (var i = 0; i < moduleNames.length; i++) {
      var modName = moduleNames[i];
      var m = Process.findModuleByName(modName);
      if (!m) continue;
      var ranges = moduleScanRegions(m).regions;
      var found = false;
      for (var r = 0; r < ranges.length && !found; r++) {
        for (var p = 0; p < probePatterns.length && !found; p++) {
          if (await scanRangeHasMatch(ranges[r].base, ranges[r].size, probePatterns[p])) {
            found = true;
          }
        }
      }
      if (found) {
        hits.push(modName);
      }
    }
    return hits;
  },

  /**
   * Scan a module's memory for specific hex string patterns.
   * Used for TLS library fingerprinting — scans for identity/version strings
   * that survive in stripped binaries (.rodata section).
   *
   * @param {string} moduleName - Name of the module to scan
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scan
   * @returns {string[]} Array of hex patterns that were found (no address details)
   */
  scanForStrings: async function(moduleName, hexPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    // Keep r-- AND r-x ranges: fingerprint version strings live in .rodata (r--).
    var moduleRanges = moduleScanRegions(m).regions;

    var found = [];
    var foundSet = {};
    for (var r = 0; r < moduleRanges.length; r++) {
      var range = moduleRanges[r];
      for (var p = 0; p < hexPatterns.length; p++) {
        var pat = hexPatterns[p];
        if (foundSet[pat]) {
          continue;  // Already found this pattern
        }
        if (await scanRangeHasMatch(range.base, range.size, pat)) {
          found.push(pat);
          foundSet[pat] = true;
        }
      }
    }
    return found;
  },

  /**
   * Scan process-wide RWX memory regions (JIT buffers) for hex patterns.
   * Uses Process.enumerateRanges('rwx') to find regions that are readable,
   * writable, and executable simultaneously.
   *
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scan
   * @returns {Object[]} Array of match objects with pattern, address, size, protection, occurrences
   */
  scanModuleRWXRegions: async function(hexPatterns) {
    var ranges = Process.enumerateRanges('rwx');
    var found = [];
    var foundSet = {};
    for (var r = 0; r < ranges.length; r++) {
      var range = ranges[r];
      for (var p = 0; p < hexPatterns.length; p++) {
        var pat = hexPatterns[p];
        if (foundSet[pat]) {
          continue;  // Already found this pattern
        }
        var results = await scanRange(range.base, range.size, pat, { stopAfter: 1 });
        if (results.length > 0) {
          found.push({
            pattern: pat,
            address: results[0].address.toString(),
            size: range.size,
            protection: range.protection,
            occurrences: results.length
          });
          foundSet[pat] = true;
        }
      }
    }
    return found;
  },

  /**
   * Scan for split constant pairs within a module. Finds two hex patterns
   * that appear within a maximum byte distance of each other, indicating
   * a split constant or related data structure.
   *
   * @param {string} moduleName - Name of the module to scan
   * @param {Object[]} splitPairs - Array of {leftHex, rightHex, leftStr, rightStr}
   * @param {number} maxDistance - Max byte distance between the two halves (default 256)
   * @returns {Object[]} Array of proximity matches with leftStr, rightStr, addresses, distance
   */
  scanSplitConstants: async function(moduleName, splitPairs, maxDistance) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    if (typeof maxDistance === 'undefined' || maxDistance === null) {
      maxDistance = 256;
    }

    var moduleRanges = moduleScanRegions(m).regions;
    var found = [];

    for (var s = 0; s < splitPairs.length; s++) {
      var pair = splitPairs[s];
      var leftMatches = [];
      var rightMatches = [];

      for (var r = 0; r < moduleRanges.length; r++) {
        var range = moduleRanges[r];
        var leftResults = await scanRange(range.base, range.size, pair.leftHex);
        for (var li = 0; li < leftResults.length; li++) {
          leftMatches.push(leftResults[li].address);
        }
        var rightResults = await scanRange(range.base, range.size, pair.rightHex);
        for (var ri = 0; ri < rightResults.length; ri++) {
          rightMatches.push(rightResults[ri].address);
        }
      }

      var matched = false;
      for (var l = 0; l < leftMatches.length && !matched; l++) {
        for (var rr = 0; rr < rightMatches.length && !matched; rr++) {
          var dist = Math.abs(leftMatches[l].sub(rightMatches[rr]).toInt32());
          if (dist <= maxDistance) {
            found.push({
              leftStr: pair.leftStr,
              rightStr: pair.rightStr,
              leftAddress: leftMatches[l].toString(),
              rightAddress: rightMatches[rr].toString(),
              distance: dist
            });
            matched = true;
          }
        }
      }
    }
    return found;
  },

  /**
   * Scan a module for encoded string patterns (XOR-encoded, base64, etc.).
   * Returns matches with the offset relative to the module base address.
   *
   * @param {string} moduleName - Name of the module to scan
   * @param {Object[]} encodedPatterns - Array of {hexPattern, encodingType, detail}
   * @returns {Object[]} Array of match objects with hexPattern, encodingType, detail, address, offset
   */
  scanForEncodedStrings: async function(moduleName, encodedPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    var moduleRanges = moduleScanRegions(m).regions;
    var found = [];

    for (var p = 0; p < encodedPatterns.length; p++) {
      var ep = encodedPatterns[p];
      var patFound = false;
      for (var r = 0; r < moduleRanges.length && !patFound; r++) {
        var range = moduleRanges[r];
        var results = await scanRange(range.base, range.size, ep.hexPattern, { stopAfter: 1 });
        if (results.length > 0) {
          found.push({
            hexPattern: ep.hexPattern,
            encodingType: ep.encodingType,
            detail: ep.detail,
            address: results[0].address.toString(),
            offset: results[0].address.sub(m.base).toString()
          });
          patFound = true;
        }
      }
    }
    return found;
  },

  /**
   * Scan writable-but-not-executable memory regions (stack, heap, writable data)
   * for hex patterns. Uses Process.enumerateRanges('rw-') and skips regions
   * larger than 64 MB to avoid scanning the entire heap.
   *
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scan
   * @returns {Object[]} Array of match objects with pattern, address, size, protection, occurrences
   */
  scanStackMemory: async function(hexPatterns) {
    var ranges = Process.enumerateRanges('rw-');
    var found = [];
    var foundSet = {};
    for (var r = 0; r < ranges.length; r++) {
      var range = ranges[r];
      if (range.size > MAX_WRITABLE_RANGE) {
        continue;  // Skip huge writable regions (whole heap) rather than scan them
      }
      for (var p = 0; p < hexPatterns.length; p++) {
        var pat = hexPatterns[p];
        if (foundSet[pat]) {
          continue;  // Already found this pattern
        }
        var results = await scanRange(range.base, range.size, pat, { stopAfter: 1 });
        if (results.length > 0) {
          found.push({
            pattern: pat,
            address: results[0].address.toString(),
            size: range.size,
            protection: range.protection,
            occurrences: results.length
          });
          foundSet[pat] = true;
        }
      }
    }
    return found;
  },

  /**
   * Combined single-pass scan: reads each memory range once and runs all
   * pattern categories against it. Replaces multiple separate RPC calls
   * (scanModuleKernelLevel + scanForStrings + scanSplitConstants + scanForEncodedStrings)
   * with a single call to eliminate redundant memory reads and RPC round-trips.
   *
   * @param {string} moduleName
   * @param {Object} opts - Scan options:
   *   opts.tlsPatterns     {string[]}  - hex patterns for TLS indicator scan
   *   opts.fpPatterns      {string[]}  - hex patterns for fingerprint strings
   *   opts.splitPairs      {Object[]}  - [{leftHex, rightHex, leftStr, rightStr}, ...]
   *   opts.encodedPatterns {Object[]}  - [{hexPattern, encodingType, detail}, ...]
   *   opts.maxSplitDistance {number}   - max byte distance for split constant proximity (default 256)
   *   opts.earlyExitThreshold {number} - stop TLS pattern scan after this many hits (default 0 = no limit)
   * @returns {Object} Combined results:
   *   {tlsMatches, fpMatches, splitMatches, encodedMatches}
   */
  scanModuleCombined: async function(moduleName, opts) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    // Keep r-- AND r-x ranges; giant libs are bounded via chunking in scanRange.
    // moduleScanRegions drops the shared dyld-cache range that Apple platforms
    // report for every image — see its docstring for the measured cost.
    var scanRegions = moduleScanRegions(m);
    var moduleRanges = scanRegions.regions;
    // Accumulates whether ANY range scan below was cut short by the safety net,
    // so an incomplete scan is never reported as a clean "nothing found".
    var scanAcc = { truncated: false };

    var maxSplitDistance = (typeof opts.maxSplitDistance !== 'undefined' && opts.maxSplitDistance !== null)
      ? opts.maxSplitDistance : 256;
    var earlyExitThreshold = (typeof opts.earlyExitThreshold !== 'undefined' && opts.earlyExitThreshold !== null)
      ? opts.earlyExitThreshold : 0;
    var fpEarlyExitThreshold = (typeof opts.fpEarlyExitThreshold !== 'undefined' && opts.fpEarlyExitThreshold !== null)
      ? opts.fpEarlyExitThreshold : 0;

    var tlsMatches = [];
    var fpMatches = [];
    var splitMatches = [];
    var encodedMatches = [];

    var tlsFoundSet = {};
    var fpFoundSet = {};
    var encodedFoundSet = {};

    // Per-pair address collectors for split constants
    var splitAddresses = [];
    if (opts.splitPairs && opts.splitPairs.length) {
      for (var s = 0; s < opts.splitPairs.length; s++) {
        splitAddresses.push({ leftMatches: [], rightMatches: [] });
      }
    }

    // Single loop over all readable ranges
    for (var r = 0; r < moduleRanges.length; r++) {
      var range = moduleRanges[r];

      // --- TLS patterns ---
      if (opts.tlsPatterns && opts.tlsPatterns.length) {
        var tlsDone = (earlyExitThreshold > 0 && tlsMatches.length >= earlyExitThreshold);
        if (!tlsDone) {
          for (var t = 0; t < opts.tlsPatterns.length; t++) {
            var tlsPat = opts.tlsPatterns[t];
            if (tlsFoundSet[tlsPat]) {
              continue;
            }
            var tlsResults = await scanRange(range.base, range.size, tlsPat, { stopAfter: 1 });
            if (tlsResults.truncated) { scanAcc.truncated = true; }
            if (tlsResults.length > 0) {
              tlsMatches.push({
                pattern: tlsPat,
                address: tlsResults[0].address.toString(),
                offset: tlsResults[0].address.sub(m.base).toString(),
                protection: range.protection,
                occurrences: tlsResults.length
              });
              tlsFoundSet[tlsPat] = true;
              if (earlyExitThreshold > 0 && tlsMatches.length >= earlyExitThreshold) {
                break;
              }
            }
          }
        }
      }

      // --- Fingerprint patterns ---
      if (opts.fpPatterns && opts.fpPatterns.length) {
        var fpDone = (fpEarlyExitThreshold > 0 && fpMatches.length >= fpEarlyExitThreshold);
        if (!fpDone) {
          for (var f = 0; f < opts.fpPatterns.length; f++) {
            var fpPat = opts.fpPatterns[f];
            if (fpFoundSet[fpPat]) {
              continue;
            }
            if (await scanRangeHasMatch(range.base, range.size, fpPat, scanAcc)) {
              fpMatches.push(fpPat);
              fpFoundSet[fpPat] = true;
              if (fpEarlyExitThreshold > 0 && fpMatches.length >= fpEarlyExitThreshold) {
                break;
              }
            }
          }
        }
      }

      // --- Encoded patterns ---
      if (opts.encodedPatterns && opts.encodedPatterns.length) {
        for (var e = 0; e < opts.encodedPatterns.length; e++) {
          var ep = opts.encodedPatterns[e];
          if (encodedFoundSet[ep.hexPattern]) {
            continue;
          }
          var encResults = await scanRange(range.base, range.size, ep.hexPattern, { stopAfter: 1 });
          if (encResults.length > 0) {
            encodedMatches.push({
              hexPattern: ep.hexPattern,
              encodingType: ep.encodingType,
              detail: ep.detail,
              address: encResults[0].address.toString(),
              offset: encResults[0].address.sub(m.base).toString()
            });
            encodedFoundSet[ep.hexPattern] = true;
          }
        }
      }

      // --- Split constants (collect addresses) ---
      if (opts.splitPairs && opts.splitPairs.length) {
        for (var sp = 0; sp < opts.splitPairs.length; sp++) {
          var pair = opts.splitPairs[sp];
          // Bounded: these two scans have no stopAfter by nature (we need the
          // addresses, not just existence), so cap how many we retain. An
          // unbounded collection over a large range could balloon into a huge
          // array before the proximity check ever ran.
          var leftResults = await scanRange(range.base, range.size, pair.leftHex,
            { stopAfter: MAX_SPLIT_MATCHES });
          if (leftResults.truncated) { scanAcc.truncated = true; }
          for (var li = 0; li < leftResults.length; li++) {
            splitAddresses[sp].leftMatches.push(leftResults[li].address);
          }
          var rightResults = await scanRange(range.base, range.size, pair.rightHex,
            { stopAfter: MAX_SPLIT_MATCHES });
          if (rightResults.truncated) { scanAcc.truncated = true; }
          for (var ri = 0; ri < rightResults.length; ri++) {
            splitAddresses[sp].rightMatches.push(rightResults[ri].address);
          }
          if (leftResults.length >= MAX_SPLIT_MATCHES || rightResults.length >= MAX_SPLIT_MATCHES) {
            console.log('[tlslibhunter] ' + moduleName + ': split-constant matches for "' +
              pair.leftStr + '"/"' + pair.rightStr + '" hit the ' + MAX_SPLIT_MATCHES +
              ' cap in one range; proximity results may be incomplete');
          }
        }
      }
    }

    // --- Split constant proximity checks ---
    if (opts.splitPairs && opts.splitPairs.length) {
      for (var sc = 0; sc < opts.splitPairs.length; sc++) {
        var sPair = opts.splitPairs[sc];
        var nearby = findNearbyPair(
          splitAddresses[sc].leftMatches,
          splitAddresses[sc].rightMatches,
          maxSplitDistance
        );
        if (nearby) {
          splitMatches.push({
            leftStr: sPair.leftStr,
            rightStr: sPair.rightStr,
            leftAddress: nearby.left.toString(),
            rightAddress: nearby.right.toString(),
            distance: nearby.distance
          });
        }
      }
    }

    return {
      tlsMatches: tlsMatches,
      fpMatches: fpMatches,
      splitMatches: splitMatches,
      encodedMatches: encodedMatches,
      // Reported so the host can distinguish "no TLS library here" from "the
      // scan did not finish", and can say how much memory was deliberately
      // left out. Both used to be invisible.
      truncated: scanAcc.truncated,
      skippedBytes: scanRegions.skippedBytes,
      scannedBytes: moduleRanges.reduce(function (a, r) { return a + r.size; }, 0)
    };
  },

  /**
   * Batch combined scan: scan multiple modules in a single RPC call.
   * Eliminates per-module RPC overhead and benefits from page cache sharing
   * (on macOS, many system libraries share dyld shared cache pages).
   *
   * Shared options (fpPatterns, splitPairs, encodedPatterns) are passed once
   * via sharedOpts to avoid duplicating them in every module config.
   *
   * @param {Object[]} moduleConfigs - Array of {name, opts} where opts contains per-module fields only
   * @param {Object} sharedOpts - Shared scan options applied to all modules (fpPatterns, splitPairs, etc.)
   * @returns {Object} Map of {moduleName: {tlsMatches, fpMatches, splitMatches, encodedMatches}}
   */
  batchScanModulesCombined: async function(moduleConfigs, sharedOpts) {
    var results = {};
    if (!sharedOpts) sharedOpts = {};
    for (var i = 0; i < moduleConfigs.length; i++) {
      var config = moduleConfigs[i];
      var moduleName = config.name;
      // Merge shared opts with per-module opts (per-module takes precedence)
      var mergedOpts = {};
      var k;
      for (k in sharedOpts) { mergedOpts[k] = sharedOpts[k]; }
      if (config.opts) {
        for (k in config.opts) { mergedOpts[k] = config.opts[k]; }
      }
      try {
        // scanModuleCombined is async now; await its Promise to keep the result shape.
        results[moduleName] = await rpc.exports.scanModuleCombined(moduleName, mergedOpts);
      } catch (e) {
        results[moduleName] = { tlsMatches: [], fpMatches: [], splitMatches: [], encodedMatches: [] };
      }
    }
    return results;
  }
};
