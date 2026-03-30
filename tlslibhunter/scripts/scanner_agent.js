'use strict';

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
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scanSync
   * @returns {Object[]} Array of match objects with pattern, address, offset, protection, occurrences
   */
  scanModuleKernelLevel: function(moduleName, hexPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    // Use Module.enumerateRanges instead of Process.enumerateRanges + manual
    // filtering. Frida's module-level API correctly handles dyld shared cache
    // modules where segments are non-contiguous in virtual memory.
    var moduleRanges = m.enumerateRanges('r');

    var found = [];
    for (var r = 0; r < moduleRanges.length; r++) {
      var range = moduleRanges[r];
      for (var p = 0; p < hexPatterns.length; p++) {
        try {
          var results = Memory.scanSync(range.base, range.size, hexPatterns[p]);
          if (results && results.length > 0) {
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
        } catch (e) {
          // Ignore read errors for individual ranges
        }
      }
    }
    return found;
  },

  /**
   * Standard module scan (fallback / simpler approach).
   * Uses module base + size directly instead of kernel memory maps.
   */
  scanModuleForPatterns: function(moduleName, patterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }
    var found = [];
    for (var i = 0; i < patterns.length; i++) {
      var pat = patterns[i];
      try {
        var res = Memory.scanSync(m.base, m.size, pat);
        if (res && res.length > 0) {
          found.push({ pattern: pat, occurrences: res.length });
        }
      } catch (e) {
        // skip pattern or region read errors
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
    var found = [];
    var exports = m.enumerateExports();
    var exportSet = {};
    for (var i = 0; i < exports.length; i++) {
      exportSet[exports[i].name] = true;
    }
    for (var j = 0; j < symbolNames.length; j++) {
      if (exportSet[symbolNames[j]]) {
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
    var symbolSet = {};
    for (var j = 0; j < symbolNames.length; j++) {
      symbolSet[symbolNames[j]] = true;
    }
    var results = {};
    for (var i = 0; i < moduleNames.length; i++) {
      var modName = moduleNames[i];
      var m = Process.findModuleByName(modName);
      if (!m) continue;
      var exports = m.enumerateExports();
      var found = [];
      for (var e = 0; e < exports.length; e++) {
        if (symbolSet[exports[e].name]) {
          found.push(exports[e].name);
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
  batchProbeModules: function(moduleNames, probePatterns) {
    var hits = [];
    for (var i = 0; i < moduleNames.length; i++) {
      var modName = moduleNames[i];
      var m = Process.findModuleByName(modName);
      if (!m) continue;
      var ranges = m.enumerateRanges('r');
      var found = false;
      for (var r = 0; r < ranges.length && !found; r++) {
        for (var p = 0; p < probePatterns.length && !found; p++) {
          try {
            var results = Memory.scanSync(ranges[r].base, ranges[r].size, probePatterns[p]);
            if (results && results.length > 0) {
              found = true;
            }
          } catch (e) {
            // Ignore read errors
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
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scanSync
   * @returns {string[]} Array of hex patterns that were found (no address details)
   */
  scanForStrings: function(moduleName, hexPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    var moduleRanges = m.enumerateRanges('r');

    var found = [];
    var foundSet = {};
    for (var r = 0; r < moduleRanges.length; r++) {
      var range = moduleRanges[r];
      for (var p = 0; p < hexPatterns.length; p++) {
        var pat = hexPatterns[p];
        if (foundSet[pat]) {
          continue;  // Already found this pattern
        }
        try {
          var results = Memory.scanSync(range.base, range.size, pat);
          if (results && results.length > 0) {
            found.push(pat);
            foundSet[pat] = true;
          }
        } catch (e) {
          // Ignore read errors for individual ranges
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
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scanSync
   * @returns {Object[]} Array of match objects with pattern, address, size, protection, occurrences
   */
  scanModuleRWXRegions: function(hexPatterns) {
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
        try {
          var results = Memory.scanSync(range.base, range.size, pat);
          if (results && results.length > 0) {
            found.push({
              pattern: pat,
              address: results[0].address.toString(),
              size: range.size,
              protection: range.protection,
              occurrences: results.length
            });
            foundSet[pat] = true;
          }
        } catch (e) {
          // Ignore read errors for individual ranges
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
  scanSplitConstants: function(moduleName, splitPairs, maxDistance) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    if (typeof maxDistance === 'undefined' || maxDistance === null) {
      maxDistance = 256;
    }

    var moduleRanges = m.enumerateRanges('r');
    var found = [];

    for (var s = 0; s < splitPairs.length; s++) {
      var pair = splitPairs[s];
      var leftMatches = [];
      var rightMatches = [];

      for (var r = 0; r < moduleRanges.length; r++) {
        var range = moduleRanges[r];
        try {
          var leftResults = Memory.scanSync(range.base, range.size, pair.leftHex);
          for (var li = 0; li < leftResults.length; li++) {
            leftMatches.push(leftResults[li].address);
          }
        } catch (e) {
          // Ignore read errors for individual ranges
        }
        try {
          var rightResults = Memory.scanSync(range.base, range.size, pair.rightHex);
          for (var ri = 0; ri < rightResults.length; ri++) {
            rightMatches.push(rightResults[ri].address);
          }
        } catch (e) {
          // Ignore read errors for individual ranges
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
  scanForEncodedStrings: function(moduleName, encodedPatterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    var moduleRanges = m.enumerateRanges('r');
    var found = [];

    for (var p = 0; p < encodedPatterns.length; p++) {
      var ep = encodedPatterns[p];
      var patFound = false;
      for (var r = 0; r < moduleRanges.length && !patFound; r++) {
        var range = moduleRanges[r];
        try {
          var results = Memory.scanSync(range.base, range.size, ep.hexPattern);
          if (results && results.length > 0) {
            found.push({
              hexPattern: ep.hexPattern,
              encodingType: ep.encodingType,
              detail: ep.detail,
              address: results[0].address.toString(),
              offset: results[0].address.sub(m.base).toString()
            });
            patFound = true;
          }
        } catch (e) {
          // Ignore read errors for individual ranges
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
   * @param {string[]} hexPatterns - Array of hex pattern strings for Memory.scanSync
   * @returns {Object[]} Array of match objects with pattern, address, size, protection, occurrences
   */
  scanStackMemory: function(hexPatterns) {
    var MAX_RANGE_SIZE = 64 * 1024 * 1024; // 64 MB
    var ranges = Process.enumerateRanges('rw-');
    var found = [];
    var foundSet = {};
    for (var r = 0; r < ranges.length; r++) {
      var range = ranges[r];
      if (range.size > MAX_RANGE_SIZE) {
        continue;
      }
      for (var p = 0; p < hexPatterns.length; p++) {
        var pat = hexPatterns[p];
        if (foundSet[pat]) {
          continue;  // Already found this pattern
        }
        try {
          var results = Memory.scanSync(range.base, range.size, pat);
          if (results && results.length > 0) {
            found.push({
              pattern: pat,
              address: results[0].address.toString(),
              size: range.size,
              protection: range.protection,
              occurrences: results.length
            });
            foundSet[pat] = true;
          }
        } catch (e) {
          // Ignore read errors for individual ranges
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
  scanModuleCombined: function(moduleName, opts) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }

    var moduleRanges = m.enumerateRanges('r');

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
            try {
              var tlsResults = Memory.scanSync(range.base, range.size, tlsPat);
              if (tlsResults && tlsResults.length > 0) {
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
            } catch (e) {
              // Ignore read errors for individual ranges
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
            try {
              var fpResults = Memory.scanSync(range.base, range.size, fpPat);
              if (fpResults && fpResults.length > 0) {
                fpMatches.push(fpPat);
                fpFoundSet[fpPat] = true;
                if (fpEarlyExitThreshold > 0 && fpMatches.length >= fpEarlyExitThreshold) {
                  break;
                }
              }
            } catch (e) {
              // Ignore read errors for individual ranges
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
          try {
            var encResults = Memory.scanSync(range.base, range.size, ep.hexPattern);
            if (encResults && encResults.length > 0) {
              encodedMatches.push({
                hexPattern: ep.hexPattern,
                encodingType: ep.encodingType,
                detail: ep.detail,
                address: encResults[0].address.toString(),
                offset: encResults[0].address.sub(m.base).toString()
              });
              encodedFoundSet[ep.hexPattern] = true;
            }
          } catch (e2) {
            // Ignore read errors for individual ranges
          }
        }
      }

      // --- Split constants (collect addresses) ---
      if (opts.splitPairs && opts.splitPairs.length) {
        for (var sp = 0; sp < opts.splitPairs.length; sp++) {
          var pair = opts.splitPairs[sp];
          try {
            var leftResults = Memory.scanSync(range.base, range.size, pair.leftHex);
            for (var li = 0; li < leftResults.length; li++) {
              splitAddresses[sp].leftMatches.push(leftResults[li].address);
            }
          } catch (e3) {
            // Ignore read errors for individual ranges
          }
          try {
            var rightResults = Memory.scanSync(range.base, range.size, pair.rightHex);
            for (var ri = 0; ri < rightResults.length; ri++) {
              splitAddresses[sp].rightMatches.push(rightResults[ri].address);
            }
          } catch (e4) {
            // Ignore read errors for individual ranges
          }
        }
      }
    }

    // --- Split constant proximity checks ---
    if (opts.splitPairs && opts.splitPairs.length) {
      for (var sc = 0; sc < opts.splitPairs.length; sc++) {
        var sPair = opts.splitPairs[sc];
        var sLeft = splitAddresses[sc].leftMatches;
        var sRight = splitAddresses[sc].rightMatches;
        if (sLeft.length === 0 || sRight.length === 0) {
          continue;
        }
        var matched = false;
        for (var l = 0; l < sLeft.length && !matched; l++) {
          for (var rr = 0; rr < sRight.length && !matched; rr++) {
            var dist = Math.abs(sLeft[l].sub(sRight[rr]).toInt32());
            if (dist <= maxSplitDistance) {
              splitMatches.push({
                leftStr: sPair.leftStr,
                rightStr: sPair.rightStr,
                leftAddress: sLeft[l].toString(),
                rightAddress: sRight[rr].toString(),
                distance: dist
              });
              matched = true;
            }
          }
        }
      }
    }

    return {
      tlsMatches: tlsMatches,
      fpMatches: fpMatches,
      splitMatches: splitMatches,
      encodedMatches: encodedMatches
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
  batchScanModulesCombined: function(moduleConfigs, sharedOpts) {
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
        results[moduleName] = rpc.exports.scanModuleCombined(moduleName, mergedOpts);
      } catch (e) {
        results[moduleName] = { tlsMatches: [], fpMatches: [], splitMatches: [], encodedMatches: [] };
      }
    }
    return results;
  }
};
