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

    var allRanges = Process.enumerateRanges('r');
    var moduleEnd = m.base.add(m.size);

    // Filter ranges that belong to this module's address space
    var moduleRanges = allRanges.filter(function(range) {
      return (range.base.compare(m.base) >= 0) &&
             (range.base.compare(moduleEnd) < 0);
    });

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

    var allRanges = Process.enumerateRanges('r');
    var moduleEnd = m.base.add(m.size);

    // Filter ranges that belong to this module's address space
    var moduleRanges = allRanges.filter(function(range) {
      return (range.base.compare(m.base) >= 0) &&
             (range.base.compare(moduleEnd) < 0);
    });

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
  }
};
