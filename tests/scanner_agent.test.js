// Unit tests for the pure helpers in tlslibhunter/scripts/scanner_agent.js.
//
// Run with:  node --test tests/
//
// The agent is a Frida script, not a Node module: it has no exports and its top
// level touches rpc/Process/Memory. Rather than duplicate the helpers here (a
// copy would drift from the shipped code and test nothing), we evaluate the REAL
// source in a vm sandbox with those globals stubbed, then reach in and exercise
// the functions directly. A syntax error or a newly-referenced global therefore
// fails these tests too.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const AGENT_PATH = path.join(__dirname, '..', 'tlslibhunter', 'scripts', 'scanner_agent.js');

// --- A NativePointer stand-in -------------------------------------------------
// Only the operations the helpers actually use: add, sub().toInt32(), compare,
// toString. Backed by BigInt so 64-bit addresses and >2 GB deltas behave like
// the real thing (which is the whole point of one of the tests below).
function ptr(value) {
  const v = BigInt(value);
  return {
    _v: v,
    add(n) { return ptr(v + BigInt(n)); },
    sub(other) {
      const d = v - (typeof other === 'object' ? other._v : BigInt(other));
      return {
        // Mirror NativePointer.toInt32()'s 32-bit truncation, including wrap.
        toInt32() { return Number(BigInt.asIntN(32, d)); },
        toNumber() { return Number(d); },
      };
    },
    compare(other) {
      const o = typeof other === 'object' ? other._v : BigInt(other);
      return v < o ? -1 : (v > o ? 1 : 0);
    },
    toString() { return '0x' + v.toString(16); },
  };
}

// --- Sandbox ------------------------------------------------------------------
function loadAgent(overrides = {}) {
  const source = fs.readFileSync(AGENT_PATH, 'utf8');
  const logs = [];
  const sandbox = {
    rpc: {},
    console: { log: (...a) => logs.push(a.join(' ')), warn: () => {}, error: () => {} },
    setTimeout,
    clearTimeout,
    Process: { findModuleByName: () => null, enumerateRanges: () => [] },
    Memory: { scan: () => {}, scanSync: () => [] },
    Module: {},
    ptr,
    ...overrides,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: AGENT_PATH });
  return { sandbox, logs };
}

// =============================================================================
test('the agent source evaluates and defines its helpers', () => {
  const { sandbox } = loadAgent();
  for (const fn of ['moduleScanRegions', 'patternByteLength', 'findNearbyPair', 'scanRange']) {
    assert.equal(typeof sandbox[fn], 'function', `${fn} should be defined`);
  }
  // rpc.exports must still be populated — the sandbox proves the top level ran.
  assert.equal(typeof sandbox.rpc.exports.scanModuleCombined, 'function');
});

// =============================================================================
// patternByteLength — feeds the chunk overlap, so an error here silently
// reintroduces boundary misses.
// =============================================================================
test('patternByteLength counts pattern bytes', () => {
  const { sandbox } = loadAgent();
  const len = sandbox.patternByteLength;

  assert.equal(len('41'), 1);
  assert.equal(len('41 42 43'), 3);
  assert.equal(len('41 42 ?? 44'), 4, 'wildcards are still one byte wide');
  assert.equal(len('?? ??'), 2);
  // A mask suffix does not change how many bytes are matched.
  assert.equal(len('41 42 43 : ff ff ff'.replace(/ : /, ':')), 3);
  // Tolerant of sloppy spacing, since patterns are built by string joins.
  assert.equal(len('  41   42  '), 2);
  // Unparseable input must degrade to 0 (== no overlap == old behaviour),
  // never to NaN, which would poison the cursor arithmetic in scanRange.
  assert.equal(len(undefined), 0);
  assert.equal(len(null), 0);
  assert.equal(len(42), 0);
});

// =============================================================================
// moduleScanRegions — the fix itself.
// =============================================================================
function fakeModule({ name = 'libtest.dylib', size, ranges }) {
  return { name, size, base: ptr(0x1000), enumerateRanges: () => ranges };
}

test('moduleScanRegions drops the oversized shared range and keeps the rest', () => {
  const { sandbox, logs } = loadAgent();
  // Numbers taken from the real macOS measurement: a 851.6 KB module whose
  // enumerateRanges('r') also reports the 587.3 MB shared dyld-cache region.
  const m = fakeModule({
    name: 'libboringssl.dylib',
    size: 872032,
    ranges: [
      { base: ptr(0x18e561000), size: 872032 },   // __TEXT
      { base: ptr(0x1edef8030), size: 45875 },    // data
      { base: ptr(0x1f61f0f70), size: 21402 },    // data
      { base: ptr(0x206aa4000), size: 615874560 }, // the shared region
    ],
  });

  const out = sandbox.moduleScanRegions(m);

  assert.equal(out.regions.length, 3, 'only the shared region is dropped');
  assert.equal(out.skippedCount, 1);
  assert.equal(out.skippedBytes, 615874560);
  const scanned = out.regions.reduce((a, r) => a + r.size, 0);
  assert.equal(scanned, 872032 + 45875 + 21402);
  // Never silent.
  assert.match(logs.join('\n'), /skipped 1 oversized range/);
  assert.match(logs.join('\n'), /libboringssl\.dylib/);
});

test('moduleScanRegions keeps every range of a module with no oversized range', () => {
  const { sandbox, logs } = loadAgent();
  const m = fakeModule({
    size: 4096,
    ranges: [{ base: ptr(0x1000), size: 4096 }, { base: ptr(0x9000), size: 128 }],
  });
  const out = sandbox.moduleScanRegions(m);
  assert.equal(out.regions.length, 2);
  assert.equal(out.skippedCount, 0);
  assert.equal(out.skippedBytes, 0);
  assert.equal(logs.length, 0, 'nothing to report, so nothing logged');
});

test('the cap floor protects a tiny module: 6 KB module keeps its 40 MB range', () => {
  // The regression this floor prevents: with a pure `4 * m.size` cap, a 6.1 KB
  // module (libcoretls_cfhelpers.dylib is real) would have a cap of ~24 KB and
  // would discard perfectly legitimate data mappings. m.size is only the primary
  // mapping, so it cannot be used as a tight bound on its own.
  const { sandbox } = loadAgent();
  const m = fakeModule({
    size: 6256,
    ranges: [
      { base: ptr(0x1000), size: 6256 },
      { base: ptr(0x40000), size: 40 * 1024 * 1024 },
    ],
  });
  const out = sandbox.moduleScanRegions(m);
  assert.equal(out.regions.length, 2, '40 MB is under the 64 MB floor, so it is kept');
  assert.equal(out.skippedCount, 0);
});

test('a genuinely huge module keeps its own huge range (cap scales with size)', () => {
  // A 200 MB packed Android .so must not have its payload filtered out: the cap
  // is 4x the module size once that exceeds the floor.
  const { sandbox } = loadAgent();
  const big = 200 * 1024 * 1024;
  const m = fakeModule({
    name: 'libmonochrome.so',
    size: big,
    ranges: [{ base: ptr(0x1000), size: big }, { base: ptr(0x40000000), size: 615874560 }],
  });
  const out = sandbox.moduleScanRegions(m);
  assert.equal(out.regions.length, 2,
    '587 MB is under 4x200 MB, so a big module still gets scanned fully');
  assert.equal(out.skippedCount, 0);
});

// =============================================================================
// scanRange — chunk-boundary overlap and truncation flag.
// =============================================================================
// Records every window Memory.scan is asked for, so we can assert on coverage
// rather than on matches.
function recordingMemory(windows, matchAt = null) {
  return {
    scan(base, size, pattern, callbacks) {
      windows.push({ start: BigInt(base._v), size });
      if (matchAt !== null) {
        const start = BigInt(base._v);
        const end = start + BigInt(size);
        if (BigInt(matchAt) >= start && BigInt(matchAt) < end) {
          callbacks.onMatch(ptr(matchAt), 4);
        }
      }
      callbacks.onComplete();
    },
  };
}

test('consecutive scan windows overlap by (pattern length - 1)', async () => {
  const windows = [];
  const { sandbox } = loadAgent({ Memory: recordingMemory(windows) });
  const CHUNK = 48 * 1024 * 1024;

  // Two chunks' worth, with an 8-byte pattern => 7 bytes of overlap.
  await sandbox.scanRange(ptr(0x100000000), CHUNK + 1000,
    '41 42 43 44 45 46 47 48', {});

  assert.equal(windows.length, 2, 'size spans two windows');
  const firstEnd = windows[0].start + BigInt(windows[0].size);
  const secondStart = windows[1].start;
  assert.equal(firstEnd - secondStart, 7n,
    'second window must start 7 bytes before the first one ended');
});

test('a match straddling a chunk boundary is found (the regression)', async () => {
  const CHUNK = 48 * 1024 * 1024;
  const base = 0x100000000;
  // Place a 4-byte match so it starts 2 bytes before the first chunk ends.
  const straddle = base + CHUNK - 2;

  // Pre-fix behaviour, reproduced: advance by exactly chunkSize, no overlap.
  // The first window ends at the boundary and the second starts on it, so a
  // match beginning 2 bytes earlier is reported by neither.
  const noOverlapWindows = [];
  const covered = (windows, addr) => windows.some(
    (w) => BigInt(addr) >= w.start && BigInt(addr) < w.start + BigInt(w.size));
  noOverlapWindows.push({ start: BigInt(base), size: CHUNK });
  noOverlapWindows.push({ start: BigInt(base + CHUNK), size: 1000 });
  assert.equal(covered(noOverlapWindows, straddle), true,
    'the START is inside chunk 1 ...');
  // ... but the match needs 4 bytes and only 2 are inside chunk 1, which is why
  // Memory.scan cannot report it. That is the bug; the overlap is the fix.

  const windows = [];
  const { sandbox } = loadAgent({ Memory: recordingMemory(windows, straddle) });
  const matches = await sandbox.scanRange(ptr(base), CHUNK + 1000, '41 42 43 44', {});

  assert.equal(matches.length, 1, 'the straddling match is found exactly once');
  assert.equal(matches[0].address.toString(), ptr(straddle).toString());
  // And the second window genuinely starts before the boundary.
  assert.ok(windows[1].start < BigInt(base + CHUNK),
    'window 2 must begin before the chunk-1 boundary');
});

test('overlap does not double-report a match found in both windows', async () => {
  const CHUNK = 48 * 1024 * 1024;
  const base = 0x100000000;
  // Sits inside the overlap region, so both windows see it.
  const inOverlap = base + CHUNK - 3;
  const windows = [];
  const { sandbox } = loadAgent({ Memory: recordingMemory(windows, inOverlap) });

  const matches = await sandbox.scanRange(ptr(base), CHUNK + 1000, '41 42 43 44', {});

  assert.equal(matches.length, 1, 'deduped by address');
});

test('scanRange reports truncated=false on a clean completion', async () => {
  const { sandbox } = loadAgent({ Memory: recordingMemory([]) });
  const matches = await sandbox.scanRange(ptr(0x1000), 4096, '41 42', {});
  assert.equal(matches.truncated, false);
});

test('a pattern longer than the chunk still terminates', async () => {
  // Guard against the cursor stalling: if overlap >= chunkSize the advance would
  // be <= 0 and the scan would loop forever.
  const windows = [];
  const { sandbox } = loadAgent({
    Memory: recordingMemory(windows),
    // Shrink nothing; instead use a pattern with more bytes than the range.
  });
  const pattern = new Array(64).fill('41').join(' ');  // 64 bytes
  const matches = await sandbox.scanRange(ptr(0x1000), 16, pattern, {});
  assert.ok(Array.isArray(matches));
  assert.ok(windows.length >= 1 && windows.length < 10, 'must not spin');
});

// =============================================================================
// findNearbyPair — replaces the quadratic loop, and fixes an overflow.
// =============================================================================
test('findNearbyPair finds a pair within maxDistance', () => {
  const { sandbox } = loadAgent();
  const hit = sandbox.findNearbyPair(
    [ptr(0x1000), ptr(0x5000)], [ptr(0x1010)], 256);
  assert.ok(hit);
  assert.equal(hit.distance, 16);
  assert.equal(hit.left.toString(), '0x1000');
  assert.equal(hit.right.toString(), '0x1010');
});

test('findNearbyPair returns null when every pair is too far apart', () => {
  const { sandbox } = loadAgent();
  assert.equal(
    sandbox.findNearbyPair([ptr(0x1000)], [ptr(0x9000)], 256), null);
});

test('findNearbyPair handles empty and missing inputs', () => {
  const { sandbox } = loadAgent();
  assert.equal(sandbox.findNearbyPair([], [ptr(1)], 10), null);
  assert.equal(sandbox.findNearbyPair([ptr(1)], [], 10), null);
  assert.equal(sandbox.findNearbyPair(null, null, 10), null);
});

test('findNearbyPair does NOT report a >2GB gap as adjacent (overflow fix)', () => {
  // The bug being pinned: the old code computed
  // Math.abs(left.sub(right).toInt32()), and toInt32() truncates to 32 bits. Two
  // addresses 0x100000000 apart differ by exactly 2^32, which truncates to 0 —
  // so the furthest-apart pair imaginable looked like distance 0. On the dyld
  // shared cache a module's __TEXT and __DATA_CONST really are ~2 GB apart, so
  // this was reachable, not theoretical.
  const { sandbox } = loadAgent();
  const left = ptr(0x100000000);
  const right = ptr(0x200000000);

  // Demonstrate the truncation is real with our pointer stub.
  assert.equal(left.sub(right).toInt32(), 0,
    'stub reproduces NativePointer.toInt32() wraparound');

  // The helper must still say "not nearby".
  assert.equal(sandbox.findNearbyPair([left], [right], 256), null);
});

test('findNearbyPair is order-independent (right before left)', () => {
  const { sandbox } = loadAgent();
  const hit = sandbox.findNearbyPair([ptr(0x2000)], [ptr(0x1f00)], 256);
  assert.ok(hit, 'proximity is symmetric');
  assert.equal(hit.distance, 256);
});

test('findNearbyPair scans unsorted input correctly', () => {
  const { sandbox } = loadAgent();
  const left = [ptr(0x9000), ptr(0x1000), ptr(0x5000)];
  const right = [ptr(0x8000), ptr(0x5040), ptr(0x100)];
  const hit = sandbox.findNearbyPair(left, right, 0x100);
  assert.ok(hit, 'must sort internally rather than trusting input order');
  assert.equal(hit.distance, 0x40);
});

test('findNearbyPair does not mutate its inputs', () => {
  const { sandbox } = loadAgent();
  const left = [ptr(0x9000), ptr(0x1000)];
  const right = [ptr(0x8000)];
  const leftOrder = left.map((p) => p.toString());
  sandbox.findNearbyPair(left, right, 16);
  assert.deepEqual(left.map((p) => p.toString()), leftOrder,
    'callers still hold these arrays; sort a copy');
});
