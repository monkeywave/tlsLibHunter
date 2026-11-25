# Changelog

All notable changes to tlsLibHunter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This file starts at 0.2.9; earlier versions are documented only in git history.

## [0.3.2]

### Added
  - **Hint about related Android processes** — after attaching, tlsLibHunter
    looks up the target's other processes (same package or same app UID) and
    the package hosting the foreground UI. When another app hosts the UI it
    logs a WARNING naming those PIDs, e.g. for the Gemini app
    (`com.google.android.apps.bard`), whose launcher trampolines to the Google
    app: "Foreground UI of 'com.google.android.apps.bard' is hosted by
    'com.google.android.googlequicksearchbox' (PIDs 568 :search, 12274
    :googleapp, ...). TLS traffic is likely there". Other processes of the
    same app are reported at INFO.
  - **`--all-processes`** (Android) — scans the target and then every related
    process (UI host first, then sibling processes) through the regular
    single-process scan with the same options (`--unfreeze`, `-o`/extraction
    into per-PID directories, `-d`, ...). A process that cannot be scanned
    (attach timeout, isolated/permission-denied, exited) is logged and the
    remaining scans continue. Prints each process's table plus a combined
    summary table; `-f json` prints one combined document. For Gemini this
    finds the TLS libraries of the Google app processes that actually carry
    its traffic. On other platforms it warns and scans only the target.

## [0.3.1]

### Fixed
  - **Packaging warnings on install** — removed the deprecated
    `License :: OSI Approved :: MIT License` classifier (the SPDX `license="MIT"`
    field already declares it) and listed `tlslibhunter.scripts` explicitly as a
    package so the bundled Frida agents (`*.js`) are no longer flagged as
    "Package would be ignored".

## [0.3.0]

### Added
  - **`--unfreeze` retries an attach that timed out on a frozen process**
    (Android, root) — when the target is frozen by Android's cached-apps freezer
    (`cgroup.freeze=1`), tlsLibHunter unfreezes the process and retries the
    attach once. Android may re-freeze it later.
  - **App-aware targeting on mobile** — a target that matches no process name is
    resolved against installed apps by label or identifier (e.g. `Gemini` →
    `com.google.android.apps.bard`); a running app is attached with a WARNING
    naming it, and `-s` resolves an app label to its identifier before spawning.
    Ambiguous labels are refused.

### Changed
  - **Not-found errors say what to do next** — an app that is installed but not
    running is reported as such, with the `-s <identifier>` command to spawn it;
    otherwise the running apps are listed and `frida-ps -Uai` is suggested. This
    replaces the dump of the first 20 processes by PID (init, logd, vold, ...).
  - **With `-d`, expected backend errors print one line** — process/device not
    found and attach refused/timed out no longer print a traceback to the
    console; it goes only to the debug log file.

### Fixed
  - **Frida attach timeouts are reported as a Frida-level failure with a
    diagnosis** — "timed out while waiting for stop from process with PID n"
    (plain `frida` fails the same way) is now attributed to either the
    cached-apps freezer (e.g. Gemini on Android 14, whose launcher hands off to
    the Google app so the `bard` process is frozen in the background) or an
    existing tracer (`TracerPid` != 0, anti-debugging). Investigation showed
    Gemini is not using anti-debugging (`TracerPid` 0).

## [0.2.9]

### Fixed
  - **A named process that exists but cannot be instrumented is now reported
    instead of silently scanning a different one** — a permission failure on the
    exact match was treated as "not found", so `tlslibhunter Finder` fell through
    to a substring match, attached to `QLMarkdown Preview Extension (Finder)`
    (PID 16891) and titled the results `TLS Libraries in 'Finder'`.
  - **Results name the process actually instrumented**, through new
    `attached_process` / `attached_pid` / `target_mismatch` fields that every
    formatter renders and flags when it differs from what was requested.
  - **An ambiguous process name is refused rather than resolved arbitrarily**, and
    a fall-back to a looser name match is logged at WARNING with the candidates.
  - **A transport failure is no longer blamed on the target** — frida resolves a
    name over the device link before attaching, so a dead frida-server surfaced
    here and was reported as "likely hardened or SIP-protected".
  - **`--format json` is machine-parseable** — agent `console.log` output reached
    stdout through frida's default log handler, corrupting the JSON document, and
    is now routed to the logger on stderr.
  - **Extraction after crash recovery no longer fails silently** — a re-spawn
    replaced the scanner's session but the hunter kept the dead original, and
    because `extract()` short-circuits on an already-initialised hunter, every
    library failed against it.
  - **A spawned target is killed rather than left suspended indefinitely** when
    `attach` or `resume` fails after `device.spawn()`.
  - **A script is unloaded when `load()` raises or an extraction RPC fails**,
    instead of staying resident in the target for the rest of the run.
  - **`close()` releases the backend and device**, and a `--host` remote device is
    removed once the last backend using it closes.
  - **`python -m tlslibhunter` exits non-zero on failure** — `main()`'s return code
    was discarded, so a failed scan always exited 0 (the console script was fine).

### Changed
  - Process-name matching has a single definition (`is_exact_name` /
    `name_matches`) shared by the resolver and the frida backend, and both output
    formatters share one `attached_label()` helper.

### Testing
  - 63 new tests across three files covering target resolution, session ownership
    across crash recovery, and resource release on failure paths (365 total).
