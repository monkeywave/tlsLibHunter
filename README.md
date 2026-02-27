# TLSLibHunter

[![PyPI version](https://img.shields.io/pypi/v/tlsLibHunter)](https://pypi.org/project/tlsLibHunter/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/tlsLibHunter)](https://pypi.org/project/tlsLibHunter/)
[![Lint](https://github.com/monkeywave/tlsLibHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/monkeywave/tlsLibHunter/actions/workflows/lint.yml)
[![License](https://img.shields.io/pypi/l/tlsLibHunter)](https://github.com/monkeywave/tlsLibHunter/blob/main/LICENSE)

Identify and extract TLS/SSL libraries from running processes using dynamic instrumentation.

## Installation

```bash
pip install tlsLibHunter
```

## Quick Start

### CLI Usage

```bash
# List TLS libraries in a local process
tlsLibHunter firefox -l

# Scan and extract TLS libraries
tlsLibHunter firefox

# Android device
tlsLibHunter com.example.app -m -l

# JSON output
tlsLibHunter firefox -l -f json
```

### Example output:

```bash
tlslibhunter -m -l Chrome
INFO: Platform: android
INFO: Found 324 loaded modules
INFO: Pattern match in libssl.so: 1 hits
INFO: Detected: libssl.so (boringssl, system)
INFO: Pattern match in libmonochrome_64.so: 1 hits
INFO: Fingerprint: libmonochrome_64.so identified as boringssl
INFO: Detected: libmonochrome_64.so (boringssl, app)
INFO: Scan complete: 2 TLS libraries found in 298 modules (8.06s)
        				TLS Libraries in 'Chrome' (android)                    
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ #    ┃ Library             ┃ Type      ┃ Class  ┃      Size ┃ Path                                                                                                                                     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1    │ libssl.so           │ boringssl │ system │ 376.0 KiB │ /apex/com.… │
│ 2    │ libmonochrome_64.so │ boringssl │ app    │ 119.1 MiB │ /data/app/~~NlI… │
└──────┴─────────────────────┴───────────┴────────┴───────────┴────────────────────────────┘

Scanned 298 modules in 8.06s
```


### Python API

```python
from tlslibhunter import TLSLibHunter

# Scan a local process
hunter = TLSLibHunter("firefox")
result = hunter.scan()
for lib in result.libraries:
    print(f"{lib.name} ({lib.library_type}) - {lib.path}")

# Scan and extract
result = hunter.scan()
extractions = hunter.extract(result, output_dir="./extracted_libs")
```

## Features

- Memory scanning for TLS string patterns
- Supports OpenSSL, BoringSSL, GnuTLS, wolfSSL, mbedTLS, NSS, SChannel, SecureTransport
- Multi-platform: Android, iOS, Windows, Linux, macOS
- Multiple extraction methods: disk copy, ADB pull, APK extraction, memory dump
- Clean Python API for programmatic use
- Backend abstraction (currently only frida but might be extended to other frameworks in the future)

## License

MIT

