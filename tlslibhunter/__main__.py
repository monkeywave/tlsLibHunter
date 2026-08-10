"""Allow running as: python -m tlslibhunter"""

import sys

from tlslibhunter.cli import main

if __name__ == "__main__":
    # sys.exit, not a bare main(): main() signals failure through its return
    # value (1 on error, 130 on Ctrl-C) and discarding it made `python -m
    # tlslibhunter` always exit 0, so scripts could not detect a failed scan.
    # The console-script wrapper generated from setup.py already does this.
    sys.exit(main())
