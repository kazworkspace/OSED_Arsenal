#!/usr/bin/env python3
"""
bo_scanner — Windows x86 PE buffer overflow static analysis tool.

Usage:
    python bo_scanner.py sample.exe
    python bo_scanner.py sample.exe -o report.json -v
    python bo_scanner.py sample.exe --api memcpy --min-confidence 0.6
    python bo_scanner.py sample.exe --function 0x401230
"""
import sys
import os

# Allow running from the directory that contains this script
sys.path.insert(0, os.path.dirname(__file__))

from bo_scanner.cli import run

if __name__ == "__main__":
    sys.exit(run())
