# CryptoBrute
A crypto wallet recovery tool that leverages brute-force and masking for seed phrase recovery.


Installation

- Required: Python 3.12.13
- Libraries: coincurve, bip-utils, requests

- Windows: download from Python.org
- Mac OS:
  brew install python@3.12

- Libraries:
  pip install coincurve bip-utils requests


Command-Line Options

usage: cryptoBrute.py [-h] {check,brute} ...

Bitcoin Wallet Recovery and Brute-Force Tool.

positional arguments:
  {check,brute}  Available commands
    check        Check a single, complete seed phrase.
    brute        Brute-force a partial seed phrase using '?' as a placeholder.

options:
  -h, --help     show this help message and exit