#!/usr/bin/env python
""" This module acts as a wrapper around the two different types of tests we run
1. Cram tests
2. Unit tests with Unity
Automake allows one entry point into the test suite and this python script is it.
"""
import os
import sys
import subprocess

def main():
    test_file = sys.argv[1]
    if test_file.endswith(".t"):
        # Tests that end in .t are cram tests
        retcode = subprocess.call(["python", "cram.py", test_file])
        sys.exit(retcode)
    else:
        # Assume it's an executable to be run
        retcode = subprocess.call(test_file)
        sys.exit(retcode)


if __name__ == '__main__':
    main()
