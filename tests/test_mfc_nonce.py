#!/usr/bin/env python3
import subprocess
import os
import sys

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srcdir = os.path.join(root, 'src', 'modules', 'rfid')
    test = os.path.join(root, 'tests', 'test_mfc_nonce.cpp')
    out = '/tmp/test_mfc_nonce'
    # compile with sources
    cmd = ['g++', '-std=c++11', '-I' + srcdir, test,
           os.path.join(srcdir, 'crypto1.cpp'),
           os.path.join(srcdir, 'mfc_nonce.cpp'),
           '-o', out]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print('compile failed')
        return r.returncode
    r = subprocess.run([out])
    print('rc', r.returncode)
    return r.returncode

if __name__ == '__main__':
    sys.exit(main())
