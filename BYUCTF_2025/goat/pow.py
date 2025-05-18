#!/usr/bin/env python3
import hashlib
import sys

def main(prefix):
    difficulty = 20
    bound = 1 << (64 - difficulty)

    i = 0
    while True:
        i += 1
        s = prefix + str(i)
        if int.from_bytes(hashlib.sha256(s.encode()).digest()[:8], "big") < bound:
            return str(i)

if __name__ == "__main__":
    prefix = sys.argv[1]
    answer = main(prefix)

    print(f"Answer: {answer}")