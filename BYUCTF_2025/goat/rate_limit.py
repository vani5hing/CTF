import secrets
import hashlib

class NcPowser:
    def __init__(self, difficulty=20, prefix_length=16):
        self.difficulty = difficulty
        self.prefix_length = prefix_length

    def get_challenge(self):
        return secrets.token_urlsafe(self.prefix_length)[:self.prefix_length].replace('-', 'b').replace('_', 'a')

    def verify_hash(self, prefix, answer):
        h = hashlib.sha256()
        h.update((prefix + answer).encode())
        bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
        return bits.startswith('0' * self.difficulty)

if __name__ == '__main__':
    powser = NcPowser()
    prefix = powser.get_challenge()

    print(f"Challenge: {prefix} (run \"python3 pow.py {prefix}\")")
    answer = input("Answer: ")

    if not powser.verify_hash(prefix, answer):
        print("Invalid answer")
        exit(1)

    print("Correct answer")
    print("===========================")