def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class FeistelNetwork:
    def __init__(self, rounds=16, round_key_size=16):
        self.rounds = rounds
        self.round_key_size = round_key_size

    def feistel_round(self, left: bytes, right: bytes, round_key: bytes) -> tuple[bytes, bytes]:
        # Simple round function: XOR right with round_key
        f_out = xor_bytes(right, round_key)
        new_right = xor_bytes(left, f_out)
        new_left = right
        return new_left, new_right

    def encrypt(self, plaintext: bytes, round_keys: list) -> bytes:
        left, right = plaintext[:len(plaintext)//2], plaintext[len(plaintext)//2:]
        for i in range(self.rounds):
            left, right = self.feistel_round(left, right, round_keys[i])
        return right + left  # note: swap halves on return

    def decrypt(self, ciphertext: bytes, round_keys: list) -> bytes:
        right, left = ciphertext[:len(ciphertext)//2], ciphertext[len(ciphertext)//2:]
        for i in reversed(range(self.rounds)):
            right, left = self.feistel_round(right, left, round_keys[i])
        return left + right
