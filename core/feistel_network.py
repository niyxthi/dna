def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def dna_feistel_f(right: bytes, round_key: bytes) -> bytes:
    """
    DNA-safe Feistel F:
    - XOR with key
    - Rotate-right by (k % 8) bits per byte
    This is 100% Feistel-invertible because rotation is invertible.
    """
    out = bytearray()

    for r, k in zip(right, round_key):
        x = r ^ k  # XOR stays Feistel-compatible

        rot = k & 7  # use lowest 3 bits as rotation amount (0..7)
        rotated = ((x >> rot) | (x << (8 - rot))) & 0xFF

        out.append(rotated)

    return bytes(out)
class FeistelNetwork:
    def __init__(self, rounds=16, round_key_size=16):
        self.rounds = rounds
        self.block_size = 16
        self.round_key_size = self.block_size // 2
    
    def feistel_round(self, left: bytes, right: bytes, round_key: bytes):
        f_out = dna_feistel_f(right, round_key)
        new_right = bytes(a ^ b for a, b in zip(left, f_out))
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
