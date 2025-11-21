def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR a with b, extending b cyclically to match a's length."""
    if len(b) == 0:
        return a  # should never happen
    b_extended = (b * ((len(a) // len(b)) + 1))[:len(a)]
    return bytes(x ^ y for x, y in zip(a, b_extended))

def dna_feistel_f(right: bytes, round_key: bytes) -> bytes:
    """
    DNA-safe Feistel F:
    - XOR with key (key repeated to match length)
    - Rotate-right by (k % 8) bits per byte
    Fully length-preserving.
    """
    out = bytearray()
    key_ext = (round_key * ((len(right) // len(round_key)) + 1))[:len(right)]

    for r, k in zip(right, key_ext):
        x = r ^ k
        rot = k & 7
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
        new_right = xor_bytes(left, f_out)  # ALWAYS same size as left
        new_left = right
        return new_left, new_right

    def encrypt(self, plaintext: bytes, round_keys: list) -> bytes:
        half = len(plaintext) // 2
        left, right = plaintext[:half], plaintext[half:]
        for i in range(self.rounds):
            left, right = self.feistel_round(left, right, round_keys[i])
        return right + left

    def decrypt(self, ciphertext: bytes, round_keys: list) -> bytes:
        half = len(ciphertext) // 2
        right, left = ciphertext[:half], ciphertext[half:]
        for i in reversed(range(self.rounds)):
            right, left = self.feistel_round(right, left, round_keys[i])
        return left + right
