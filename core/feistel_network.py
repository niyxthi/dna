DEBUG_MODE = True

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR a with b, extending b cyclically to match a's length.
    This guarantees the result has the same length as a.
    """
    if len(b) == 0:
        return a
    # Repeat key material to cover the full length of a
    b_extended = (b * ((len(a) // len(b)) + 1))[:len(a)]
    return bytes(x ^ y for x, y in zip(a, b_extended))


def dna_feistel_f(right: bytes, round_key: bytes) -> bytes:
    """
    DNA-inspired Feistel round function F:

      F(R, K):
        1) Extend K to match len(R)
        2) X = R XOR K_ext
        3) For each byte x in X, rotate-right by (k & 7) bits

    This is length-preserving and invertible inside a Feistel structure.
    """
    if len(right) == 0:
        return b""

    key_ext = (round_key * ((len(right) // len(round_key)) + 1))[:len(right)]
    out = bytearray()

    for r, k in zip(right, key_ext):
        x = r ^ k
        rot = k & 7  # 0..7
        rotated = ((x >> rot) | (x << (8 - rot))) & 0xFF
        out.append(rotated)

    return bytes(out)


class FeistelNetwork:
    def __init__(self, rounds: int = 16, round_key_size: int = 16):
        self.rounds = rounds
        self.round_key_size = round_key_size

    def feistel_round(self, left: bytes, right: bytes, round_key: bytes):
        f_out = dna_feistel_f(right, round_key)
        new_right = xor_bytes(left, f_out)
        new_left = right
        return new_left, new_right

    def encrypt(self, plaintext: bytes, round_keys: list[bytes]) -> bytes:
        assert len(plaintext) % 2 == 0, "Feistel plaintext must have even length (pad it first)."
        half = len(plaintext) // 2
        left, right = plaintext[:half], plaintext[half:]

        if DEBUG_MODE:
            print("\n[FEISTEL] === Encryption ===")
            print(f"[FEISTEL] Initial L = {left.hex()}")
            print(f"[FEISTEL] Initial R = {right.hex()}")

        for i in range(self.rounds):
            if DEBUG_MODE:
                print(f"[FEISTEL] Round {i}: Using round key {round_keys[i].hex()}")
            left, right = self.feistel_round(left, right, round_keys[i])
            if DEBUG_MODE:
                print(f"[FEISTEL] After round {i}: L = {left.hex()}, R = {right.hex()}")

        cipher = right + left  # swap halves
        if DEBUG_MODE:
            print(f"[FEISTEL] Final ciphertext bytes = {cipher.hex()}")
        return cipher

    def decrypt(self, ciphertext: bytes, round_keys: list[bytes]) -> bytes:
        assert len(ciphertext) % 2 == 0, "Feistel ciphertext must have even length."
        half = len(ciphertext) // 2
        right, left = ciphertext[:half], ciphertext[half:]

        if DEBUG_MODE:
            print("\n[FEISTEL] === Decryption ===")
            print(f"[FEISTEL] Initial R = {right.hex()}")
            print(f"[FEISTEL] Initial L = {left.hex()}")

        for i in reversed(range(self.rounds)):
            if DEBUG_MODE:
                print(f"[FEISTEL] Round {i}: Using round key {round_keys[i].hex()}")
            right, left = self.feistel_round(right, left, round_keys[i])
            if DEBUG_MODE:
                print(f"[FEISTEL] After round {i}: R = {right.hex()}, L = {left.hex()}")

        plain = left + right
        if DEBUG_MODE:
            print(f"[FEISTEL] Final decrypted bytes = {plain.hex()}")
        return plain
