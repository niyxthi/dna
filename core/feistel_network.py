def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def dna_style_f(right: bytes, round_key: bytes) -> bytes:
    """
    DNA-inspired F(R, K):
    - Step 1: XOR R and K
    - Step 2: Treat each byte as 4 bases (00/01/10/11) and 'rotate' each base
      by the corresponding 2 bits from the key byte (mod 4).
    """
    # First, XOR like before
    xored = xor_bytes(right, round_key)

    result = bytearray()
    for rb, kb in zip(xored, round_key):
        new_byte = 0
        for i in range(4):  # 4 pairs of 2 bits in one byte
            # Extract 2-bit chunk from rb and kb
            r_pair = (rb >> (2 * i)) & 0b11        # 0..3
            k_pair = (kb >> (2 * i)) & 0b11        # 0..3

            # DNA-style "rotation": new base index = (r + k) mod 4
            # - If k_pair == 0 => no change
            # - If k_pair == 2 => complement-like effect (00->10, 01->11, etc.)
            new_pair = (r_pair + k_pair) & 0b11    # mod 4

            new_byte |= (new_pair << (2 * i))
        result.append(new_byte)

    return bytes(result)


class FeistelNetwork:
    def __init__(self, rounds=16, round_key_size=16):
        self.rounds = rounds
        self.block_size = 16
        self.round_key_size = self.block_size // 2
    
    def feistel_round(self, left: bytes, right: bytes, round_key: bytes) -> tuple[bytes, bytes]:
        # New DNA-style round function
        f_out = dna_style_f(right, round_key)
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
