class DNAEncoder:
    binary_to_dna_map = {
        "00": 'A',
        "01": 'C',
        "10": 'G',
        "11": 'T'
    }
    dna_to_binary_map = {v: k for k, v in binary_to_dna_map.items()}

    @staticmethod
    def text_to_binary(text: str) -> str:
        return ''.join(f"{ord(c):08b}" for c in text)

    @staticmethod
    def binary_to_text(binary_str: str) -> str:
        chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)

    @classmethod
    def binary_to_dna(cls, binary_str: str) -> str:
        if len(binary_str) % 2 != 0:
            binary_str += '0'  # padding if odd length
        dna_seq = ""
        for i in range(0, len(binary_str), 2):
            pair = binary_str[i:i+2]
            dna_seq += cls.binary_to_dna_map[pair]
        return dna_seq

    @classmethod
    def dna_to_binary(cls, dna_str: str) -> str:
        return ''.join(cls.dna_to_binary_map[base] for base in dna_str)
