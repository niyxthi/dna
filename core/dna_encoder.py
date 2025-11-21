class DNAEncoder:
    CODONS = [
        'AAA','AAC','AAG','AAT','ACA','ACC','ACG','ACT',
        'AGA','AGC','AGG','AGT','ATA','ATC','ATG','ATT',
        'CAA','CAC','CAG','CAT','CCA','CCC','CCG','CCT',
        'CGA','CGC','CGG','CGT','CTA','CTC','CTG','CTT',
        'GAA','GAC','GAG','GAT','GCA','GCC','GCG','GCT',
        'GGA','GGC','GGG','GGT','GTA','GTC','GTG','GTT',
        'TAA','TAC','TAG','TAT','TCA','TCC','TCG','TCT',
        'TGA','TGC','TGG','TGT','TTA','TTC','TTG','TTT'
    ]

    CODON_TO_INDEX = {codon: idx for idx, codon in enumerate(CODONS)}

    # (old maps can stay if you want, for backward compatibility)
    binary_to_dna_map = {
        "00": 'A',
        "01": 'C',
        "10": 'G',
        "11": 'T'
    }
    dna_to_binary_map = {v: k for k, v in binary_to_dna_map.items()}

    binary_to_dna_map = {
        "00": 'A',
        "01": 'C',
        "10": 'G',
        "11": 'T'
    }

    @staticmethod
    def text_to_binary(text: str) -> str:
        data = text.encode("utf-8")
        return ''.join(f"{byte:08b}" for byte in data)

    @staticmethod
    def binary_to_text(binary_str: str) -> str:
        bytes_list = [
            int(binary_str[i:i+8], 2)
            for i in range(0, len(binary_str), 8)
        ]
        return bytes(bytes_list).decode("utf-8", errors="ignore")
    
    @classmethod
    def binary_to_codon_dna(cls, binary_str: str) -> str:
        """
        Convert a binary string into a DNA string using 6-bit groups -> codons (3 bases).
        Padding: if bits not multiple of 6, pad with zeros at the end.
        """
        # Pad to multiple of 6
        if len(binary_str) % 6 != 0:
            pad_len = 6 - (len(binary_str) % 6)
            binary_str += '0' * pad_len
        else:
            pad_len = 0

        dna_seq = []
        for i in range(0, len(binary_str), 6):
            chunk = binary_str[i:i+6]
            idx = int(chunk, 2)          # 0..63
            codon = cls.CODONS[idx]
            dna_seq.append(codon)

        # You can optionally return pad_len too if you want to track it;
        # for now we'll assume we handle padding by knowing original length at decryption.
        return ''.join(dna_seq)

    @classmethod
    def codon_dna_to_binary(cls, dna_str: str) -> str:
        """
        Inverse of binary_to_codon_dna.
        Assumes dna_str length is multiple of 3.
        """
        if len(dna_str) % 3 != 0:
            raise ValueError("DNA length must be a multiple of 3 (codons)")

        bits = []
        for i in range(0, len(dna_str), 3):
            codon = dna_str[i:i+3]
            idx = cls.CODON_TO_INDEX.get(codon)
            if idx is None:
                raise ValueError(f"Invalid codon in DNA sequence: {codon}")
            bits.append(f"{idx:06b}")
        return ''.join(bits)

    # Partial example – fill the full table from any standard codon chart
    GENETIC_CODE = {
        # Phenylalanine
        "TTT": "F", "TTC": "F",
        # Leucine
        "TTA": "L", "TTG": "L", "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",
        # ...
        # Fill in the rest: I, M, V, S, P, T, A, Y, H, Q, N, K, D, E, C, W, R, G, and stop codons (*)
    }

    @classmethod
    def dna_to_amino_acids(cls, dna_str: str) -> str:
        """
        Map DNA codon string to amino acid sequence.
        This is *one-way* (not used for decryption).
        """
        if len(dna_str) % 3 != 0:
            raise ValueError("DNA length must be a multiple of 3 to map to amino acids.")
        aa_seq = []
        for i in range(0, len(dna_str), 3):
            codon = dna_str[i:i+3]
            aa = cls.GENETIC_CODE.get(codon, 'X')  # X for unknown / padding codons
            aa_seq.append(aa)
        return ''.join(aa_seq)


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
