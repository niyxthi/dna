class DNAEncoder:
    # 2-bit mapping (kept for backward compatibility / other uses)
    binary_to_dna_map = {
        "00": 'A',
        "01": 'C',
        "10": 'G',
        "11": 'T'
    }
    dna_to_binary_map = {v: k for k, v in binary_to_dna_map.items()}

    # 64 codons (3-base combinations)
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

    # Standard genetic code (codon -> amino acid)
    GENETIC_CODE = {
        # Phenylalanine (F)
        "TTT": "F", "TTC": "F",

        # Leucine (L)
        "TTA": "L", "TTG": "L",
        "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",

        # Isoleucine (I)
        "ATT": "I", "ATC": "I", "ATA": "I",

        # Methionine / Start (M)
        "ATG": "M",

        # Valine (V)
        "GTT": "V", "GTC": "V", "GTA": "V", "GTG": "V",

        # Serine (S)
        "TCT": "S", "TCC": "S", "TCG": "S", "TCA": "S",
        "AGT": "S", "AGC": "S",

        # Proline (P)
        "CCT": "P", "CCC": "P", "CCA": "P", "CCG": "P",

        # Threonine (T)
        "ACT": "T", "ACC": "T", "ACA": "T", "ACG": "T",

        # Alanine (A)
        "GCT": "A", "GCC": "A", "GCA": "A", "GCG": "A",

        # Tyrosine (Y)
        "TAT": "Y", "TAC": "Y",

        # Histidine (H)
        "CAT": "H", "CAC": "H",

        # Glutamine (Q)
        "CAA": "Q", "CAG": "Q",

        # Asparagine (N)
        "AAT": "N", "AAC": "N",

        # Lysine (K)
        "AAA": "K", "AAG": "K",

        # Aspartic Acid (D)
        "GAT": "D", "GAC": "D",

        # Glutamic Acid (E)
        "GAA": "E", "GAG": "E",

        # Cysteine (C)
        "TGT": "C", "TGC": "C",

        # Tryptophan (W)
        "TGG": "W",

        # Arginine (R)
        "CGT": "R", "CGC": "R", "CGA": "R", "CGG": "R",
        "AGA": "R", "AGG": "R",

        # Glycine (G)
        "GGT": "G", "GGC": "G", "GGA": "G", "GGG": "G",

        # STOP codons
        "TAA": "*", "TAG": "*", "TGA": "*"
    }

    # ---------- Text / binary ----------

    @staticmethod
    def text_to_binary(text: str) -> str:
        """
        UTF-8 text -> binary string.
        """
        data = text.encode("utf-8")
        return ''.join(f"{byte:08b}" for byte in data)

    @staticmethod
    def binary_to_text(binary_str: str) -> str:
        """
        Binary string -> UTF-8 text (best effort).
        """
        if len(binary_str) % 8 != 0:
            # ignore trailing partial byte (shouldn't normally happen)
            binary_str = binary_str[:len(binary_str) - (len(binary_str) % 8)]
        bytes_list = [
            int(binary_str[i:i+8], 2)
            for i in range(0, len(binary_str), 8)
        ]
        return bytes(bytes_list).decode("utf-8", errors="ignore")

    # ---------- Codon DNA encoding ----------

    @classmethod
    def binary_to_codon_dna(cls, binary_str: str):
        """
        Convert binary -> codon DNA using 6-bit groups.
        Returns (dna_string, pad_len_bits).
        pad_len is how many '0' bits we appended at the END.
        """
        pad_len = (6 - (len(binary_str) % 6)) % 6
        if pad_len != 0:
            binary_str += '0' * pad_len

        dna_seq = []
        for i in range(0, len(binary_str), 6):
            chunk = binary_str[i:i+6]
            idx = int(chunk, 2)  # 0..63
            dna_seq.append(cls.CODONS[idx])

        return ''.join(dna_seq), pad_len

    @classmethod
    def codon_dna_to_binary(cls, dna_str: str) -> str:
        """
        Codon DNA -> binary (6 bits per codon).
        Does NOT remove padding; caller must strip pad_len bits.
        """
        if len(dna_str) % 3 != 0:
            raise ValueError("DNA length must be a multiple of 3 (codons).")

        bits = []
        for i in range(0, len(dna_str), 3):
            codon = dna_str[i:i+3]
            idx = cls.CODON_TO_INDEX.get(codon)
            if idx is None:
                raise ValueError(f"Invalid codon in DNA sequence: {codon}")
            bits.append(f"{idx:06b}")
        return ''.join(bits)

    # ---------- Amino acid projection (for visualization only) ----------

    @classmethod
    def dna_to_amino_acids(cls, dna_str: str) -> str:
        """
        DNA codon string -> amino acid sequence.
        Not used for decryption (one-way mapping).
        """
        if len(dna_str) % 3 != 0:
            raise ValueError("DNA length must be a multiple of 3.")
        aa_seq = []
        for i in range(0, len(dna_str), 3):
            codon = dna_str[i:i+3]
            aa = cls.GENETIC_CODE.get(codon, 'X')
            aa_seq.append(aa)
        return ''.join(aa_seq)

    # ---------- Old 2-bit DNA mapping (still available) ----------

    @classmethod
    def binary_to_dna(cls, binary_str: str) -> str:
        """
        2-bit -> base (A/C/G/T). Not used in new cipher, but kept.
        """
        if len(binary_str) % 2 != 0:
            binary_str += '0'
        dna_seq = []
        for i in range(0, len(binary_str), 2):
            pair = binary_str[i:i+2]
            dna_seq.append(cls.binary_to_dna_map[pair])
        return ''.join(dna_seq)

    @classmethod
    def dna_to_binary(cls, dna_str: str) -> str:
        """
        Base (A/C/G/T) -> 2-bit binary. Not used in new cipher, but kept.
        """
        return ''.join(cls.dna_to_binary_map[base] for base in dna_str)
