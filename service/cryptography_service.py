from core.dna_encoder import DNAEncoder
from core.feistel_network import FeistelNetwork
from core.quantum_keygen import QuantumResistantKeyGen
from service.key_management import KeyManagementService


class CryptographyService:
    def __init__(self):
        self.dna_encoder = DNAEncoder()
        self.key_manager = KeyManagementService()
        self.feistel = FeistelNetwork()

    AMINO_GROUPS = {
        "hydro": "AVILMFWY",
        "polar": "STNQC",
        "basic": "KRH",
        "acid":  "DE",
        "special": "GP",
        "stop": "*"
    }

    def amino_confuse(self, aa_seq: str, dna_key: str) -> str:
        """
        Biologically accurate amino-acid confusion layer.
        Mutates amino acids within their biochemical groups
        (hydrophobic, polar, acidic, basic, special).
        STOP codons (*) stay unchanged.
        """
        # Determine shift from DNA key (biologically safe)
        shift = sum(ord(x) for x in dna_key) % 7  # 7 is good biological rotation

        reverse_map = {}
        for group_name, letters in self.AMINO_GROUPS.items():
            for aa in letters:
                reverse_map[aa] = letters

        confused = []

        for aa in aa_seq:
            if aa == "*":
                confused.append("*")
                continue

            group = reverse_map.get(aa)
            if not group:
                confused.append(aa)
                continue

            idx = group.index(aa)
            new_idx = (idx + shift) % len(group)
            confused.append(group[new_idx])

        return "".join(confused)

    def encrypt(self, plain_text: str, dna_key: str) -> str:
        """
        Encrypts UTF-8 text using:
        - Feistel network over bytes (with even-length padding)
        - Codon-based DNA encoding for ciphertext representation

        Output format:
            <plain_len_bytes>|<plain_bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        # 1) Text -> binary (UTF-8)
        binary_data = self.dna_encoder.text_to_binary(plain_text)
        plain_bit_len = len(binary_data)

        # 2) Binary -> bytes (group 8 bits)
        plain_bytes = bytes(
            int(binary_data[i:i+8], 2)
            for i in range(0, len(binary_data), 8)
        )
        plain_len = len(plain_bytes)

        # 3) Pad to EVEN length for Feistel (required for splitting into two halves)
        feistel_pad = 0
        feistel_input = plain_bytes
        if len(feistel_input) % 2 != 0:
            feistel_input += b"\x00"
            feistel_pad = 1  # we added 1 padding byte at the end

        # 4) Generate Feistel round keys from DNA key
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 5) Feistel encryption
        encrypted_bytes = self.feistel.encrypt(feistel_input, round_keys)

        # 6) Cipher bytes -> binary string (8 bits per byte)
        encrypted_bin = ''.join(f"{b:08b}" for b in encrypted_bytes)

        # 7) Binary -> codon-based DNA (6 bits -> codon)
        dna_seq, codon_pad = self.dna_encoder.binary_to_codon_dna(encrypted_bin)
        # --- Amino-acid confusion layer (biologically accurate) ---
        aa_seq = self.dna_encoder.dna_to_amino_acids(dna_seq)
        aa_confused = self.amino_confuse(aa_seq, dna_key)

        # Final ciphertext format (5 fields):
        # plain_len | plain_bit_len | feistel_pad | codon_pad | dna_seq
        return f"{plain_len}|{plain_bit_len}|{feistel_pad}|{codon_pad}|{dna_seq}|{aa_confused}"

    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        """
        Accepts BOTH formats automatically:
          5 fields: <len>|<bits>|<feistel_pad>|<codon_pad>|<dna_seq>
          6 fields: <len>|<bits>|<feistel_pad>|<codon_pad>|<dna_seq>|<amino_confused>
        The amino-acid confusion layer is ignored.
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        encrypted_dna = encrypted_dna.strip()

        # Split into MAX 6 parts
        parts = encrypted_dna.split("|")

        if len(parts) < 5:
            raise ValueError(
                "Invalid encrypted DNA format. Expected at least 5 fields:"
                " <plain_len>|<bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>"
            )

        # Handle both cases:
        # 5 fields  -> parts = [len, bits, feistel_pad, codon_pad, dna_seq]
        # 6 fields  -> parts = [len, bits, feistel_pad, codon_pad, dna_seq, amino_confused]
        plain_len_str     = parts[0]
        plain_bits_str    = parts[1]
        feistel_pad_str   = parts[2]
        codon_pad_str     = parts[3]
        dna_seq           = parts[4]  # final codon DNA sequence
        # parts[5] exists (if amino-confusion layer present) → safely ignored

        # Convert numeric fields
        try:
            plain_len   = int(plain_len_str)
            plain_bits  = int(plain_bits_str)
            feistel_pad = int(feistel_pad_str)
            codon_pad   = int(codon_pad_str)
        except:
            raise ValueError("Failed to parse metadata fields in ciphertext header.")

        # 1) DNA codons → 6-bit binary
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        # 2) Remove codon padding bits
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]

        # 3) Expected Feistel cipher length = original plaintext length + pad byte
        expected_cipher_bytes = plain_len + feistel_pad
        expected_bits = expected_cipher_bytes * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Ciphertext corruption: expected {expected_bits} bits, "
                f"got {len(encrypted_binary)} bits after codon depadding."
            )

        # 4) Binary → bytes
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i+8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        # 5) Regenerate Feistel round keys
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 6) Feistel decrypt
        decrypted_bytes_full = self.feistel.decrypt(encrypted_bytes, round_keys)

        # 7) Remove Feistel padding byte if present
        if feistel_pad == 1:
            decrypted_bytes = decrypted_bytes_full[:-1]
        else:
            decrypted_bytes = decrypted_bytes_full

        # Ensure correct plaintext length
        if len(decrypted_bytes) != plain_len:
            raise ValueError(
                f"Plaintext length mismatch: expected {plain_len}, "
                f"got {len(decrypted_bytes)}"
            )

        # 8) Bytes → binary → truncate to bit length
        decrypted_bin = ''.join(f"{b:08b}" for b in decrypted_bytes)
        decrypted_bin = decrypted_bin[:plain_bits]

        # 9) Binary → text
        return self.dna_encoder.binary_to_text(decrypted_bin)

