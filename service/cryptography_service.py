from core.dna_encoder import DNAEncoder
from core.feistel_network import FeistelNetwork
from core.quantum_keygen import QuantumResistantKeyGen
from service.key_management import KeyManagementService

DEBUG_MODE = True


class CryptographyService:
    # Amino-acid biochemical groupings for confusion layer
    AMINO_GROUPS = {
        "hydro": "AVILMFWY",   # hydrophobic
        "polar": "STNQC",      # polar uncharged
        "basic": "KRH",        # positively charged
        "acid":  "DE",         # negatively charged
        "special": "GP",       # special structural
        "stop": "*"            # termination
    }

    def __init__(self):
        self.dna_encoder = DNAEncoder()
        self.key_manager = KeyManagementService()
        self.feistel = FeistelNetwork()

    # ---------- Amino-acid confusion layer ----------

    def amino_confuse(self, aa_seq: str, dna_key: str) -> str:
        """
        Biochemically-plausible confusion of amino-acid sequence.
        Mutates amino acids within their biochemical groups; STOP (*) unchanged.
        """
        # Derive a small rotation from DNA key
        shift = sum(ord(x) for x in dna_key) % 7

        # Build reverse map: amino-acid -> its group string
        reverse_map = {}
        for _, letters in self.AMINO_GROUPS.items():
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
    
    def decrypt_with_seed(self, encrypted_dna: str, seed: bytes) -> str:
        """
        SERVER-SIDE decryption:
        Uses a quantum-resistant seed instead of the DNA key.
        This preserves the 'server never sees the DNA key' model.

        Accepts 5-field or 6-field ciphertext:
          len|bits|feistel_pad|codon_pad|dna_seq
          len|bits|feistel_pad|codon_pad|dna_seq|aa_confused
        """
        enc_str = encrypted_dna.strip()
        parts = enc_str.split("|")

        if len(parts) < 5:
            raise ValueError(
                "Invalid encrypted DNA format. Expected at least 5 fields: "
                "<plain_len>|<bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>"
            )

        plain_len_str = parts[0]
        plain_bits_str = parts[1]
        feistel_pad_str = parts[2]
        codon_pad_str = parts[3]
        dna_seq = parts[4]  # ignore AA confusion layer if present

        try:
            plain_len = int(plain_len_str)
            plain_bits = int(plain_bits_str)
            feistel_pad = int(feistel_pad_str)
            codon_pad = int(codon_pad_str)
        except Exception:
            raise ValueError("Failed to parse metadata fields in ciphertext header.")

        if DEBUG_MODE:
            print("\n=== DECRYPTION PIPELINE (SERVER / SEED MODE) ===")
            print("[DEC] Header -> plain_len =", plain_len,
                  ", plain_bits =", plain_bits,
                  ", feistel_pad =", feistel_pad,
                  ", codon_pad =", codon_pad)
            print("[DEC] DNA seq (first 60):",
                  dna_seq[:60] + ("..." if len(dna_seq) > 60 else ""))

        # 1) Codon DNA -> binary (6-bit groups)
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        if DEBUG_MODE:
            print("[DEC] Encrypted binary (6-bit groups, first 64):",
                  encrypted_binary[:64] + ("..." if len(encrypted_binary) > 64 else ""))

        # 2) Remove codon padding bits
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]
            if DEBUG_MODE:
                print("[DEC] After removing codon pad bits, len =", len(encrypted_binary))

        # 3) Expected Feistel cipher length (bytes)
        expected_cipher_bytes = plain_len + feistel_pad
        expected_bits = expected_cipher_bytes * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Ciphertext corruption: expected {expected_bits} bits, "
                f"got {len(encrypted_binary)} bits after codon depadding."
            )

        # 4) Binary -> bytes
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i+8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        if DEBUG_MODE:
            print("[DEC] Encrypted bytes:", encrypted_bytes.hex())

        # 5) Regenerate Feistel round keys FROM SEED
        round_keys = QuantumResistantKeyGen.generate_round_keys_from_seed(
            seed,
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

        if len(decrypted_bytes) != plain_len:
            raise ValueError(
                f"Plaintext length mismatch: expected {plain_len}, got {len(decrypted_bytes)}"
            )

        if DEBUG_MODE:
            print("[DEC] Decrypted bytes:", decrypted_bytes.hex())

        # 8) Bytes -> binary
        decrypted_bin = ''.join(f"{b:08b}" for b in decrypted_bytes)
        decrypted_bin = decrypted_bin[:plain_bits]

        if DEBUG_MODE:
            print("[DEC] Decrypted bits (first 64):",
                  decrypted_bin[:64] + ("..." if len(decrypted_bin) > 64 else ""))

        # 9) Binary -> text
        plain_text = self.dna_encoder.binary_to_text(decrypted_bin)

        if DEBUG_MODE:
            print("[DEC] Final plaintext:", repr(plain_text))

        return plain_text

    # ---------- Encryption ----------

    def encrypt(self, plain_text: str, dna_key: str) -> str:
        """
        Encrypts plaintext into codon-based DNA ciphertext with amino-acid projection.

        Output format:
          <plain_len_bytes>|<plain_bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>|<aa_confused>
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        # 1) Text -> binary
        binary_data = self.dna_encoder.text_to_binary(plain_text)
        plain_bit_len = len(binary_data)

        # 2) Binary -> bytes
        plain_bytes = bytes(
            int(binary_data[i:i+8], 2)
            for i in range(0, len(binary_data), 8)
        )
        plain_len = len(plain_bytes)

        if DEBUG_MODE:
            print("\n=== ENCRYPTION PIPELINE ===")
            print("[ENC] Plaintext:", repr(plain_text))
            print("[ENC] Plaintext bits (first 64):",
                  binary_data[:64] + ("..." if len(binary_data) > 64 else ""))
            print(f"[ENC] Plaintext bytes ({plain_len}B):", plain_bytes.hex())

        # 3) Pad to even length for Feistel
        feistel_pad = 0
        feistel_input = plain_bytes
        if len(feistel_input) % 2 != 0:
            feistel_input += b"\x00"
            feistel_pad = 1
            if DEBUG_MODE:
                print("[ENC] Feistel pad added (1 byte). New length:", len(feistel_input))

        # 4) Generate Feistel round keys from DNA key
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 5) Feistel encrypt
        encrypted_bytes = self.feistel.encrypt(feistel_input, round_keys)

        if DEBUG_MODE:
            print("[ENC] Encrypted bytes:", encrypted_bytes.hex())

        # 6) Bytes -> binary string
        encrypted_bin = ''.join(f"{b:08b}" for b in encrypted_bytes)

        # 7) Binary -> codon DNA
        dna_seq, codon_pad = self.dna_encoder.binary_to_codon_dna(encrypted_bin)

        if DEBUG_MODE:
            print("[ENC] Cipher bits (first 64):",
                  encrypted_bin[:64] + ("..." if len(encrypted_bin) > 64 else ""))
            print("[ENC] Codon DNA (first 60):",
                  dna_seq[:60] + ("..." if len(dna_seq) > 60 else ""))
            print("[ENC] Codon pad bits:", codon_pad)

        # 8) Amino-acid confusion layer
        aa_seq = self.dna_encoder.dna_to_amino_acids(dna_seq)
        aa_confused = self.amino_confuse(aa_seq, dna_key)

        if DEBUG_MODE:
            print("[ENC] Amino-acid projection:", aa_seq)
            print("[ENC] Amino-acid confused seq:", aa_confused)

        # Final ciphertext string
        cipher_str = f"{plain_len}|{plain_bit_len}|{feistel_pad}|{codon_pad}|{dna_seq}|{aa_confused}"

        if DEBUG_MODE:
            print("[ENC] Final ciphertext string:", cipher_str)

        return cipher_str

    # ---------- Decryption ----------

    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        """
        Decrypts ciphertext in either 5-field or 6-field format:

          5 fields: len|bits|feistel_pad|codon_pad|dna_seq
          6 fields: len|bits|feistel_pad|codon_pad|dna_seq|aa_confused

        The amino-acid confusion field (if present) is ignored.
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        enc_str = encrypted_dna.strip()
        parts = enc_str.split("|")

        if len(parts) < 5:
            raise ValueError(
                "Invalid encrypted DNA format. Expected at least 5 fields: "
                "<plain_len>|<bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>"
            )

        plain_len_str = parts[0]
        plain_bits_str = parts[1]
        feistel_pad_str = parts[2]
        codon_pad_str = parts[3]
        dna_seq = parts[4]  # ignore parts[5] if present

        try:
            plain_len = int(plain_len_str)
            plain_bits = int(plain_bits_str)
            feistel_pad = int(feistel_pad_str)
            codon_pad = int(codon_pad_str)
        except Exception:
            raise ValueError("Failed to parse metadata fields in ciphertext header.")

        if DEBUG_MODE:
            print("\n=== DECRYPTION PIPELINE ===")
            print("[DEC] Header -> plain_len =", plain_len,
                  ", plain_bits =", plain_bits,
                  ", feistel_pad =", feistel_pad,
                  ", codon_pad =", codon_pad)
            print("[DEC] DNA seq (first 60):",
                  dna_seq[:60] + ("..." if len(dna_seq) > 60 else ""))

        # 1) Codon DNA -> binary (6-bit groups)
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        if DEBUG_MODE:
            print("[DEC] Encrypted binary (6-bit groups, first 64):",
                  encrypted_binary[:64] + ("..." if len(encrypted_binary) > 64 else ""))

        # 2) Remove codon padding bits
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]
            if DEBUG_MODE:
                print("[DEC] After removing codon pad bits, len =", len(encrypted_binary))

        # 3) Expected Feistel cipher length (bytes)
        expected_cipher_bytes = plain_len + feistel_pad
        expected_bits = expected_cipher_bytes * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Ciphertext corruption: expected {expected_bits} bits, "
                f"got {len(encrypted_binary)} bits after codon depadding."
            )

        # 4) Binary -> bytes
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i+8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        if DEBUG_MODE:
            print("[DEC] Encrypted bytes:", encrypted_bytes.hex())

        # 5) Regenerate round keys
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

        if len(decrypted_bytes) != plain_len:
            raise ValueError(
            f"Plaintext length mismatch: expected {plain_len}, got {len(decrypted_bytes)}"
            )

        if DEBUG_MODE:
            print("[DEC] Decrypted bytes:", decrypted_bytes.hex())

        # 8) Bytes -> binary
        decrypted_bin = ''.join(f"{b:08b}" for b in decrypted_bytes)
        decrypted_bin = decrypted_bin[:plain_bits]

        if DEBUG_MODE:
            print("[DEC] Decrypted bits (first 64):",
                  decrypted_bin[:64] + ("..." if len(decrypted_bin) > 64 else ""))

        # 9) Binary -> text
        plain_text = self.dna_encoder.binary_to_text(decrypted_bin)

        if DEBUG_MODE:
            print("[DEC] Final plaintext:", repr(plain_text))

        return plain_text
