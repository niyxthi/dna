from core.dna_encoder import DNAEncoder
from core.feistel_network import FeistelNetwork
from core.quantum_keygen import QuantumResistantKeyGen
from service.key_management import KeyManagementService


class CryptographyService:
    def __init__(self):
        self.dna_encoder = DNAEncoder()
        self.key_manager = KeyManagementService()
        self.feistel = FeistelNetwork()

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

        # Final ciphertext format (5 fields):
        # plain_len | plain_bit_len | feistel_pad | codon_pad | dna_seq
        return f"{plain_len}|{plain_bit_len}|{feistel_pad}|{codon_pad}|{dna_seq}"

    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        """
        Decrypts ciphertext in format:
            <plain_len_bytes>|<plain_bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        encrypted_dna = encrypted_dna.strip()

        # Parse header
        try:
            plain_len_str, plain_bits_str, feistel_pad_str, codon_pad_str, dna_seq = encrypted_dna.split("|", 4)
            plain_len = int(plain_len_str)
            plain_bit_len = int(plain_bits_str)
            feistel_pad = int(feistel_pad_str)
            codon_pad = int(codon_pad_str)
        except Exception:
            raise ValueError(
                "Invalid encrypted DNA format. Expected "
                "'<plain_len>|<plain_bits>|<feistel_pad>|<codon_pad>|<dna_seq>'"
            )

        # 1) Codon DNA -> binary (6 bits per codon)
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        # 2) Remove codon-level padding bits (added at encryption)
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]

        # 3) Compute expected Feistel ciphertext length in bytes
        expected_feistel_len = plain_len + feistel_pad
        expected_bits = expected_feistel_len * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Corrupted ciphertext: expected {expected_bits} bits after depadding, "
                f"got {len(encrypted_binary)}"
            )

        # 4) Binary -> bytes by grouping 8 bits
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i+8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        if len(encrypted_bytes) != expected_feistel_len:
            raise ValueError(
                f"Length mismatch before Feistel: expected {expected_feistel_len} bytes, "
                f"got {len(encrypted_bytes)}"
            )

        # 5) Regenerate Feistel keys
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 6) Feistel decryption
        decrypted_bytes_full = self.feistel.decrypt(encrypted_bytes, round_keys)

        # 7) Remove Feistel padding byte if it was added
        if feistel_pad == 1:
            decrypted_bytes = decrypted_bytes_full[:-1]
        else:
            decrypted_bytes = decrypted_bytes_full

        if len(decrypted_bytes) != plain_len:
            raise ValueError(
                f"Plaintext length mismatch after Feistel: expected {plain_len} bytes, "
                f"got {len(decrypted_bytes)}"
            )

        # 8) Decrypted bytes -> binary string
        decrypted_bin = ''.join(f"{b:08b}" for b in decrypted_bytes)

        # 9) Truncate to original bit length (in case of future multi-byte chars)
        decrypted_bin = decrypted_bin[:plain_bit_len]

        # 10) Binary -> text (UTF-8)
        return self.dna_encoder.binary_to_text(decrypted_bin)
