from core.dna_encoder import DNAEncoder
from core.feistel_network import FeistelNetwork
from core.quantum_keygen import QuantumResistantKeyGen
from service.key_management import KeyManagementService
import hashlib

DEBUG_MODE = True


class CryptographyService:
    """DNA–Quantum cryptography service with MAC-only amino-acid layer.

    Ciphertext format (6 fields, '|' separated):
        <plain_len_bytes>|<plain_bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>|<mac_aa>

    - plain_len_bytes : length of original plaintext in bytes
    - plain_bit_len   : exact number of bits used for plaintext (UTF-8)
    - feistel_pad     : 0 or 1 (if a padding byte was added to make length even)
    - codon_pad       : number of bits padded to reach multiple of 6 for codon mapping
    - dna_seq         : codon-based DNA ciphertext
    - mac_aa          : amino-acid MAC computed from (seed, dna_seq)
    """

    def __init__(self):
        self.dna_encoder = DNAEncoder()
        self.key_manager = KeyManagementService()
        self.feistel = FeistelNetwork()

    # ---------------------------------------------------------------------
    # Amino-acid MAC helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _bytes_to_amino_mac(mac_bytes: bytes, length: int = 24) -> str:
        """Convert MAC bytes into a protein-like amino-acid string.

        We use a 21-symbol alphabet: 20 amino acids + stop (*).
        We read the MAC bits in 5-bit chunks (0..31) and map each
        value modulo 21 into that alphabet.
        """
        aa_alphabet = "ACDEFGHIKLMNPQRSTVWY*"  # 20 amino acids + stop
        bits = "".join(f"{b:08b}" for b in mac_bytes)

        aa_list = []
        idx = 0
        while len(aa_list) < length and idx + 5 <= len(bits):
            chunk = bits[idx:idx + 5]
            val = int(chunk, 2)
            aa = aa_alphabet[val % len(aa_alphabet)]
            aa_list.append(aa)
            idx += 5

        return "".join(aa_list)

    @staticmethod
    def _compute_aa_mac(seed: bytes, dna_seq: str) -> str:
        """Compute an amino-acid MAC over the DNA ciphertext.

        MAC bytes = SHA3-256( seed || "|DNA|" || dna_seq )
        Then map those MAC bytes to an amino-acid string.

        This binds the DNA ciphertext to the seed (derived from
        the client's DNA key). Any change in dna_seq or seed will
        change the MAC-AA.
        """
        h = hashlib.sha3_256()
        h.update(seed)
        h.update(b"|DNA|")
        h.update(dna_seq.encode("ascii"))
        mac_bytes = h.digest()
        return CryptographyService._bytes_to_amino_mac(mac_bytes, length=24)

    # ---------------------------------------------------------------------
    # Encryption
    # ---------------------------------------------------------------------

    def encrypt(self, plain_text: str, dna_key: str) -> str:
        """Encrypt plaintext and produce DNA ciphertext + MAC-AA.

        Returns a string of the form:
            "plain_len|plain_bit_len|feistel_pad|codon_pad|dna_seq|mac_aa"
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        # 1) Text -> binary (via DNAEncoder to keep symmetry)
        binary_data = self.dna_encoder.text_to_binary(plain_text)
        plain_bit_len = len(binary_data)

        # 2) Binary -> bytes
        plain_bytes = bytes(
            int(binary_data[i:i + 8], 2)
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

        # 4) Generate Feistel round keys and seed from DNA key
        seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)
        round_keys = QuantumResistantKeyGen.generate_round_keys_from_seed(
            seed,
            self.feistel.rounds,
            self.feistel.round_key_size,
        )

        # 5) Feistel encrypt
        encrypted_bytes = self.feistel.encrypt(feistel_input, round_keys)

        if DEBUG_MODE:
            print("[ENC] Encrypted bytes:", encrypted_bytes.hex())

        # 6) Bytes -> binary string
        encrypted_bin = "".join(f"{b:08b}" for b in encrypted_bytes)

        # 7) Binary -> codon DNA
        dna_seq, codon_pad = self.dna_encoder.binary_to_codon_dna(encrypted_bin)

        if DEBUG_MODE:
            print("[ENC] Cipher bits (first 64):",
                  encrypted_bin[:64] + ("..." if len(encrypted_bin) > 64 else ""))
            print("[ENC] Codon DNA (first 60):",
                  dna_seq[:60] + ("..." if len(dna_seq) > 60 else ""))
            print("[ENC] Codon pad bits:", codon_pad)

        # 8) Amino-acid MAC based on seed + DNA cipher
        mac_aa = self._compute_aa_mac(seed, dna_seq)

        if DEBUG_MODE:
            print("[ENC] MAC-AA:", mac_aa)

        # Final ciphertext string (6 fields)
        cipher_str = f"{plain_len}|{plain_bit_len}|{feistel_pad}|{codon_pad}|{dna_seq}|{mac_aa}"

        if DEBUG_MODE:
            print("[ENC] Final ciphertext string:", cipher_str)

        return cipher_str

    # ---------------------------------------------------------------------
    # Decryption with DNA key (local mode)
    # ---------------------------------------------------------------------

    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        """Decrypt using the DNA key (single-machine mode).

        Validates MAC-AA before attempting Feistel decryption.
        """
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        enc_str = encrypted_dna.strip()
        parts = enc_str.split("|")

        if len(parts) < 6:
            raise ValueError(
                "Invalid encrypted DNA format. Expected 6 fields: "
                "<plain_len>|<bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>|<mac_aa>"
            )

        plain_len_str, plain_bits_str, feistel_pad_str, codon_pad_str, dna_seq, mac_aa = parts[:6]

        try:
            plain_len = int(plain_len_str)
            plain_bits = int(plain_bits_str)
            feistel_pad = int(feistel_pad_str)
            codon_pad = int(codon_pad_str)
        except Exception:
            raise ValueError("Failed to parse metadata fields in ciphertext header.")

        if DEBUG_MODE:
            print("\n=== DECRYPTION PIPELINE (LOCAL DNA KEY) ===")
            print("[DEC] Header -> plain_len =", plain_len,
                  ", plain_bits =", plain_bits,
                  ", feistel_pad =", feistel_pad,
                  ", codon_pad =", codon_pad)
            print("[DEC] DNA seq (first 60):",
                  dna_seq[:60] + ("..." if len(dna_seq) > 60 else ""))
            print("[DEC] MAC-AA:", mac_aa)

        # 1) Recompute seed from DNA key and verify MAC-AA
        seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)
        mac_expected = self._compute_aa_mac(seed, dna_seq)
        if DEBUG_MODE:
            print("[DEC] Expected MAC-AA:", mac_expected)
        if mac_expected != mac_aa:
            raise ValueError("MAC verification failed: message may be tampered.")

        # 2) Codon DNA -> binary (6-bit groups)
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        if DEBUG_MODE:
            print("[DEC] Encrypted binary (6-bit groups, first 64):",
                  encrypted_binary[:64] + ("..." if len(encrypted_binary) > 64 else ""))

        # 3) Remove codon padding bits
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]
            if DEBUG_MODE:
                print("[DEC] After removing codon pad bits, len =", len(encrypted_binary))

        # 4) Expected Feistel cipher length (bytes)
        expected_cipher_bytes = plain_len + feistel_pad
        expected_bits = expected_cipher_bytes * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Ciphertext corruption: expected {expected_bits} bits, "
                f"got {len(encrypted_binary)} bits after codon depadding."
            )

        # 5) Binary -> bytes
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i + 8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        if DEBUG_MODE:
            print("[DEC] Encrypted bytes:", encrypted_bytes.hex())

        # 6) Regenerate round keys
        round_keys = QuantumResistantKeyGen.generate_round_keys_from_seed(
            seed,
            self.feistel.rounds,
            self.feistel.round_key_size,
        )

        # 7) Feistel decrypt
        decrypted_bytes_full = self.feistel.decrypt(encrypted_bytes, round_keys)

        # 8) Remove Feistel padding byte if present
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

        # 9) Bytes -> binary
        decrypted_bin = "".join(f"{b:08b}" for b in decrypted_bytes)
        decrypted_bin = decrypted_bin[:plain_bits]

        if DEBUG_MODE:
            print("[DEC] Decrypted bits (first 64):",
                  decrypted_bin[:64] + ("..." if len(decrypted_bin) > 64 else ""))

        # 10) Binary -> text
        plain_text = self.dna_encoder.binary_to_text(decrypted_bin)

        if DEBUG_MODE:
            print("[DEC] Final plaintext:", repr(plain_text))

        return plain_text

    # ---------------------------------------------------------------------
    # Decryption with seed (server-side mode)
    # ---------------------------------------------------------------------

    def decrypt_with_seed(self, encrypted_dna: str, seed: bytes) -> str:
        """Decrypt using only the quantum-resistant seed (server side).

        The server does NOT know the DNA key; it only receives the seed
        and the ciphertext from the client.
        """
        enc_str = encrypted_dna.strip()
        parts = enc_str.split("|")

        if len(parts) < 6:
            raise ValueError(
                "Invalid encrypted DNA format. Expected 6 fields: "
                "<plain_len>|<bit_len>|<feistel_pad>|<codon_pad>|<dna_seq>|<mac_aa>"
            )

        plain_len_str, plain_bits_str, feistel_pad_str, codon_pad_str, dna_seq, mac_aa = parts[:6]

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
            print("[DEC] MAC-AA:", mac_aa)

        # 1) Verify MAC-AA using seed
        mac_expected = self._compute_aa_mac(seed, dna_seq)
        if DEBUG_MODE:
            print("[DEC] Expected MAC-AA:", mac_expected)
        if mac_expected != mac_aa:
            raise ValueError("MAC verification failed: message may be tampered.")
        if DEBUG_MODE:
            print("[AUTH] MAC-AA verified successfully. Message is authentic.")

        # 2) Codon DNA -> binary (6-bit groups)
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(dna_seq)

        if DEBUG_MODE:
            print("[DEC] Encrypted binary (6-bit groups, first 64):",
                  encrypted_binary[:64] + ("..." if len(encrypted_binary) > 64 else ""))

        # 3) Remove codon padding bits
        if codon_pad > 0:
            encrypted_binary = encrypted_binary[:-codon_pad]
            if DEBUG_MODE:
                print("[DEC] After removing codon pad bits, len =", len(encrypted_binary))

        # 4) Expected Feistel cipher length (bytes)
        expected_cipher_bytes = plain_len + feistel_pad
        expected_bits = expected_cipher_bytes * 8

        if len(encrypted_binary) != expected_bits:
            raise ValueError(
                f"Ciphertext corruption: expected {expected_bits} bits, "
                f"got {len(encrypted_binary)} bits after codon depadding."
            )

        # 5) Binary -> bytes
        encrypted_bytes = bytes(
            int(encrypted_binary[i:i + 8], 2)
            for i in range(0, len(encrypted_binary), 8)
        )

        if DEBUG_MODE:
            print("[DEC] Encrypted bytes:", encrypted_bytes.hex())

        # 6) Regenerate Feistel round keys FROM SEED
        round_keys = QuantumResistantKeyGen.generate_round_keys_from_seed(
            seed,
            self.feistel.rounds,
            self.feistel.round_key_size,
        )

        # 7) Feistel decrypt
        decrypted_bytes_full = self.feistel.decrypt(encrypted_bytes, round_keys)

        # 8) Remove Feistel padding byte if present
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

        # 9) Bytes -> binary
        decrypted_bin = "".join(f"{b:08b}" for b in decrypted_bytes)
        decrypted_bin = decrypted_bin[:plain_bits]

        if DEBUG_MODE:
            print("[DEC] Decrypted bits (first 64):",
                  decrypted_bin[:64] + ("..." if len(decrypted_bin) > 64 else ""))

        # 10) Binary -> text
        plain_text = self.dna_encoder.binary_to_text(decrypted_bin)

        if DEBUG_MODE:
            print("[DEC] Final plaintext:", repr(plain_text))

        return plain_text
