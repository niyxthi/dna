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
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        # 1) Text -> binary
        binary_data = self.dna_encoder.text_to_binary(plain_text)

        # 2) Binary -> bytes for Feistel
        data_bytes = int(binary_data, 2).to_bytes((len(binary_data) + 7) // 8, 'big')

        # 3) Generate round keys from DNA key
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 4) Feistel encryption
        encrypted_bytes = self.feistel.encrypt(data_bytes, round_keys)

        # 5) Cipher bytes -> binary
        encrypted_bin = bin(int.from_bytes(encrypted_bytes, 'big'))[2:].zfill(len(encrypted_bytes) * 8)

        # 6) Binary -> codon-based DNA ciphertext
        encrypted_dna = self.dna_encoder.binary_to_codon_dna(encrypted_bin)

        return encrypted_dna


    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")

        # 1) Codon-based DNA -> binary
        encrypted_binary = self.dna_encoder.codon_dna_to_binary(encrypted_dna)

        # 2) Binary -> bytes
        encrypted_bytes = int(encrypted_binary, 2).to_bytes((len(encrypted_binary) + 7) // 8, 'big')

        # 3) Generate same round keys
        round_keys = QuantumResistantKeyGen.generate_round_keys(
            dna_key,
            self.feistel.rounds,
            self.feistel.round_key_size
        )

        # 4) Feistel decryption
        decrypted_bytes = self.feistel.decrypt(encrypted_bytes, round_keys)

        # 5) Decrypted bytes -> binary
        decrypted_bin = bin(int.from_bytes(decrypted_bytes, 'big'))[2:].zfill(len(decrypted_bytes) * 8)

        # 6) Binary -> plaintext
        return self.dna_encoder.binary_to_text(decrypted_bin)
