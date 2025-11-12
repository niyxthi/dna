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
        binary_data = self.dna_encoder.text_to_binary(plain_text)
        dna_encoded = self.dna_encoder.binary_to_dna(binary_data)
        dna_binary = self.dna_encoder.dna_to_binary(dna_encoded)
        data_bytes = int(dna_binary, 2).to_bytes((len(dna_binary) + 7) // 8, 'big')

        round_keys = QuantumResistantKeyGen.generate_round_keys(dna_key, self.feistel.rounds, self.feistel.round_key_size)
        encrypted_bytes = self.feistel.encrypt(data_bytes, round_keys)

        encrypted_bin = bin(int.from_bytes(encrypted_bytes, 'big'))[2:].zfill(len(encrypted_bytes)*8)
        encrypted_dna = self.dna_encoder.binary_to_dna(encrypted_bin)
        return encrypted_dna

    def decrypt(self, encrypted_dna: str, dna_key: str) -> str:
        if not self.key_manager.validate_dna_key(dna_key):
            raise ValueError("Invalid DNA key")
        encrypted_binary = self.dna_encoder.dna_to_binary(encrypted_dna)
        encrypted_bytes = int(encrypted_binary, 2).to_bytes((len(encrypted_binary) +7)//8, 'big')

        round_keys = QuantumResistantKeyGen.generate_round_keys(dna_key, self.feistel.rounds, self.feistel.round_key_size)
        decrypted_bytes = self.feistel.decrypt(encrypted_bytes, round_keys)

        decrypted_bin = bin(int.from_bytes(decrypted_bytes, 'big'))[2:].zfill(len(decrypted_bytes)*8)
        decoded_dna = self.dna_encoder.binary_to_dna(decrypted_bin)
        decoded_binary = self.dna_encoder.dna_to_binary(decoded_dna)
        return self.dna_encoder.binary_to_text(decoded_binary)
