import random

class KeyManagementService:
    bases = ['A', 'C', 'G', 'T']

    @staticmethod
    def generate_random_dna_key(length: int) -> str:
        return ''.join(random.choice(KeyManagementService.bases) for _ in range(length))

    @staticmethod
    def validate_dna_key(dna_key: str) -> bool:
        return all(b in KeyManagementService.bases for b in dna_key)
