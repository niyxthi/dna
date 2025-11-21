import socket
import json

from service.cryptography_service import CryptographyService
from core.quantum_keygen import QuantumResistantKeyGen

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000


def main():
    service = CryptographyService()

    dna_key = input("Enter DNA key (A/C/G/T): ").strip()
    plaintext = input("Enter plaintext to encrypt: ")

    # 1) Encrypt on client side
    ciphertext = service.encrypt(plaintext, dna_key)

    # 2) Derive quantum-resistant seed (server will only see this, not DNA)
    seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)
    seed_hex = seed.hex()

    print("\n[CLIENT] Ciphertext to send:")
    print(ciphertext)
    print("\n[CLIENT] Seed (hex, first 64):", seed_hex[:64], "...")

    # 3) Prepare JSON payload
    message = {
        "ciphertext": ciphertext,
        "seed": seed_hex
    }
    data = json.dumps(message).encode("utf-8")

    # 4) Send to server and receive response
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"\n[CLIENT] Connecting to server {SERVER_HOST}:{SERVER_PORT} ...")
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(data)

        # We assume response fits under 8 KB for demo
        response = s.recv(8192).decode("utf-8")

    print("\n[CLIENT] Server responded with decrypted plaintext:")
    print(repr(response))


if __name__ == "__main__":
    main()
