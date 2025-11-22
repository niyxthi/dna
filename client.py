import socket
import json

from service.cryptography_service import CryptographyService
from core.quantum_keygen import QuantumResistantKeyGen

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000


def main():
    service = CryptographyService()

    print("=== DNA Cryptography Client (MAC-AA) ===\n")
    dna_key = input("Enter DNA key (A/C/G/T): ").strip().upper()
    plaintext = input("Enter plaintext to encrypt: ")

    # Encrypt locally on client side
    ciphertext = service.encrypt(plaintext, dna_key)

    # Derive seed from DNA key (server never sees DNA key)
    seed = QuantumResistantKeyGen.base_seed_from_dna(dna_key)
    seed_hex = seed.hex()

    print("\n[CLIENT] Ciphertext:")
    print(ciphertext)

    print("\n[CLIENT] Sending seed (first 64 hex):")
    print(seed_hex[:64], "...")

    # Build JSON payload
    data = json.dumps({
        "ciphertext": ciphertext,
        "seed": seed_hex
    }).encode("utf-8")

    # Connect to server
    print(f"\n[CLIENT] Connecting to server at {SERVER_HOST}:{SERVER_PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(data)

        # Receive decrypted plaintext from server
        response = s.recv(8192).decode("utf-8")

    print("\n[CLIENT] Server responded with plaintext:")
    print(repr(response))


if __name__ == "__main__":
    main()
