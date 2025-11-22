import socket
import json

from service.cryptography_service import CryptographyService
from core.quantum_keygen import QuantumResistantKeyGen

HOST = "0.0.0.0"
PORT = 5000
SNIFF_FILE = "sniffed_packet.json"


def handle_client(conn, addr, service: CryptographyService):
    print(f"\n[SERVER] Connection from {addr}")

    # Receive data
    data = conn.recv(8192)
    if not data:
        print("[SERVER] No data received.")
        return

    # Parse JSON
    try:
        message = json.loads(data.decode("utf-8"))
    except Exception as e:
        print("[SERVER] Failed to parse JSON:", e)
        conn.sendall(b"ERROR: Invalid JSON format")
        return

    ciphertext = message.get("ciphertext")
    seed_hex = message.get("seed")

    if ciphertext is None or seed_hex is None:
        conn.sendall(b"ERROR: Missing ciphertext or seed in message")
        return
    # Save sniffed packet for attacker simulation
    try:
        sniffed = {
            "ciphertext": ciphertext,
            "seed": seed_hex,
            "client_addr": str(addr)
        }
        with open(SNIFF_FILE, "w", encoding="utf-8") as f:
            json.dump(sniffed, f, indent=2)
        print(f"[SERVER] Sniffed packet logged to {SNIFF_FILE}")
    except Exception as e:
        print("[SERVER] Could not write sniff log:", e)

    # Convert seed back to bytes
    try:
        seed = bytes.fromhex(seed_hex)
    except Exception as e:
        print("[SERVER] Invalid seed hex:", e)
        conn.sendall(b"ERROR: Invalid seed hex")
        return

    print("\n[SERVER] Received Ciphertext:")
    print(ciphertext)

    print("\n[SERVER] Received Seed (first 64 hex):")
    print(seed_hex[:64], "...")

    # SERVER decrypts using only the seed
    try:
        plaintext = service.decrypt_with_seed(ciphertext, seed)
    except Exception as e:
        print("[SERVER] Decryption failed:", e)
        conn.sendall(f"ERROR: {e}".encode("utf-8"))
        return

    print("\n[SERVER] Decrypted plaintext:")
    print(repr(plaintext))

    # Send plaintext back to client
    conn.sendall(plaintext.encode("utf-8"))


def main():
    print(f"[SERVER] Starting server on {HOST}:{PORT} ...")
    service = CryptographyService()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print("[SERVER] Listening for connections...")

        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn, addr, service)


if __name__ == "__main__":
    main()
