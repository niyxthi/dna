import socket
import json

from service.cryptography_service import CryptographyService
from core.quantum_keygen import QuantumResistantKeyGen  # for type clarity, not strictly needed

HOST = "0.0.0.0"
PORT = 5000


def handle_client(conn, addr, service: CryptographyService):
    print(f"\n[SERVER] Connection from {addr}")

    data = conn.recv(8192)
    if not data:
        print("[SERVER] No data received.")
        return

    try:
        message = json.loads(data.decode("utf-8"))
    except Exception as e:
        print("[SERVER] Failed to parse JSON:", e)
        conn.sendall(b"ERROR: Invalid JSON")
        return

    ciphertext = message.get("ciphertext")
    seed_hex = message.get("seed")

    if ciphertext is None or seed_hex is None:
        print("[SERVER] Missing fields in message.")
        conn.sendall(b"ERROR: Missing ciphertext or seed")
        return

    try:
        seed = bytes.fromhex(seed_hex)
    except Exception as e:
        print("[SERVER] Failed to parse seed hex:", e)
        conn.sendall(b"ERROR: Invalid seed format")
        return

    print("\n[SERVER] Received ciphertext:")
    print(ciphertext)
    print("\n[SERVER] Received seed (first 64 hex):", seed_hex[:64], "...")

    # Decrypt using seed (SERVER DOES NOT KNOW DNA KEY)
    try:
        plaintext = service.decrypt_with_seed(ciphertext, seed)
    except Exception as e:
        print("[SERVER] Decryption error:", e)
        conn.sendall(f"ERROR: Decryption failed: {e}".encode("utf-8"))
        return

    print("\n[SERVER] Decrypted plaintext:")
    print(repr(plaintext))

    # Send the plaintext back to the client
    conn.sendall(plaintext.encode("utf-8"))


def main():
    service = CryptographyService()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT} ...")

        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn, addr, service)


if __name__ == "__main__":
    main()
