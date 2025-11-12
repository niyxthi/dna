from service.cryptography_service import CryptographyService
from service.key_management import KeyManagementService

def main():
    crypto_service = CryptographyService()
    key_manager = KeyManagementService()
    print("Welcome to DNA Cryptography CLI")
    while True:
        print("\nMenu:")
        print("1. Generate random DNA key")
        print("2. Encrypt text")
        print("3. Decrypt text")
        print("4. Exit")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            length = int(input("Enter desired DNA key length: "))
            dna_key = key_manager.generate_random_dna_key(length)
            print(f"Generated DNA key: {dna_key}")

        elif choice == '2':
            dna_key = input("Enter DNA key: ").strip().upper()
            plain_text = input("Enter plaintext to encrypt: ")
            try:
                encrypted = crypto_service.encrypt(plain_text, dna_key)
                print(f"\nEncrypted DNA sequence:\n{encrypted}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '3':
            dna_key = input("Enter DNA key: ").strip().upper()
            encrypted = input("Enter encrypted DNA sequence to decrypt: ").strip().upper()
            try:
                decrypted = crypto_service.decrypt(encrypted, dna_key)
                print(f"\nDecrypted text:\n{decrypted}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
