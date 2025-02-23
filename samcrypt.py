import os
import secrets
import getpass
import pyfiglet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_keys(key_size=2048):
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('privatekey.pem', 'wb') as f:
            f.write(private_pem)
        with open('pubkey.pem', 'wb') as f:
            f.write(public_pem)

        print("Keys generated successfully.")
        return private_key, public_key
    except Exception as e:
        print(f"Error generating keys: {e}")
        return None, None

def load_keys():
    try:
        with open('privatekey.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open('pubkey.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key
    except FileNotFoundError:
        print("No existing keys found. Please generate keys first.")
        return None, None
    except Exception as e:
        print(f"Error loading keys: {e}")
        return None, None

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives a key from given passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def aes_encrypt(file_path: str, passphrase: str, output_file: str):
    try:
        salt = os.urandom(16)
        iv = secrets.token_bytes(16)
        
        # Derive key from passphrase
        key = derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)

        print("File encrypted successfully using AES!")
        return True
        
    except Exception as e:
        print(f"AES Encryption Error: {e}")
        return False

def aes_decrypt(file_path: str, passphrase: str, output_file: str):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        
        try:
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print("File decrypted successfully using AES!")
            return True
        
        except ValueError:
            print("Invalid padding bytes - possible incorrect passphrase")
            return False
        
    except Exception as e:
        print(f"AES Decryption Error: {e}")
        return False

def rsa_encrypt_file(file_path: str, public_key, output_file: str):
    try:
        # Generate random session key for AES
        session_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        # Encrypt data with AES
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Encrypt session key with RSA
        encrypted_session_key = public_key.encrypt(
            session_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write output file structure: IV + Encrypted Session Key + Ciphertext
        with open(output_file, 'wb') as f:
            f.write(iv)
            f.write(encrypted_session_key)
            f.write(ciphertext)

        print("File encrypted successfully using RSA!")
        return True

    except Exception as e:
        print(f"RSA Encryption Error: {e}")
        return False 

def rsa_decrypt_file(file_path: str, private_key, output_file: str):
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            encrypted_session_key_length = private_key.key_size // 8 
            encrypted_session_key = f.read(encrypted_session_key_length)
            ciphertext = f.read()

        # Decrypt session key 
        session_key = private_key.decrypt(
            encrypted_session_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None 
            )
        )

        # Decrypt data 
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        
        try:
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print("File decrypted successfully using RSA!")
            return True 
          
        except ValueError:
            print("Invalid padding - possible corrupted data")
            return False 

    except Exception as e:
        print(f"RSA Decryption Error: {e}")
        return False 

def display_banner():
    """Display ASCII art banner."""
    ascii_banner = pyfiglet.figlet_format("SamCrypt")
    print(ascii_banner)
    print("                      Created By Mohit Sambharwal\n")

def main():
    display_banner()
    while True:
        print("\nSelect Encryption Method:")
        print("1. Symmetric Encryption (AES)")
        print("2. Asymmetric Encryption (RSA)")
        print("3. Exit")
        
        method_choice = input("Enter your choice (1/2/3): ").strip()

        if method_choice == "1":
            action_choice = input("Do you want to (e)ncrypt or (d)ecrypt a file? ").lower()
            
            if action_choice == 'e':
                file_path = input("Enter file path to encrypt: ")
                output_file = input("Enter output file path: ")
                passphrase = getpass.getpass("Enter encryption passphrase: ")
                aes_encrypt(file_path, passphrase, output_file)

            elif action_choice == 'd':
                file_path = input("Enter file path to decrypt: ")
                output_file = input("Enter output file path: ")
                passphrase = getpass.getpass("Enter decryption passphrase: ")
                aes_decrypt(file_path, passphrase, output_file)

            else:
                print("Invalid choice!")

        elif method_choice == "2":
            while True:
                print("\nRSA Operations:")
                print("1. Generate Keys")
                print("2. Encrypt File")
                print("3. Decrypt File")
                print("4. Back to Main Menu")
                
                rsa_choice = input("Enter your choice (1-4): ").strip()

                if rsa_choice == "1":
                    generate_keys()
                
                elif rsa_choice == "2":
                    file_path = input("Enter file path to encrypt: ")
                    _, public_key = load_keys()
                    if public_key:
                        output_file = input("Enter output file path: ")
                        rsa_encrypt_file(file_path, public_key, output_file)
                
                elif rsa_choice == "3":
                    file_path = input("Enter file path to decrypt: ")
                    private_key, _ = load_keys()
                    if private_key:
                        output_file = input("Enter output file path: ")
                        rsa_decrypt_file(file_path, private_key, output_file)
                
                elif rsa_choice == "4":
                    break 
                
                else:
                    print("Invalid choice!")

        elif method_choice == "3":
            print("Exiting...")
            break 

if __name__ == "__main__":
    main()
