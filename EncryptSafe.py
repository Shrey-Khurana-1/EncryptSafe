from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import base64
import hashlib

class EncryptSafe:
    def __init__(self):
        self.symmetric_key = None
        self.public_key = None
        self.private_key = None

    def generate_symmetric_key(self):
        self.symmetric_key = Fernet.generate_key()

    def generate_asymmetric_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self, private_key_path='private_key.pem', public_key_path='public_key.pem'):
        with open(private_key_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_keys(self, private_key_path='private_key.pem', public_key_path='public_key.pem'):
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def symmetric_encrypt(self, plaintext):
        if not self.symmetric_key:
            raise ValueError("Symmetric key not generated")
        cipher = Fernet(self.symmetric_key)
        return cipher.encrypt(plaintext)

    def symmetric_decrypt(self, ciphertext):
        if not self.symmetric_key:
            raise ValueError("Symmetric key not generated")
        cipher = Fernet(self.symmetric_key)
        return cipher.decrypt(ciphertext).decode()

    def asymmetric_encrypt(self, plaintext):
        if not self.public_key:
            raise ValueError("Public key not available")
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def asymmetric_decrypt(self, ciphertext):
        if not self.private_key:
            raise ValueError("Private key not available")
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def sign(self, data):
        if not self.private_key:
            raise ValueError("Private key not available")
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature):
        if not self.public_key:
            raise ValueError("Public key not available")
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def password_encrypt_decrypt(self, data=None, password=None):
        if data is None or password is None:
            raise ValueError("Data and password must be provided.")

        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), os.urandom(16), 100000)
        cipher = Fernet(base64.urlsafe_b64encode(kdf))
        if isinstance(data, str):
            data = data.encode()

        ciphertext = cipher.encrypt(data)
        decrypted_text = cipher.decrypt(ciphertext).decode()

        return ciphertext, decrypted_text


if __name__ == "__main__":
    encrypt_safe = EncryptSafe()
    print("|||Welcome to EncryptSafe|||\n")
    data_source = input("Enter 'file' to load data from a file or 'input' to enter data manually: ")
    if((data_source!="file")&(data_source!="input")):
        print("Incorrect Choice!")
        exit()

    while True:
        print("\nEncryptSafe Menu:")
        print("1. Generate Symmetric Key")
        print("2. Generate Asymmetric Keys")
        print("3. Save Keys")
        print("4. Load Keys")
        print("5. Symmetric Encryption and Decryption")
        print("6. Asymmetric Encryption and Decryption")
        print("7. Digital Signature")
        print("8. Password Encryption and Decryption")
        print("9. Quit")

        choice = input("\nEnter your choice: ")

        if choice == '1':
            encrypt_safe.generate_symmetric_key()
            print("Symmetric key generated.")
        
        elif choice == '2':
            encrypt_safe.generate_asymmetric_keys()
            print("Asymmetric keys generated.")
        
        elif choice == '3':
            private_key_path = input("Enter private key file path: ")
            public_key_path = input("Enter public key file path: ")
            encrypt_safe.save_keys(private_key_path, public_key_path)
            print("Keys saved successfully.")
        
        elif choice == '4':
            private_key_path = input("Enter private key file path: ")
            public_key_path = input("Enter public key file path: ")
            encrypt_safe.load_keys(private_key_path, public_key_path)
            print("Keys loaded successfully.")
        
        elif choice == '5':
            if data_source.lower() == 'file':
                file_path = input("Enter the path to the data file: ")
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
            elif data_source.lower() == 'input':
                plaintext = input("Enter plaintext: ").encode()
            else:
                print("Invalid choice. Please enter 'file' or 'input'.")
                continue
            ciphertext = encrypt_safe.symmetric_encrypt(plaintext)
            print("Ciphertext:", ciphertext)
            print("Decrypted Text:", encrypt_safe.symmetric_decrypt(ciphertext))
        
        elif choice == '6':
            if data_source.lower() == 'file':
                file_path = input("Enter the path to the data file: ")
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
            elif data_source.lower() == 'input':
                plaintext = input("Enter plaintext: ").encode()
            else:
                print("Invalid choice. Please enter 'file' or 'input'.")
                continue
            ciphertext = encrypt_safe.asymmetric_encrypt(plaintext)
            print("Ciphertext:", ciphertext)
            print("Decrypted Text:", encrypt_safe.asymmetric_decrypt(ciphertext))
        
        elif choice == '7':
            if data_source.lower() == 'file':
                file_path = input("Enter the path to the data file: ")
                with open(file_path, 'rb') as f:
                    data = f.read().strip()
                print("Data to sign:", data.decode())
                data_verify = data
            elif data_source.lower() == 'input':
                data = input("Enter data to sign: ").strip().encode()
                data_verify = input("Enter data to verify: ").strip().encode()
            else:
                print("Invalid choice. Please enter 'file' or 'input'.")
                continue
            signature = encrypt_safe.sign(data)
            print("Signature:", base64.b64encode(signature).decode())
            signature_verify = base64.b64decode(input("Enter signature to verify: "))
            print("Data to verify:", data_verify.decode())
            verified = encrypt_safe.verify_signature(data_verify, signature_verify)
            print("Verified:", verified)
        
        elif choice == '8':
            if data_source.lower() == 'file':
                file_path = input("Enter the path to the data file: ")
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
            elif data_source.lower() == 'input':
                plaintext = input("Enter plaintext: ").encode()
            else:
                print("Invalid choice. Please enter 'file' or 'input'.")
                continue
            password = input("Enter password: ")
            ciphertext, decrypted_text = encrypt_safe.password_encrypt_decrypt(data=plaintext, password=password)
            print("Ciphertext:", ciphertext)
            print("Decrypted Text:", decrypted_text)
        
        elif choice == '9':
            print("Exiting EncryptSafe. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")
