# sign_message.py
# This script signs a given message file using a private RSA key and saves the signature.

import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_message(message_file_path, private_key_path, signature_file_path):
    """Signs a message file using a private RSA key.

    Args:
        message_file_path (str): Path to the file containing the message to sign.
        private_key_path (str): Path to the PEM file containing the private RSA key.
        signature_file_path (str): Path where the generated signature will be saved.
    """
    try:
        # Read the message from the file
        with open(message_file_path, "rb") as f:
            message = f.read()

        # Load the private key
        with open(private_key_path, "rb") as f:
            private_key_data = f.read()
            try:
                key = RSA.import_key(private_key_data)
            except ValueError as e:
                print(f"Error importing private key: {e}. Ensure the key is a valid PEM-encoded RSA private key.")
                return

        # Hash the message
        h = SHA256.new(message)

        # Sign the hash
        signer = pkcs1_15.new(key)
        signature = signer.sign(h)

        # Save the signature to a file
        with open(signature_file_path, "wb") as f:
            f.write(signature)
        print(f"Message signed successfully. Signature saved to {signature_file_path}")

    except FileNotFoundError:
        print(f"Error: One or more files not found. Please check paths:")
        print(f"  Message file: {message_file_path}")
        print(f"  Private key file: {private_key_path}")
    except Exception as e:
        print(f"An error occurred during signing: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sign_message.py <message_file> <private_key_file> <signature_output_file>")
        print("Example: python sign_message.py message.txt private_key.pem signature.sig")
        sys.exit(1)

    message_file = sys.argv[1]
    private_key_file = sys.argv[2]
    signature_file = sys.argv[3]

    sign_message(message_file, private_key_file, signature_file)

