# verify_message.py
# This script verifies a digital signature against a message using a public RSA key.

import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_signature(message_file_path, public_key_path, signature_file_path):
    """Verifies a digital signature against a message using a public RSA key.

    Args:
        message_file_path (str): Path to the file containing the original message.
        public_key_path (str): Path to the PEM file containing the public RSA key.
        signature_file_path (str): Path to the file containing the signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Read the message from the file
        with open(message_file_path, "rb") as f:
            message = f.read()

        # Load the public key
        with open(public_key_path, "rb") as f:
            public_key_data = f.read()
            try:
                key = RSA.import_key(public_key_data)
            except ValueError as e:
                print(f"Error importing public key: {e}. Ensure the key is a valid PEM-encoded RSA public key.")
                return False

        # Read the signature from the file
        with open(signature_file_path, "rb") as f:
            signature = f.read()

        # Hash the message
        h = SHA256.new(message)

        # Verify the signature
        verifier = pkcs1_15.new(key)
        try:
            verifier.verify(h, signature)
            print("Signature is valid.")
            return True
        except (ValueError, TypeError):
            print("Signature is invalid.")
            return False

    except FileNotFoundError:
        print(f"Error: One or more files not found. Please check paths:")
        print(f"  Message file: {message_file_path}")
        print(f"  Public key file: {public_key_path}")
        print(f"  Signature file: {signature_file_path}")
        return False
    except Exception as e:
        print(f"An error occurred during verification: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python verify_message.py <message_file> <public_key_file> <signature_file>")
        print("Example: python verify_message.py message.txt public_key.pem signature.sig")
        sys.exit(1)

    message_file = sys.argv[1]
    public_key_file = sys.argv[2]
    signature_file = sys.argv[3]

    verify_signature(message_file, public_key_file, signature_file)

