# crypto_tool.py
# This script provides a command-line interface for various cryptographic operations.

import argparse
import os
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC

# --- AES Functions ---

def aes_encrypt(key, input_file, output_file):
    """Encrypts a file using AES-256 GCM.

    Args:
        key (bytes): The 256-bit (32 bytes) secret key.
        input_file (str): Path to the file to encrypt.
        output_file (str): Path to save the encrypted file.
    """
    try:
        with open(input_file, "rb") as f_in:
            plaintext = f_in.read()

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(output_file, "wb") as f_out:
            [f_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
        print(f"File 	'{input_file}' encrypted successfully to '{output_file}'.")
        print(f"Nonce, Tag, and Ciphertext saved.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except Exception as e:
        print(f"An error occurred during AES encryption: {e}")

def aes_decrypt(key, input_file, output_file):
    """Decrypts a file using AES-256 GCM.

    Args:
        key (bytes): The 256-bit (32 bytes) secret key.
        input_file (str): Path to the encrypted file.
        output_file (str): Path to save the decrypted file.
    """
    try:
        with open(input_file, "rb") as f_in:
            nonce, tag, ciphertext = [f_in.read(x) for x in (16, 16, -1)] # AES GCM nonce is 16 bytes, tag is 16 bytes

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, "wb") as f_out:
            f_out.write(plaintext)
        print(f"File '{input_file}' decrypted successfully to '{output_file}'.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except (ValueError, KeyError) as e:
        print(f"Decryption failed. Key incorrect or ciphertext corrupted: {e}")
    except Exception as e:
        print(f"An error occurred during AES decryption: {e}")

# --- RSA Functions (Adapted from Digital Signatures project for encryption/decryption) ---

def generate_rsa_keys_for_toolkit(bits=2048, private_key_file="rsa_private.pem", public_key_file="rsa_public.pem"):
    """Generates an RSA key pair for the toolkit and saves them to PEM files."""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(private_key_file, "wb") as f:
        f.write(private_key)
    print(f"RSA private key saved to {private_key_file}")
    with open(public_key_file, "wb") as f:
        f.write(public_key)
    print(f"RSA public key saved to {public_key_file}")

def rsa_encrypt(public_key_path, input_file, output_file):
    """Encrypts a file using an RSA public key (PKCS#1 OAEP).

    Args:
        public_key_path (str): Path to the PEM file containing the RSA public key.
        input_file (str): Path to the file to encrypt (should be small).
        output_file (str): Path to save the encrypted file.
    """
    try:
        with open(input_file, "rb") as f_in:
            plaintext = f_in.read()

        with open(public_key_path, "rb") as f_key:
            recipient_key = RSA.import_key(f_key.read())

        key_size_bytes = recipient_key.size_in_bytes()
        max_data_size = key_size_bytes - 2 * SHA256.digest_size - 2
        if len(plaintext) > max_data_size:
            print(f"Error: Plaintext size ({len(plaintext)} bytes) is too large for RSA encryption with this key.")
            print(f"Maximum data size for this key is {max_data_size} bytes.")
            print("RSA is typically used to encrypt small data, like symmetric keys.")
            return

        cipher_rsa = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
        ciphertext = cipher_rsa.encrypt(plaintext)

        with open(output_file, "wb") as f_out:
            f_out.write(ciphertext)
        print(f"File '{input_file}' encrypted successfully to '{output_file}' using RSA.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' or public key '{public_key_path}' not found.")
    except Exception as e:
        print(f"An error occurred during RSA encryption: {e}")

def rsa_decrypt(private_key_path, input_file, output_file):
    """Decrypts a file using an RSA private key (PKCS#1 OAEP).

    Args:
        private_key_path (str): Path to the PEM file containing the RSA private key.
        input_file (str): Path to the RSA encrypted file.
        output_file (str): Path to save the decrypted file.
    """
    try:
        with open(input_file, "rb") as f_in:
            ciphertext = f_in.read()

        with open(private_key_path, "rb") as f_key:
            private_key = RSA.import_key(f_key.read())

        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        plaintext = cipher_rsa.decrypt(ciphertext)

        with open(output_file, "wb") as f_out:
            f_out.write(plaintext)
        print(f"File '{input_file}' decrypted successfully to '{output_file}' using RSA.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' or private key '{private_key_path}' not found.")
    except (ValueError, TypeError) as e:
        print(f"RSA Decryption failed. Key incorrect or ciphertext corrupted: {e}")
    except Exception as e:
        print(f"An error occurred during RSA decryption: {e}")

# --- SHA-256 Hashing Function ---

def sha256_hash_file(input_file):
    """Computes the SHA-256 hash of a file.

    Args:
        input_file (str): Path to the file to hash.

    Returns:
        str: The hex-encoded SHA-256 hash, or None if an error occurs.
    """
    try:
        hasher = SHA256.new()
        with open(input_file, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        hex_digest = hasher.hexdigest()
        print(f"SHA-256 Hash of '{input_file}': {hex_digest}")
        return hex_digest
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found for hashing.")
        return None
    except Exception as e:
        print(f"An error occurred during SHA-256 hashing: {e}")
        return None

# --- HMAC-SHA256 Function ---

def generate_hmac_sha256(key, input_file, output_file=None):
    """Generates an HMAC-SHA256 tag for a file.

    Args:
        key (bytes): The secret key for HMAC.
        input_file (str): Path to the file to authenticate.
        output_file (str, optional): Path to save the HMAC tag. If None, prints to console.

    Returns:
        str: The hex-encoded HMAC-SHA256 tag, or None if an error occurs.
    """
    try:
        hmac_hasher = HMAC.new(key, digestmod=SHA256)
        with open(input_file, "rb") as f:
            while chunk := f.read(8192):
                hmac_hasher.update(chunk)
        hex_tag = hmac_hasher.hexdigest()

        if output_file:
            with open(output_file, "w") as f_out:
                f_out.write(hex_tag)
            print(f"HMAC-SHA256 for '{input_file}' saved to '{output_file}': {hex_tag}")
        else:
            print(f"HMAC-SHA256 for '{input_file}': {hex_tag}")
        return hex_tag

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found for HMAC generation.")
        return None
    except Exception as e:
        print(f"An error occurred during HMAC-SHA256 generation: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cryptography Toolkit for AES, RSA, SHA-256, and HMAC operations.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # AES Parser
    aes_parser = subparsers.add_parser("aes", help="AES encryption/decryption operations.")
    aes_subparsers = aes_parser.add_subparsers(dest="aes_op", help="AES operation", required=True)

    aes_genkey_parser = aes_subparsers.add_parser("genkey", help="Generate a new 32-byte AES key.")
    aes_genkey_parser.add_argument("--outfile", required=True, metavar="KEY_FILE_PATH", help="File path to save the new 32-byte AES key.")

    aes_encrypt_parser = aes_subparsers.add_parser("encrypt", help="Encrypt a file using AES-GCM.")
    aes_encrypt_parser.add_argument("--key", required=True, help="Path to the file containing the 32-byte AES key, or the key itself as a hex string (64 chars).")
    aes_encrypt_parser.add_argument("--infile", required=True, help="Input file to encrypt.")
    aes_encrypt_parser.add_argument("--outfile", required=True, help="Output file for encrypted data.")

    aes_decrypt_parser = aes_subparsers.add_parser("decrypt", help="Decrypt a file using AES-GCM.")
    aes_decrypt_parser.add_argument("--key", required=True, help="Path to the file containing the 32-byte AES key, or the key itself as a hex string (64 chars).")
    aes_decrypt_parser.add_argument("--infile", required=True, help="Input file to decrypt.")
    aes_decrypt_parser.add_argument("--outfile", required=True, help="Output file for decrypted data.")

    # RSA Parser
    rsa_parser = subparsers.add_parser("rsa", help="RSA encryption/decryption operations.")
    rsa_subparsers = rsa_parser.add_subparsers(dest="rsa_op", help="RSA operation", required=True)

    rsa_genkeys_parser = rsa_subparsers.add_parser("genkeys", help="Generate RSA public/private key pair.")
    rsa_genkeys_parser.add_argument("--privfile", default="rsa_private.pem", help="Filename for private key (default: rsa_private.pem).")
    rsa_genkeys_parser.add_argument("--pubfile", default="rsa_public.pem", help="Filename for public key (default: rsa_public.pem).")
    rsa_genkeys_parser.add_argument("--bits", type=int, default=2048, help="Key size in bits (default: 2048).")

    rsa_encrypt_parser = rsa_subparsers.add_parser("encrypt", help="Encrypt a file using RSA public key.")
    rsa_encrypt_parser.add_argument("--pubkey", required=True, help="Path to RSA public key file (.pem).")
    rsa_encrypt_parser.add_argument("--infile", required=True, help="Input file to encrypt (small data).")
    rsa_encrypt_parser.add_argument("--outfile", required=True, help="Output file for encrypted data.")

    rsa_decrypt_parser = rsa_subparsers.add_parser("decrypt", help="Decrypt a file using RSA private key.")
    rsa_decrypt_parser.add_argument("--privkey", required=True, help="Path to RSA private key file (.pem).")
    rsa_decrypt_parser.add_argument("--infile", required=True, help="Input file to decrypt.")
    rsa_decrypt_parser.add_argument("--outfile", required=True, help="Output file for decrypted data.")

    # SHA256 Parser
    sha256_parser = subparsers.add_parser("sha256", help="SHA-256 hashing operations.")
    # Making 'hash' the operation, not a flag. This makes it a sub-command implicitly.
    sha256_parser.add_argument("infile", help="Input file to hash.") # No separate subparser, direct arg

    # HMAC Parser
    hmac_parser = subparsers.add_parser("hmac", help="HMAC-SHA256 generation.")
    hmac_subparsers = hmac_parser.add_subparsers(dest="hmac_op", help="HMAC operation", required=True)

    hmac_genkey_parser = hmac_subparsers.add_parser("genkey", help="Generate a new random key for HMAC.")
    hmac_genkey_parser.add_argument("--outfile", required=True, metavar="KEY_FILE_PATH", help="File path to save the new HMAC key.")

    hmac_generate_parser = hmac_subparsers.add_parser("generate", help="Generate HMAC-SHA256 for a file.")
    hmac_generate_parser.add_argument("--key", required=True, help="Path to the file containing the HMAC secret key, or the key itself as a string/hex string.")
    hmac_generate_parser.add_argument("--infile", required=True, help="Input file to authenticate.")
    hmac_generate_parser.add_argument("--outfile", help="Optional: Output file to save the HMAC tag.")

    args = parser.parse_args()

    def get_key_from_arg(key_arg, is_aes_key=False):
        if os.path.exists(key_arg):
            with open(key_arg, "rb") as kf:
                key_bytes = kf.read()
        else:
            try:
                key_bytes = bytes.fromhex(key_arg)
            except ValueError:
                # For HMAC, allow non-hex string keys as well, encode to bytes
                if not is_aes_key:
                    key_bytes = key_arg.encode('utf-8')
                else:
                    print("Error: AES key must be a valid file path or a hex string.")
                    sys.exit(1)
        
        if is_aes_key and len(key_bytes) not in [16, 24, 32]:
            print(f"Error: AES key must be 16, 24, or 32 bytes long. Provided key is {len(key_bytes)} bytes.")
            sys.exit(1)
        return key_bytes

    if args.command == "aes":
        if args.aes_op == "genkey":
            new_key = get_random_bytes(32) # Generate a 256-bit (32 bytes) key
            with open(args.outfile, "wb") as kf:
                kf.write(new_key)
            print(f"New 32-byte AES key generated and saved to '{args.outfile}'. Hex: {new_key.hex()}")
        elif args.aes_op == "encrypt":
            aes_key = get_key_from_arg(args.key, is_aes_key=True)
            aes_encrypt(aes_key, args.infile, args.outfile)
        elif args.aes_op == "decrypt":
            aes_key = get_key_from_arg(args.key, is_aes_key=True)
            aes_decrypt(aes_key, args.infile, args.outfile)

    elif args.command == "rsa":
        if args.rsa_op == "genkeys":
            generate_rsa_keys_for_toolkit(args.bits, args.privfile, args.pubfile)
        elif args.rsa_op == "encrypt":
            rsa_encrypt(args.pubkey, args.infile, args.outfile)
        elif args.rsa_op == "decrypt":
            rsa_decrypt(args.privkey, args.infile, args.outfile)

    elif args.command == "sha256":
        # No sub-operation for sha256, infile is a direct argument
        sha256_hash_file(args.infile)

    elif args.command == "hmac":
        if args.hmac_op == "genkey":
            new_key = get_random_bytes(32) # Generate a 256-bit (32 bytes) key, common for HMAC-SHA256
            with open(args.outfile, "wb") as kf:
                kf.write(new_key)
            print(f"New 32-byte HMAC key generated and saved to '{args.outfile}'. Hex: {new_key.hex()}")
        elif args.hmac_op == "generate":
            hmac_key = get_key_from_arg(args.key, is_aes_key=False)
            generate_hmac_sha256(hmac_key, args.infile, args.outfile)

    else:
        parser.print_help()

