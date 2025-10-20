# generate_keys.py
# This script generates an RSA key pair (private and public keys)
# and saves them to PEM files.

from Crypto.PublicKey import RSA

def generate_rsa_key_pair(bits=2048):
    """Generates an RSA key pair.

    Args:
        bits (int): The key length in bits. Default is 2048.

    Returns:
        tuple: A tuple containing the private key and public key objects.
    """
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key_data, filename):
    """Saves key data to a file.

    Args:
        key_data (bytes): The key data to save.
        filename (str): The name of the file to save the key to.
    """
    with open(filename, "wb") as f:
        f.write(key_data)
    print(f"Key saved to {filename}")

if __name__ == "__main__":
    private_key_pem, public_key_pem = generate_rsa_key_pair()

    # Save the private key
    save_key_to_file(private_key_pem, "private_key.pem")

    # Save the public key
    save_key_to_file(public_key_pem, "public_key.pem")

    print("RSA key pair generated successfully.")
    print("Private key stored in private_key.pem")
    print("Public key stored in public_key.pem")

