import random

def generate_binary_keys(secret_key, length):
    """Generate binary keys B1, B2, B3, B4 based on the secret key."""
    random.seed(secret_key)  # Seed the random number generator for reproducibility
    return [random.getrandbits(8) for _ in range(4)]  # Generate 4 binary keys

def encrypt(plaintext, secret_key):
    """Encrypt the plaintext using the RuleCipher system."""
    # Generate binary keys
    binary_keys = generate_binary_keys(secret_key, len(plaintext))
    
    # Convert plaintext to ASCII values
    ascii_values = [ord(char) for char in plaintext]
    
    # Encrypt using the encryption rule
    ciphertext = ascii_values
    for key in binary_keys:
        ciphertext = [c ^ key for c in ciphertext]  # XOR with the binary key
    
    return ciphertext, binary_keys

def decrypt(ciphertext, binary_keys):
    """Decrypt the ciphertext using the RuleCipher system."""
    decrypted = ciphertext
    for key in reversed(binary_keys):
        decrypted = [c ^ key for c in decrypted]  # XOR with the binary key in reverse order
    
    # Convert ASCII values back to characters
    return ''.join(chr(c) for c in decrypted)

# Example usage
secret_key = "SECRET"
plaintext = "MAKASSAR"

# Encrypt
ciphertext, binary_keys = encrypt(plaintext, secret_key)
print(f"Ciphertext: {ciphertext}")
print(f"Binary Keys: {binary_keys}")

# Decrypt
decrypted_text = decrypt(ciphertext, binary_keys)
print(f"Decrypted Text: {decrypted_text}")
