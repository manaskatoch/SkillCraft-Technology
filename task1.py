def encrypt_caesar(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            # Determine if character is uppercase or lowercase
            offset = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap around the alphabet
            encrypted += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            # Leave non-alphabetic characters unchanged
            encrypted += char
    return encrypted

def decrypt_caesar(ciphertext, shift):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            decrypted += char
    return decrypted

def main():
    print("Caesar Cipher Tool")
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Invalid mode selected. Please choose 'encrypt' or 'decrypt'.")
        return

    text = input("Enter the text: ")
    try:
        shift = int(input("Enter shift value (0-25): "))
        if shift < 0 or shift > 25:
            print("Shift value must be between 0 and 25.")
            return
    except ValueError:
        print("Invalid shift value. Please enter an integer between 0 and 25.")
        return

    if mode == 'encrypt':
        result = encrypt_caesar(text, shift)
        print(f"Encrypted text: {result}")
    else:
        result = decrypt_caesar(text, shift)
        print(f"Decrypted text: {result}")

if __name__ == "__main__":
    main()
