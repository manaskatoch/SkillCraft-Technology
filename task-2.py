from PIL import Image
import random

class ImageEncryptor:
    def __init__(self, image_path):
        self.image = Image.open(image_path).convert('RGB')
        self.pixels = list(self.image.getdata())
        self.size = self.image.size

    def save_image(self, pixels, filename):
        """Save a list of pixels as an image file."""
        img = Image.new('RGB', self.size)
        img.putdata(pixels)
        img.save(filename)
        print(f"Image saved as {filename}")

    def swap_encrypt(self, key):
        """Encrypt by shuffling pixels using a key."""
        random.seed(key)
        indices = list(range(len(self.pixels)))
        random.shuffle(indices)

        encrypted_pixels = [self.pixels[i] for i in indices]
        self.save_image(encrypted_pixels, 'encrypted_swap.png')
        # Save permutation indices for decryption
        with open('swap_indices.txt', 'w') as f:
            f.write(','.join(map(str, indices)))
        print("Permutation indices saved to swap_indices.txt")

    def swap_decrypt(self, encrypted_path):
        """Decrypt by reversing the pixel shuffle."""
        with open('swap_indices.txt', 'r') as f:
            indices = list(map(int, f.read().strip().split(',')))

        encrypted_image = Image.open(encrypted_path).convert('RGB')
        encrypted_pixels = list(encrypted_image.getdata())

        # Reconstruct original pixel order
        decrypted_pixels = [None] * len(encrypted_pixels)
        for original_pos, shuffled_pos in enumerate(indices):
            decrypted_pixels[shuffled_pos] = encrypted_pixels[original_pos]

        self.save_image(decrypted_pixels, 'decrypted_swap.png')

    def shift_encrypt(self, shift):
        """Encrypt by shifting pixel RGB values."""
        def shift_pixel(pixel):
            return tuple((component + shift) % 256 for component in pixel)

        encrypted_pixels = [shift_pixel(p) for p in self.pixels]
        self.save_image(encrypted_pixels, 'encrypted_shift.png')

    def shift_decrypt(self, encrypted_path, shift):
        """Decrypt by reversing the pixel RGB shift."""
        encrypted_image = Image.open(encrypted_path).convert('RGB')
        encrypted_pixels = list(encrypted_image.getdata())

        def unshift_pixel(pixel):
            return tuple((component - shift) % 256 for component in pixel)

        decrypted_pixels = [unshift_pixel(p) for p in encrypted_pixels]
        self.save_image(decrypted_pixels, 'decrypted_shift.png')

def main():
    print("=== Image Encryption Tool ===")
    img_path = input("Enter path to image file: ").strip()
    encryptor = ImageEncryptor(img_path)

    mode = input("Choose mode (encrypt/decrypt): ").strip().lower()
    method = input("Choose method (swap/shift): ").strip().lower()

    if mode == 'encrypt':
        if method == 'swap':
            key = input("Enter secret key (string): ")
            encryptor.swap_encrypt(key)
        elif method == 'shift':
            try:
                shift = int(input("Enter shift value (0-255): "))
                if not 0 <= shift <= 255:
                    raise ValueError
            except ValueError:
                print("Invalid shift value. Must be an integer 0-255.")
                return
            encryptor.shift_encrypt(shift)
        else:
            print("Invalid method.")
    elif mode == 'decrypt':
        enc_img_path = input("Enter path to encrypted image file: ").strip()
        if method == 'swap':
            encryptor.swap_decrypt(enc_img_path)
        elif method == 'shift':
            try:
                shift = int(input("Enter shift value used during encryption (0-255): "))
                if not 0 <= shift <= 255:
                    raise ValueError
            except ValueError:
                print("Invalid shift value. Must be an integer 0-255.")
                return
            encryptor.shift_decrypt(enc_img_path, shift)
        else:
            print("Invalid method.")
    else:
        print("Invalid mode. Choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()