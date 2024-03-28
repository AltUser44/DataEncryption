import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

class RSAEncryptionApp:
    def __init__(self, root):
        """create application main window root and generate RSA keys."""
        self.root = root
        self.initialize_gui()
        self.private_key, self.public_key = self.generate_keys()

    def initialize_gui(self):
        """graphical user interface for the RSA encryption tool."""
        self.root.title("RSA Encryption Tool")
        font_specs = ("Roboto", 12)

        tk.Label(self.root, text="Enter Text:", font=font_specs).grid(row=0, column=0, padx=5, pady=5)
        self.text_entry = scrolledtext.ScrolledText(self.root, height=5, width=40, font=font_specs, bg='#FFC0CB')  # Light pink
        self.text_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(self.root, text="Encrypt", font=font_specs, command=self.encrypt_message).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Decrypt", font=font_specs, command=self.decrypt_message).grid(row=1, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Result:", font=font_specs).grid(row=2, column=0, padx=5, pady=5)
        self.result_entry = scrolledtext.ScrolledText(self.root, height=5, width=40, font=font_specs, bg='#ADD8E6')  # Light blue
        self.result_entry.grid(row=2, column=1, padx=5, pady=5)

    def generate_keys(self):
        """Generate a pair of RSA keys for encryption and decryption."""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def encrypt_message(self):
        """Encrypt the message entered by the user using the public RSA key."""
        recipient_key = RSA.import_key(self.public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        message = self.text_entry.get(1.0, tk.END).strip()  # Strip whitespace
        encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
        self.result_entry.delete(1.0, tk.END)
        self.result_entry.insert(tk.END, binascii.hexlify(encrypted_message).decode('utf-8'))

    def decrypt_message(self):
        """Decrypt the message entered by the user using the private RSA key."""
        private_key = RSA.import_key(self.private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            encrypted_message_hex = self.text_entry.get(1.0, tk.END).strip()
            encrypted_message_hex = ''.join(filter(lambda x: x in '0123456789abcdefABCDEF', encrypted_message_hex))
            if len(encrypted_message_hex) % 2 != 0:
                raise ValueError("Hexadecimal string has an odd length")
            encrypted_message = binascii.unhexlify(encrypted_message_hex)
            decrypted_message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
            self.result_entry.delete(1.0, tk.END)
            self.result_entry.insert(tk.END, decrypted_message)
        except ValueError as e:
            messagebox.showerror("Decryption Error", str(e))
        except binascii.Error as e:
            messagebox.showerror("Decryption Error", "Non-hexadecimal digit found. Ensure the encrypted data is correct.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAEncryptionApp(root)
    root.mainloop()
