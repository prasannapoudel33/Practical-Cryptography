# import tkinter as tk
# from tkinter import messagebox, simpledialog, filedialog
# import os

# # Function to copy text to clipboard
# def copy_to_clipboard(text):
#     root.clipboard_clear()
#     root.clipboard_append(text)
#     root.update()  # Required to finalize the clipboard update

# # AES Encryption and Decryption Functions
# def encrypt_message_aes(message, key):
#     """Encrypts a message using a simple block cipher with a given numeric key."""
#     block_size = 8
#     padded_message = message + ' ' * (block_size - len(message) % block_size)
    
#     encrypted_message = ''.join(
#         chr((ord(char) + key) % 256) for char in padded_message
#     )
#     return encrypted_message

# def decrypt_message_aes(encrypted_message, key):
#     """Decrypts a message using a simple block cipher with a given numeric key."""
#     decrypted_message = ''.join(
#         chr((ord(char) - key) % 256) for char in encrypted_message
#     )
#     return decrypted_message.strip()

# # GUI Functions
# def handle_encryption_aes():
#     message = simpledialog.askstring("Input", "Enter the message to encrypt:")
#     key = simpledialog.askinteger("Input", "Enter the numeric key for encryption:")
#     if message and key is not None:
#         encrypted = encrypt_message_aes(message, key)
#         # Show the encrypted message in a messagebox with a "Copy" button
#         copy_to_clipboard(encrypted)  # Automatically copy to clipboard
#         messagebox.showinfo("Encrypted Message", f"Encrypted: {encrypted}\n\n(Copied to clipboard!)")
#         return encrypted
#     else:
#         messagebox.showerror("Error", "Message or Key cannot be empty!")

# def handle_decryption_aes():
#     message = simpledialog.askstring("Input", "Enter the message to decrypt:")
#     key = simpledialog.askinteger("Input", "Enter the numeric key for decryption:")
#     if message and key is not None:
#         decrypted = decrypt_message_aes(message, key)
#         # Show the decrypted message in a messagebox with a "Copy" button
#         copy_to_clipboard(decrypted)  # Automatically copy to clipboard
#         messagebox.showinfo("Decrypted Message", f"Decrypted: {decrypted}\n\n(Copied to clipboard!)")
#         return decrypted
#     else:
#         messagebox.showerror("Error", "Message or Key cannot be empty!")

# # Salsa20 Encryption and Decryption Functions
# def rot_left(x, y):
#     return ((x << y) % (2**32 - 1))

# def quarterround(y):
#     assert len(y) == 4
#     z = [0] * 4
#     z[1] = y[1] ^ rot_left(((y[0] + y[3]) % 2**32), 7)
#     z[2] = y[2] ^ rot_left(((z[1] + y[0]) % 2**32), 9)
#     z[3] = y[3] ^ rot_left(((z[2] + z[1]) % 2**32), 13)
#     z[0] = y[0] ^ rot_left(((z[3] + z[2]) % 2**32), 18)
#     return z

# def rowround(y):
#     assert len(y) == 16
#     z = [0] * 16
#     z[0], z[1], z[2], z[3] = quarterround([y[0], y[1], y[2], y[3]])
#     z[5], z[6], z[7], z[4] = quarterround([y[5], y[6], y[7], y[4]])
#     z[10], z[11], z[8], z[9] = quarterround([y[10], y[11], y[8], y[9]])
#     z[15], z[12], z[13], z[14] = quarterround([y[15], y[12], y[13], y[14]])
#     return z

# def columnround(x):
#     assert len(x) == 16
#     y = [0] * 16
#     y[0], y[4], y[8], y[12] = quarterround([x[0], x[4], x[8], x[12]])
#     y[5], y[9], y[13], y[1] = quarterround([x[5], x[9], x[13], x[1]])
#     y[10], y[14], y[2], y[6] = quarterround([x[10], x[14], x[2], x[6]])
#     y[15], y[3], y[7], y[11] = quarterround([x[15], x[3], x[7], x[11]])
#     return y

# def doubleround(x):
#     return rowround(columnround(x))

# def littleendian(b):
#     assert len(b) == 4
#     return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)

# def littleendian_invert(w):
#     return [w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff]

# def salsa_20(x):
#     _x = [0] * 16
#     i = 0
#     k = 0
#     while i < 16:
#         _x[i] = littleendian([x[k], x[k+1], x[k+2], x[k+3]])
#         k += 4
#         i += 1

#     z = _x
#     for j in range(10):
#         z = doubleround(z)

#     y = []
#     for i in range(16):
#         w = z[i] + _x[i]
#         y.append(w & 0xff)
#         y.append((w >> 8) & 0xff)
#         y.append((w >> 16) & 0xff)
#         y.append((w >> 24) & 0xff)

#     return y

# sig_0 = [101, 120, 112, 97]
# sig_1 = [110, 100, 32, 51]
# sig_2 = [50, 45, 98, 121]
# sig_3 = [116, 101, 32, 107]

# def salsa20_stream(block_counter, nonce, key):
#     assert len(block_counter) == 8
#     assert len(nonce) == 8
#     assert len(key) == 32
    
#     k0 = key[:16]
#     k1 = key[16:]
#     return salsa_20(sig_0 + k0 + sig_1 + nonce + block_counter + sig_2 + k1 + sig_3)

# def salsa20_xor(message, nonce, key):
#     """Input in bytes. Returns encrypted message in the form of bytearray"""
#     assert len(nonce) == 8
#     assert len(key) == 32
#     _nonce = list(nonce)
#     _key = list(key)
#     block_counter = [0] * 8
#     k0 = _key[:16]
#     k1 = _key[16:]
#     enc_list = [a ^ b for a, b in zip(salsa_20(sig_0 + k0 + sig_1 + _nonce + block_counter + sig_2 + k1 + sig_3), list(message))]
#     return bytearray(enc_list)

# def handle_encryption_salsa20():
#     file_path = filedialog.askopenfilename(title="Select a file to encrypt")
#     if file_path:
#         with open(file_path, 'rb') as file:
#             message = file.read()
#         key = os.urandom(32)
#         nonce = os.urandom(8)
#         encrypted_message = salsa20_xor(message, nonce, key)
#         save_path = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".enc")
#         if save_path:
#             with open(save_path, 'wb') as file:
#                 file.write(encrypted_message)
#             messagebox.showinfo("Success", f"File encrypted and saved successfully!\nKey: {key.hex()}\nNonce: {nonce.hex()}")

# def handle_decryption_salsa20():
#     file_path = filedialog.askopenfilename(title="Select a file to decrypt")
#     if file_path:
#         with open(file_path, 'rb') as file:
#             encrypted_message = file.read()
#         key = simpledialog.askstring("Input", "Enter the 32-byte key in hex:")
#         nonce = simpledialog.askstring("Input", "Enter the 8-byte nonce in hex:")
#         if key and nonce:
#             key = bytes.fromhex(key)
#             nonce = bytes.fromhex(nonce)
#             decrypted_message = salsa20_xor(encrypted_message, nonce, key)
#             save_path = filedialog.asksaveasfilename(title="Save decrypted file as", defaultextension=".txt")
#             if save_path:
#                 with open(save_path, 'wb') as file:
#                     file.write(decrypted_message)
#                 messagebox.showinfo("Success", "File decrypted and saved successfully!")

# # Setting up the main window
# def main():
#     global root
#     root = tk.Tk()
#     root.title("File Encryption Tool")

#     # Buttons for AES encryption and decryption
#     aes_frame = tk.LabelFrame(root, text="AES Encryption", padx=10, pady=10)
#     aes_frame.pack(padx=10, pady=10, fill="both", expand="yes")

#     encrypt_button_aes = tk.Button(aes_frame, text="Encrypt Message (AES)", command=handle_encryption_aes)
#     encrypt_button_aes.pack(pady=5)

#     decrypt_button_aes = tk.Button(aes_frame, text="Decrypt Message (AES)", command=handle_decryption_aes)
#     decrypt_button_aes.pack(pady=5)

#     # Buttons for Salsa20 encryption and decryption
#     salsa20_frame = tk.LabelFrame(root, text="Salsa20 Encryption", padx=10, pady=10)
#     salsa20_frame.pack(padx=10, pady=10, fill="both", expand="yes")

#     encrypt_button_salsa20 = tk.Button(salsa20_frame, text="Encrypt File (Salsa20)", command=handle_encryption_salsa20)
#     encrypt_button_salsa20.pack(pady=5)

#     decrypt_button_salsa20 = tk.Button(salsa20_frame, text="Decrypt File (Salsa20)", command=handle_decryption_salsa20)
#     decrypt_button_salsa20.pack(pady=5)

#     root.mainloop()

# if __name__ == "__main__":
#     main()





import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import os

# Function to copy text to clipboard
def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()  # Required to finalize the clipboard update

# AES Encryption and Decryption Functions
def encrypt_message_aes(message, key):
    """Encrypts a message using a simple block cipher with a given numeric key."""
    block_size = 8
    padded_message = message + ' ' * (block_size - len(message) % block_size)
    
    encrypted_message = ''.join(
        chr((ord(char) + key) % 256) for char in padded_message
    )
    return encrypted_message

def decrypt_message_aes(encrypted_message, key):
    """Decrypts a message using a simple block cipher with a given numeric key."""
    decrypted_message = ''.join(
        chr((ord(char) - key) % 256) for char in encrypted_message
    )
    return decrypted_message.strip()

# GUI Functions
def handle_encryption_aes():
    message = simpledialog.askstring("Input", "Enter the message to encrypt:")
    key = simpledialog.askinteger("Input", "Enter the numeric key for encryption:")
    if message and key is not None:
        encrypted = encrypt_message_aes(message, key)
        # Show the encrypted message in a messagebox with a "Copy" button
        copy_to_clipboard(encrypted)  # Automatically copy to clipboard
        messagebox.showinfo("Encrypted Message", f"Encrypted: {encrypted}\n\n(Copied to clipboard!)")
        return encrypted
    else:
        messagebox.showerror("Error", "Message or Key cannot be empty!")

def handle_decryption_aes():
    message = simpledialog.askstring("Input", "Enter the message to decrypt:")
    key = simpledialog.askinteger("Input", "Enter the numeric key for decryption:")
    if message and key is not None:
        decrypted = decrypt_message_aes(message, key)
        # Show the decrypted message in a messagebox with a "Copy" button
        copy_to_clipboard(decrypted)  # Automatically copy to clipboard
        messagebox.showinfo("Decrypted Message", f"Decrypted: {decrypted}\n\n(Copied to clipboard!)")
        return decrypted
    else:
        messagebox.showerror("Error", "Message or Key cannot be empty!")

# Salsa20 Encryption and Decryption Functions
def rot_left(x, y):
    return ((x << y) % (2**32 - 1))

def quarterround(y):
    assert len(y) == 4
    z = [0] * 4
    z[1] = y[1] ^ rot_left(((y[0] + y[3]) % 2**32), 7)
    z[2] = y[2] ^ rot_left(((z[1] + y[0]) % 2**32), 9)
    z[3] = y[3] ^ rot_left(((z[2] + z[1]) % 2**32), 13)
    z[0] = y[0] ^ rot_left(((z[3] + z[2]) % 2**32), 18)
    return z

def rowround(y):
    assert len(y) == 16
    z = [0] * 16
    z[0], z[1], z[2], z[3] = quarterround([y[0], y[1], y[2], y[3]])
    z[5], z[6], z[7], z[4] = quarterround([y[5], y[6], y[7], y[4]])
    z[10], z[11], z[8], z[9] = quarterround([y[10], y[11], y[8], y[9]])
    z[15], z[12], z[13], z[14] = quarterround([y[15], y[12], y[13], y[14]])
    return z

def columnround(x):
    assert len(x) == 16
    y = [0] * 16
    y[0], y[4], y[8], y[12] = quarterround([x[0], x[4], x[8], x[12]])
    y[5], y[9], y[13], y[1] = quarterround([x[5], x[9], x[13], x[1]])
    y[10], y[14], y[2], y[6] = quarterround([x[10], x[14], x[2], x[6]])
    y[15], y[3], y[7], y[11] = quarterround([x[15], x[3], x[7], x[11]])
    return y

def doubleround(x):
    return rowround(columnround(x))

def littleendian(b):
    assert len(b) == 4
    return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)

def littleendian_invert(w):
    return [w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff]

def salsa_20(x):
    _x = [0] * 16
    i = 0
    k = 0
    while i < 16:
        _x[i] = littleendian([x[k], x[k+1], x[k+2], x[k+3]])
        k += 4
        i += 1

    z = _x
    for j in range(10):
        z = doubleround(z)

    y = []
    for i in range(16):
        w = z[i] + _x[i]
        y.append(w & 0xff)
        y.append((w >> 8) & 0xff)
        y.append((w >> 16) & 0xff)
        y.append((w >> 24) & 0xff)

    return y

sig_0 = [101, 120, 112, 97]
sig_1 = [110, 100, 32, 51]
sig_2 = [50, 45, 98, 121]
sig_3 = [116, 101, 32, 107]

def salsa20_stream(block_counter, nonce, key):
    assert len(block_counter) == 8
    assert len(nonce) == 8
    assert len(key) == 32
    
    k0 = key[:16]
    k1 = key[16:]
    return salsa_20(sig_0 + k0 + sig_1 + nonce + block_counter + sig_2 + k1 + sig_3)

def salsa20_xor(message, nonce, key):
    """Input in bytes. Returns encrypted message in the form of bytearray"""
    assert len(nonce) == 8
    assert len(key) == 32
    _nonce = list(nonce)
    _key = list(key)
    block_counter = [0] * 8
    k0 = _key[:16]
    k1 = _key[16:]
    enc_list = [a ^ b for a, b in zip(salsa_20(sig_0 + k0 + sig_1 + _nonce + block_counter + sig_2 + k1 + sig_3), list(message))]
    return bytearray(enc_list)

def handle_encryption_salsa20():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        with open(file_path, 'rb') as file:
            message = file.read()
        key = os.urandom(32)
        nonce = os.urandom(8)
        encrypted_message = salsa20_xor(message, nonce, key)
        save_path = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".enc")
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted_message)
            
            # Copy the key and nonce to the clipboard
            key_hex = key.hex()
            nonce_hex = nonce.hex()
            clipboard_text = f"Key: {key_hex}\nNonce: {nonce_hex}"
            copy_to_clipboard(clipboard_text)
            
            messagebox.showinfo("Success", f"File encrypted and saved successfully!\nKey: {key_hex}\nNonce: {nonce_hex}\n\n(Copied to clipboard!)")

def handle_decryption_salsa20():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        with open(file_path, 'rb') as file:
            encrypted_message = file.read()
        key = simpledialog.askstring("Input", "Enter the 32-byte key in hex:")
        nonce = simpledialog.askstring("Input", "Enter the 8-byte nonce in hex:")
        if key and nonce:
            key = bytes.fromhex(key)
            nonce = bytes.fromhex(nonce)
            decrypted_message = salsa20_xor(encrypted_message, nonce, key)
            save_path = filedialog.asksaveasfilename(title="Save decrypted file as", defaultextension=".txt")
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_message)
                messagebox.showinfo("Success", "File decrypted and saved successfully!")

# Setting up the main window
def main():
    global root
    root = tk.Tk()
    root.title("File Encryption Tool")

    # Buttons for AES encryption and decryption
    aes_frame = tk.LabelFrame(root, text="AES Encryption", padx=10, pady=10)
    aes_frame.pack(padx=10, pady=10, fill="both", expand="yes")

    encrypt_button_aes = tk.Button(aes_frame, text="Encrypt Message (AES)", command=handle_encryption_aes)
    encrypt_button_aes.pack(pady=5)

    decrypt_button_aes = tk.Button(aes_frame, text="Decrypt Message (AES)", command=handle_decryption_aes)
    decrypt_button_aes.pack(pady=5)

    # Buttons for Salsa20 encryption and decryption
    salsa20_frame = tk.LabelFrame(root, text="Salsa20 Encryption", padx=10, pady=10)
    salsa20_frame.pack(padx=10, pady=10, fill="both", expand="yes")

    encrypt_button_salsa20 = tk.Button(salsa20_frame, text="Encrypt File (Salsa20)", command=handle_encryption_salsa20)
    encrypt_button_salsa20.pack(pady=5)

    decrypt_button_salsa20 = tk.Button(salsa20_frame, text="Decrypt File (Salsa20)", command=handle_decryption_salsa20)
    decrypt_button_salsa20.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
    