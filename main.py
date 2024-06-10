import tkinter as tk
from tkinter import filedialog, messagebox
from keys_generator import generate_keys, decrypt_and_deserialize_private_key
from signing_tool import sign_document, verify_signature
from encryption_tool import encrypt_file, decrypt_file

root = tk.Tk()

# Window parameters
root.title('Easy QES')
root.geometry('600x700')

# Header
header = tk.Label(root, text='Welcome to Easy QES!', font=('Georgia', 25, 'bold'), fg='#80E080')
header.pack()

# Generate keys section
generate_keys_header = tk.Label(root, text='Generate keys by providing a PIN', font=20, fg='#A0E0A0')
generate_keys_header.pack()

pin_entry = tk.Entry(root, show='*')
pin_entry.pack()

generation_label = tk.Label(root, font=15, fg='#A0E0A0')

def generate_keys_button_function():
    if len(pin_entry.get()) != 4:
        generation_label.configure(text='Provide a 4 digit PIN', fg='#FF0000')
    elif generate_keys(int(pin_entry.get())):
        generation_label.configure(text='Keys generated successfully', fg='#A0E0A0')
    else:
        generation_label.configure(text='Generation failed', fg='#A0E0A0')
    generation_label.pack()

generate_keys_button = tk.Button(root, text='Generate', command=generate_keys_button_function)
generate_keys_button.pack()

# Sign Document Section
sign_document_header = tk.Label(root, text='Sign a Document', font=20, fg='#A0E0A0')
sign_document_header.pack()

def sign_document_button_function():
    file_path = filedialog.askopenfilename()
    if file_path:
        pin = pin_entry.get()
        if len(pin) != 4:
            messagebox.showerror('Error', 'Provide a 4 digit PIN')
        else:
            private_key = decrypt_and_deserialize_private_key(int(pin))
            if private_key:
                sign_document(file_path, private_key)
                messagebox.showinfo('Success', 'Document signed successfully')
            else:
                messagebox.showerror('Error', 'Decryption failed')

sign_document_button = tk.Button(root, text='Sign Document', command=sign_document_button_function)
sign_document_button.pack()

# Verify Signature Section
verify_signature_header = tk.Label(root, text='Verify a Signature', font=20, fg='#A0E0A0')
verify_signature_header.pack()

def verify_signature_button_function():
    file_path = filedialog.askopenfilename(title="Select Document to Verify")
    sig_path = filedialog.askopenfilename(title="Select Signature File")
    if file_path and sig_path:
        if verify_signature(file_path, sig_path):
            messagebox.showinfo('Success', 'Signature verified successfully')
        else:
            messagebox.showerror('Error', 'Signature verification failed')

verify_signature_button = tk.Button(root, text='Verify Signature', command=verify_signature_button_function)
verify_signature_button.pack()

# Encrypt File Section
encrypt_file_header = tk.Label(root, text='Encrypt a File', font=20, fg='#A0E0A0')
encrypt_file_header.pack()

def encrypt_file_button_function():
    file_path = filedialog.askopenfilename()
    if file_path:
        public_key_path = filedialog.askopenfilename(title="Select Public Key File")
        if public_key_path:
            encrypt_file(file_path, public_key_path)
            messagebox.showinfo('Success', 'File encrypted successfully')

encrypt_file_button = tk.Button(root, text='Encrypt File', command=encrypt_file_button_function)
encrypt_file_button.pack()

# Decrypt File Section
decrypt_file_header = tk.Label(root, text='Decrypt a File', font=20, fg='#A0E0A0')
decrypt_file_header.pack()

def decrypt_file_button_function():
    file_path = filedialog.askopenfilename()
    if file_path:
        pin = pin_entry.get()
        if len(pin) != 4:
            messagebox.showerror('Error', 'Provide a 4 digit PIN')
        else:
            private_key = decrypt_and_deserialize_private_key(int(pin))
            if private_key:
                decrypt_file(file_path, private_key)
                messagebox.showinfo('Success', 'File decrypted successfully')
            else:
                messagebox.showerror('Error', 'Decryption failed')

decrypt_file_button = tk.Button(root, text='Decrypt File', command=decrypt_file_button_function)
decrypt_file_button.pack()

root.mainloop()
