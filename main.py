import tkinter as tk
from tkinter import messagebox
import os
from keys_generator import generate_keys, save_keys_to_pendrive, load_keys_from_pendrive, find_pendrive
from encryption_tool import encrypt_file, decrypt_file, sign_document

root = tk.Tk()

# Window parameters
root.title('Easy QES')
root.geometry('400x500')

# Header
header = tk.Label(root, text='Welcome to Easy QES!', font=('Georgia', 25, 'bold'), fg='#80E080')
header.pack()

# Generate keys section
generate_keys_header = tk.Label(root, text='Generate keys by providing a PIN', font=20, fg='#A0E0A0')
generate_keys_header.pack()

pin_entry = tk.Entry(root)
pin_entry.pack()

generation_label = tk.Label(root, font=15, fg='#A0E0A0')

def generate_keys_button_function():
    if len(pin_entry.get()) != 4:
        generation_label.configure(text='Provide a 4 digit PIN', fg='#FF0000')
    elif save_keys_to_pendrive(int(pin_entry.get())):
        generation_label.configure(text='Keys generated and saved successfully', fg='#A0E0A0')
    else:
        generation_label.configure(text='Generation failed', fg='#FF0000')

    generation_label.pack()

generate_keys_button = tk.Button(root, text='Generate', command=lambda: generate_keys_button_function())
generate_keys_button.pack()

# Icons for status/messages
status_frame = tk.Frame(root)
status_frame.pack()

hardware_status_icon = tk.Label(status_frame, text='Hardware: Disconnected', fg='red')
hardware_status_icon.pack()

signature_status_icon = tk.Label(status_frame, text='Signature: Not signed', fg='red')
signature_status_icon.pack()

encryption_status_icon = tk.Label(status_frame, text='Encryption: Not encrypted', fg='red')
encryption_status_icon.pack()

def update_hardware_status():
    if find_pendrive():
        hardware_status_icon.configure(text='Hardware: Connected', fg='green')
    else:
        hardware_status_icon.configure(text='Hardware: Disconnected', fg='red')

# Regularly check hardware status
def check_hardware():
    update_hardware_status()
    root.after(2000, check_hardware)

check_hardware()

# Encrypt file section
encrypt_file_header = tk.Label(root, text='Encrypt a file', font=20, fg='#A0E0A0')
encrypt_file_header.pack()

file_entry = tk.Entry(root)
file_entry.pack()

def encrypt_file_button_function():
    file_path = file_entry.get()
    public_key_path = os.path.join(find_pendrive(), 'public_key.pub')
    if encrypt_file(file_path, public_key_path):
        encryption_status_icon.configure(text='Encryption: Encrypted', fg='green')
    else:
        encryption_status_icon.configure(text='Encryption: Failed', fg='red')

encrypt_file_button = tk.Button(root, text='Encrypt', command=lambda: encrypt_file_button_function())
encrypt_file_button.pack()

root.mainloop()
