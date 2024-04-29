import tkinter as tk
from keys_generator import generate_keys

root = tk.Tk()

# Window parameters
root.title('Easy QES')
root.geometry('400x500')

# Header
header = tk.Label(root, text='Welcome to Easy QES!', font=('Goergia', 25, 'bold'), fg='#80E080')
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
    elif generate_keys(int(pin_entry.get())):
        generation_label.configure(text='Keys generated successfully', fg='#A0E0A0')
    else:
        generation_label.configure(text='Generation failed', fg='#A0E0A0')

    generation_label.pack()

generate_keys_button = tk.Button(root, text='Generate', command=lambda: generate_keys_button_function())
generate_keys_button.pack()

root.mainloop()