import base64
import io
import os
import sqlite3
import tkinter as tk
from tkinter import Label, filedialog, messagebox, simpledialog

import cv2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageTk

# Allowed file types
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".mp3", ".txt", ".csv"}

# Database connection
conn = sqlite3.connect("secure_files.db")
cursor = conn.cursor()

# Create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT,
    file_type TEXT,
    file_data BLOB,
    salt BLOB
)
""")
conn.commit()

# Function to generate a key from PIN
def derive_key(pin: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

# Function to encrypt file with PIN
def encrypt_file(data, pin):
    salt = os.urandom(16)  # Generate random salt
    key = derive_key(pin, salt)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data, salt  # Return encrypted data & salt

# Function to decrypt file with PIN
def decrypt_file(encrypted_data, pin, salt):
    try:
        key = derive_key(pin, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Function to upload and encrypt file
def upload_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return  

    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext not in ALLOWED_EXTENSIONS:
        messagebox.showerror("Invalid File", "Only allowed file types can be uploaded.")
        return

    # Ask for a PIN from the user
    pin = simpledialog.askstring("Set PIN", "Enter a secure PIN to encrypt this file:", show="*")
    if not pin:
        messagebox.showwarning("PIN Required", "You must enter a PIN to encrypt the file.")
        return

    # Read file as binary
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Encrypt file
    encrypted_data, salt = encrypt_file(file_data, pin)

    # Store in database
    cursor.execute("INSERT INTO files (file_name, file_type, file_data, salt) VALUES (?, ?, ?, ?)",
                   (file_name, file_ext, encrypted_data, salt))
    conn.commit()
    messagebox.showinfo("Success", f"File '{file_name}' uploaded and encrypted successfully!")

# Function to download encrypted file
def download_encrypted_file():
    cursor.execute("SELECT id, file_name FROM files")
    files = cursor.fetchall()

    if not files:
        messagebox.showinfo("No Files", "No files found in the database.")
        return

    download_window = tk.Toplevel(root)
    download_window.title("Download Encrypted File")
    download_window.geometry("400x300")

    def save_encrypted_file(file_id, file_name):
        cursor.execute("SELECT file_data FROM files WHERE id=?", (file_id,))
        encrypted_data = cursor.fetchone()[0]

        save_path = filedialog.asksaveasfilename(defaultextension="",
                                                 initialfile=file_name,
                                                 filetypes=[("All Files", "*.*")])
        if save_path:
            with open(save_path, "wb") as file:
                file.write(encrypted_data)
            messagebox.showinfo("Success", f"Encrypted file saved as {save_path}")

    for file_id, file_name in files:
        file_button = tk.Button(download_window, text=file_name, command=lambda id=file_id, name=file_name: save_encrypted_file(id, name))
        file_button.pack(pady=5)

# Function to access file inside the app
def access_file():
    cursor.execute("SELECT id, file_name, file_type FROM files")
    files = cursor.fetchall()

    if not files:
        messagebox.showinfo("No Files", "No files found in the database.")
        return

    access_window = tk.Toplevel(root)
    access_window.title("Access File")
    access_window.geometry("500x400")

    def decrypt_and_show(file_id, file_name, file_type):
        cursor.execute("SELECT file_data, salt FROM files WHERE id=?", (file_id,))
        result = cursor.fetchone()
        encrypted_data, salt = result

        # Ask for the PIN
        pin = simpledialog.askstring("Enter PIN", "Enter the PIN to access this file:", show="*")
        if not pin:
            messagebox.showwarning("PIN Required", "You must enter the correct PIN.")
            return

        decrypted_data = decrypt_file(encrypted_data, pin, salt)
        if decrypted_data is None:
            messagebox.showerror("Error", "Decryption failed! Incorrect PIN.")
            return

        # Display content in the app
        if file_type in [".png", ".jpg", ".jpeg", ".gif"]:
            # Show image
            image = Image.open(io.BytesIO(decrypted_data))
            img_window = tk.Toplevel(access_window)
            img_window.title(f"Image: {file_name}")
            img = ImageTk.PhotoImage(image)
            label = Label(img_window, image=img)
            label.image = img
            label.pack()

        elif file_type in [".txt", ".csv"]:
            # Show text
            text_window = tk.Toplevel(access_window)
            text_window.title(f"Text File: {file_name}")
            text_window.geometry("600x400")
            text_box = tk.Text(text_window, wrap=tk.WORD)
            text_box.insert(tk.END, decrypted_data.decode(errors="ignore"))
            text_box.pack(expand=True, fill=tk.BOTH)

        elif file_type in [".mp4", ".mp3"]:
            # Show message (Playback requires external software)
            messagebox.showinfo("Media File", "This is a media file. Save and play it on your media player.")

    for file_id, file_name, file_type in files:
        file_button = tk.Button(access_window, text=file_name, command=lambda id=file_id, name=file_name, type=file_type: decrypt_and_show(id, name, type))
        file_button.pack(pady=5)

# Create GUI window
root = tk.Tk()
root.title("Secure File Storage with PIN")
root.geometry("400x400")

# Upload button
upload_button = tk.Button(root, text="Upload & Encrypt File", command=upload_file, padx=20, pady=10)
upload_button.pack(pady=10)

# Download Encrypted button
download_button = tk.Button(root, text="Download Encrypted File", command=download_encrypted_file, padx=20, pady=10)
download_button.pack(pady=10)

# Access File button (Decrypt inside the app)
access_button = tk.Button(root, text="Access File with PIN", command=access_file, padx=20, pady=10)
access_button.pack(pady=10)

# Label to display status
label = tk.Label(root, text="Allowed: PDF, DOCX, PNG, JPG, JPEG, GIF, MP4, MP3, TXT, CSV", wraplength=350)
label.pack(pady=10)

# Run the application
root.mainloop()

# Close database connection when app closes
conn.close()
