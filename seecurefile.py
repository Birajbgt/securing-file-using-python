import base64
import io
import os
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import cv2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageTk

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".mp3", ".txt", ".csv"}

class SecureFileStorageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Storage")
        self.root.geometry("450x500")
        
        self.conn = sqlite3.connect("secure_files.db")
        self.cursor = self.conn.cursor()
        self.create_table()
        
        self.create_widgets()
    
    def create_table(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            file_type TEXT,
            file_data BLOB,
            salt BLOB
        )
        """)
        self.conn.commit()
    
    def derive_key(self, pin, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(pin.encode()))
    
    def encrypt_file(self, data, pin):
        salt = os.urandom(16)
        key = self.derive_key(pin, salt)
        cipher = Fernet(key)
        return cipher.encrypt(data), salt
    
    def decrypt_file(self, encrypted_data, pin, salt):
        try:
            key = self.derive_key(pin, salt)
            cipher = Fernet(key)
            return cipher.decrypt(encrypted_data)
        except:
            return None
    
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            messagebox.showerror("Invalid File", "Only allowed file types can be uploaded.")
            return
        
        pin = simpledialog.askstring("Set PIN", "Enter a secure PIN:", show="*")
        if not pin:
            return
        
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        encrypted_data, salt = self.encrypt_file(file_data, pin)
        self.cursor.execute("INSERT INTO files (file_name, file_type, file_data, salt) VALUES (?, ?, ?, ?)",
                            (file_name, file_ext, encrypted_data, salt))
        self.conn.commit()
        messagebox.showinfo("Success", "File uploaded and encrypted successfully!")
    
    def access_file(self):
        self.cursor.execute("SELECT id, file_name, file_type FROM files")
        files = self.cursor.fetchall()
        if not files:
            messagebox.showinfo("No Files", "No files found in the database.")
            return
        
        access_window = tk.Toplevel(self.root)
        access_window.title("Access File")
        access_window.geometry("500x400")
        
        for file_id, file_name, file_type in files:
            ttk.Button(access_window, text=file_name, command=lambda id=file_id, name=file_name, type=file_type: self.decrypt_and_show(id, name, type)).pack(pady=5)
    
    def decrypt_and_show(self, file_id, file_name, file_type):
        self.cursor.execute("SELECT file_data, salt FROM files WHERE id=?", (file_id,))
        result = self.cursor.fetchone()
        encrypted_data, salt = result
        
        pin = simpledialog.askstring("Enter PIN", "Enter the PIN:", show="*")
        if not pin:
            return
        
        decrypted_data = self.decrypt_file(encrypted_data, pin, salt)
        if decrypted_data is None:
            messagebox.showerror("Error", "Incorrect PIN!")
            return
        
        if file_type in [".png", ".jpg", ".jpeg", ".gif"]:
            image = Image.open(io.BytesIO(decrypted_data))
            img_window = tk.Toplevel()
            img_window.title(f"Image: {file_name}")
            img = ImageTk.PhotoImage(image)
            label = tk.Label(img_window, image=img)
            label.image = img
            label.pack()
        elif file_type in [".txt", ".csv"]:
            text_window = tk.Toplevel()
            text_window.title(f"Text File: {file_name}")
            text_box = tk.Text(text_window, wrap=tk.WORD)
            text_box.insert(tk.END, decrypted_data.decode(errors="ignore"))
            text_box.pack(expand=True, fill=tk.BOTH)
        else:
            messagebox.showinfo("Media File", "Save and play it externally.")
    
    def create_widgets(self):
        frame = tk.Frame(self.root, padx=10, pady=10)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Secure File Storage", font=("Arial", 14)).pack(pady=10)
        ttk.Button(frame, text="Upload & Encrypt File", command=self.upload_file).pack(pady=10)
        ttk.Button(frame, text="Access File with PIN", command=self.access_file).pack(pady=10)
        ttk.Label(frame, text="Allowed: PDF, DOCX, PNG, JPG, GIF, MP4, MP3, TXT, CSV").pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileStorageApp(root)
    root.mainloop()