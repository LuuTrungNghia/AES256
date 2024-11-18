import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import time
import random
import string

class AESCipher:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("Khóa AES-256 phải có đúng 32 ký tự.")
        self.key = key.encode('utf-8')

    def encrypt(self, plaintext):
        try:
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            return f"{iv}:{ct}"
        except Exception as e:
            raise ValueError(f"Lỗi trong quá trình mã hóa: {e}")

    def decrypt(self, ciphertext):
        try:
            iv, ct = ciphertext.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except (ValueError, KeyError) as e:
            raise ValueError("Giải mã thất bại. Vui lòng kiểm tra khóa hoặc dữ liệu đầu vào.")
        except Exception as e:
            raise ValueError(f"Lỗi trong quá trình giải mã: {e}")

def handle_encryption():
    key = key_entry.get()
    if len(key) != 32:
        messagebox.showerror("Lỗi", "Khóa AES-256 phải có đúng 32 ký tự.")
        return
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Lưu ý", "Vui lòng nhập văn bản để mã hóa.")
        return
    try:
        start_time = time.time()
        aes = AESCipher(key)
        encrypted_text = aes.encrypt(text)
        end_time = time.time()
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted_text)
        messagebox.showinfo("Thành công", f"Mã hóa hoàn tất trong {end_time - start_time:.2f} giây.")
    except ValueError as e:
        messagebox.showerror("Lỗi mã hóa", str(e))
    except Exception as e:
        messagebox.showerror("Lỗi không xác định", str(e))

def handle_decryption():
    key = key_entry.get()
    if len(key) != 32:
        messagebox.showerror("Lỗi", "Khóa AES-256 phải có đúng 32 ký tự.")
        return
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Lưu ý", "Vui lòng nhập văn bản để giải mã.")
        return
    try:
        start_time = time.time()
        aes = AESCipher(key)
        decrypted_text = aes.decrypt(text)
        end_time = time.time()
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
        messagebox.showinfo("Thành công", f"Giải mã hoàn tất trong {end_time - start_time:.2f} giây.")
    except ValueError as e:
        messagebox.showerror("Lỗi giải mã", str(e))
    except Exception as e:
        messagebox.showerror("Lỗi không xác định", str(e))

def toggle_key_visibility():
    key_entry.config(show="" if show_key_var.get() else "*")

def load_file():
    file_path = filedialog.askopenfilename(title="Chọn tệp văn bản", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, content)

def save_file():
    file_path = filedialog.asksaveasfilename(title="Lưu kết quả",
                                             defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        content = output_text.get("1.0", tk.END).strip()
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        messagebox.showinfo("Lưu thành công", "Kết quả đã được lưu vào tệp.")

def generate_random_key():
    random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, random_key)

def copy_to_clipboard(text):
    window.clipboard_clear()
    window.clipboard_append(text)
    messagebox.showinfo("Thành công", "Đã sao chép vào clipboard.")

def transfer_to_input():
    encrypted_text = output_text.get("1.0", tk.END).strip()
    input_text.delete("1.0", tk.END)
    input_text.insert(tk.END, encrypted_text)

# Tạo giao diện người dùng với tkinter
window = tk.Tk()
window.title("Mã hóa và Giải mã văn bản AES-256")
window.geometry("700x700")
window.configure(bg="#282c34")

# Khung nhập khóa AES
key_frame = tk.Frame(window, bg="#282c34")
key_frame.pack(pady=15)
tk.Label(key_frame, text="Khóa AES-256 (32 ký tự):", font=("Arial", 12), fg="white", bg="#282c34").grid(row=0, column=0, padx=5)
key_entry = tk.Entry(key_frame, font=("Arial", 12), width=40, show="*")
key_entry.grid(row=0, column=1, padx=5)
show_key_var = tk.BooleanVar()
show_key_check = tk.Checkbutton(key_frame, text="Hiện khóa", variable=show_key_var, command=toggle_key_visibility, bg="#282c34", fg="white")
show_key_check.grid(row=0, column=2, padx=5)
generate_key_button = tk.Button(key_frame, text="Tạo khóa ngẫu nhiên", command=generate_random_key, bg="#009688", fg="white")
generate_key_button.grid(row=1, column=1, pady=5)

# Khung nhập văn bản
input_frame = tk.Frame(window, bg="#282c34")
input_frame.pack(pady=15)
tk.Label(input_frame, text="Văn bản đầu vào:", font=("Arial", 12), fg="white", bg="#282c34").grid(row=0, column=0, sticky="w", padx=5)
input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, width=70, height=10, font=("Arial", 10))
input_text.grid(row=1, column=0, columnspan=3, pady=5)

# Khung nút chức năng
button_frame = tk.Frame(window, bg="#282c34")
button_frame.pack(pady=20)

# Căn chỉnh các nút theo hàng với khoảng cách đều
tk.Button(button_frame, text="Tải tệp", command=load_file, bg="#009688", fg="white", width=15).grid(row=0, column=0, padx=10, pady=5)
tk.Button(button_frame, text="Mã hóa", command=handle_encryption, bg="#4CAF50", fg="white", width=15).grid(row=0, column=1, padx=10, pady=5)
tk.Button(button_frame, text="Giải mã", command=handle_decryption, bg="#f44336", fg="white", width=15).grid(row=0, column=2, padx=10, pady=5)
tk.Button(button_frame, text="Lưu kết quả", command=save_file, bg="#FF9800", fg="white", width=15).grid(row=0, column=3, padx=10, pady=5)

# Khung xuất kết quả
output_frame = tk.Frame(window, bg="#282c34")
output_frame.pack(pady=15)
tk.Label(output_frame, text="Kết quả:", font=("Arial", 12), fg="white", bg="#282c34").grid(row=0, column=0, sticky="w", padx=5)
output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=70, height=10, font=("Arial", 10))
output_text.grid(row=1, column=0, columnspan=3, pady=5)
tk.Button(output_frame, text="Sao chép kết quả", command=lambda: copy_to_clipboard(output_text.get("1.0", tk.END).strip()), bg="#009688", fg="white", width=20).grid(row=2, column=1, pady=5)
tk.Button(output_frame, text="Chuyển vào ô nhập", command=transfer_to_input, bg="#8E24AA", fg="white", width=20).grid(row=2, column=2, pady=5)

window.mainloop()
