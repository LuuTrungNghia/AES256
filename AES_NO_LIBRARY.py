import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import os

# -----------------------------
# AES Constants
# -----------------------------

# S-box cho bước SubBytes trong AES
sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# -----------------------------
# AES Helper Functions
# -----------------------------

# Hàm thêm padding vào dữ liệu
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

# Hàm xóa padding sau khi giải mã
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# -----------------------------
# AES Key Expansion
# -----------------------------

# Hàm mở rộng khóa
def key_expansion(key):
    Nk = 8  # Number of key words (AES-256)
    Nr = 14  # Number of rounds (AES-256)
    Nb = 4  # Number of columns in the state

    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    expanded_key = [list(key[i:i + 4]) for i in range(0, len(key), 4)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = expanded_key[i - 1]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= Rcon[(i // Nk) - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = [sbox[b] for b in temp]
        expanded_key.append([
            expanded_key[i - Nk][j] ^ temp[j] for j in range(4)
        ])
    return [expanded_key[i:i + Nb] for i in range(0, len(expanded_key), Nb)]

# -----------------------------
# AES Core Functions
# -----------------------------

def add_round_key(state, key):
    return [[state[row][col] ^ key[row][col] for col in range(4)] for row in range(4)]

def sub_bytes(state):
    return [[sbox[byte] for byte in row] for row in state]

def sub_bytes_inv(state):
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return [[inv_sbox[byte] for byte in row] for row in state]

def shift_rows(state):
    return [state[i][i:] + state[i][:i] for i in range(4)]

def shift_rows_inv(state):
    return [
        state[0],
        state[1][3:] + state[1][:3],
        state[2][2:] + state[2][:2],
        state[3][1:] + state[3][:1]
    ]

def mix_columns(state):
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    for i in range(4):
        a = state[0][i], state[1][i], state[2][i], state[3][i]
        state[0][i] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ gmul(a[2], 1) ^ gmul(a[3], 1)
        state[1][i] = gmul(a[0], 1) ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ gmul(a[3], 1)
        state[2][i] = gmul(a[0], 1) ^ gmul(a[1], 1) ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        state[3][i] = gmul(a[0], 3) ^ gmul(a[1], 1) ^ gmul(a[2], 1) ^ gmul(a[3], 2)
    return state

def mix_columns_inv(state):
    def gmul_inv(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    for i in range(4):
        a = state[0][i], state[1][i], state[2][i], state[3][i]
        state[0][i] = gmul_inv(a[0], 0x0E) ^ gmul_inv(a[1], 0x0B) ^ gmul_inv(a[2], 0x0D) ^ gmul_inv(a[3], 0x09)
        state[1][i] = gmul_inv(a[0], 0x09) ^ gmul_inv(a[1], 0x0E) ^ gmul_inv(a[2], 0x0B) ^ gmul_inv(a[3], 0x0D)
        state[2][i] = gmul_inv(a[0], 0x0D) ^ gmul_inv(a[1], 0x09) ^ gmul_inv(a[2], 0x0E) ^ gmul_inv(a[3], 0x0B)
        state[3][i] = gmul_inv(a[0], 0x0B) ^ gmul_inv(a[1], 0x0D) ^ gmul_inv(a[2], 0x09) ^ gmul_inv(a[3], 0x0E)
    return state

# -----------------------------
# AES Encryption and Decryption
# -----------------------------

# Hàm mã hóa từng khối 16 byte
def encrypt_block(block, round_keys):
    state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]
    state = add_round_key(state, round_keys[0])
    for round in range(1, 14):  # AES-256 có 14 vòng
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[14])
    return bytes(sum(state, []))

# Hàm giải mã từng khối 16 byte
def decrypt_block(block, round_keys):
    state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]
    state = add_round_key(state, round_keys[14])
    state = shift_rows_inv(state)
    state = sub_bytes_inv(state)
    for round in range(13, 0, -1):  # AES-256 có 14 vòng
        state = add_round_key(state, round_keys[round])
        state = mix_columns_inv(state)
        state = shift_rows_inv(state)
        state = sub_bytes_inv(state)
    state = add_round_key(state, round_keys[0])
    return bytes(sum(state, []))

# -----------------------------
# Encryption and Decryption of Data
# -----------------------------

# Hàm mã hóa toàn bộ văn bản
def encrypt_data(data, key):
    key = pad(key)[:32]  # Đảm bảo khóa là 256-bit
    round_keys = key_expansion(key)
    data = pad(data)
    encrypted = b''.join(encrypt_block(data[i:i + 16], round_keys) for i in range(0, len(data), 16))
    return encrypted

# Hàm giải mã toàn bộ văn bản
def decrypt_data(data, key):
    key = pad(key)[:32]  # Đảm bảo khóa là 256-bit
    round_keys = key_expansion(key)
    decrypted = b''.join(decrypt_block(data[i:i + 16], round_keys) for i in range(0, len(data), 16))
    return unpad(decrypted)

# Giao diện người dùng với Tkinter
class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption/Decryption")
        self.root.geometry("700x750")  # Kích thước cửa sổ lớn hơn
        self.root.config(bg="#f4f7fc")  # Màu nền sáng cho cửa sổ
        self.create_widgets()

    def create_widgets(self):
        # Tạo frame chứa các widget
        frame = tk.Frame(self.root, bg="#ffffff", bd=10, relief="solid")
        frame.pack(padx=30, pady=30, fill=tk.BOTH, expand=True)

        # Nhập khóa (256-bit)
        tk.Label(frame, text="Key (256-bit):", font=("Helvetica", 14), bg="#ffffff").pack(anchor="w", pady=10)
        self.key_entry = tk.Entry(frame, width=50, font=("Helvetica", 12), bd=2, relief="groove")
        self.key_entry.pack(pady=10)

        # Nhập văn bản cần mã hóa/giải mã
        tk.Label(frame, text="Input Text:", font=("Helvetica", 14), bg="#ffffff").pack(anchor="w", pady=10)
        self.input_text = tk.Text(frame, height=12, width=60, font=("Helvetica", 12), bd=2, relief="groove")  # Thêm border
        self.input_text.pack(pady=10)

        # Tạo một frame riêng để chứa các nút
        button_frame = tk.Frame(frame, bg="#ffffff")
        button_frame.pack(pady=20)

        # Nút mã hóa
        self.encrypt_button = tk.Button(button_frame, text="Encrypt", font=("Helvetica", 12), bg="#4CAF50", fg="white", relief="raised", command=self.encrypt_text)
        self.encrypt_button.pack(side=tk.LEFT, padx=15)

        # Nút giải mã
        self.decrypt_button = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 12), bg="#2196F3", fg="white", relief="raised", command=self.decrypt_text)
        self.decrypt_button.pack(side=tk.LEFT, padx=15)

        # Nút Clear
        self.clear_button = tk.Button(button_frame, text="Clear", font=("Helvetica", 12), bg="#FFC107", fg="white", relief="raised", command=self.clear_text)
        self.clear_button.pack(side=tk.LEFT, padx=15)

        # Hiển thị kết quả (Output)
        tk.Label(frame, text="Output:", font=("Helvetica", 14), bg="#ffffff").pack(anchor="w", pady=10)
        self.output_text = tk.Text(frame, height=12, width=60, font=("Helvetica", 12), bd=2, relief="groove")  # Thêm border
        self.output_text.pack(pady=10)

    def encrypt_text(self):
        key = self.key_entry.get().encode("utf-8")
        text = self.input_text.get("1.0", tk.END).strip().encode("utf-8")

        if len(key) != 32:
            messagebox.showerror("Error", "The key must be 256 bits (32 bytes).")
            return

        try:
            encrypted = encrypt_data(text, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", encrypted.hex())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        key = self.key_entry.get().encode("utf-8")
        encrypted_hex = self.input_text.get("1.0", tk.END).strip()

        if len(key) != 32:
            messagebox.showerror("Error", "The key must be 256 bits (32 bytes).")
            return

        try:
            encrypted_data = bytes.fromhex(encrypted_hex)
            decrypted = decrypt_data(encrypted_data, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decrypted.decode("utf-8", errors="ignore"))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def clear_text(self):
        """Clear all fields."""
        self.key_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()