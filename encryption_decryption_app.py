import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import logging
import sys
import traceback

# Set up logging to file that will work in both script and exe mode
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)
# log_file = os.path.join(os.path.expanduser("~"), "email_extraction_log.txt")
log_file = os.path.join(log_dir, "encryption-decryption_log.txt")
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DecryptionApp:
    def __init__(self, root):

        # Global variables
        self.encrypted_file_path = None
        self.tree = None
        self.df = None

        self.root = root
        self.root.title("Decryption Tool")

        self.root.geometry("1000x700")
        self.root.configure(bg="white")

        # Create a frame for the main menu
        self.decryption_frame = tk.Frame(self.root, bg="white")
        self.decryption_frame.pack(pady=20)

        # Label for title
        self.label_title = tk.Label(
            self.decryption_frame, 
            text="Decryption Tool".upper(), 
            bg="white", 
            fg="black", 
            font=("Helvetica", 24, "bold"), 
            width=30, 
            height=2, 
            relief="flat"
        )
        self.label_title.pack(pady=10)

        self.file_button = tk.Button(
            self.decryption_frame,
            text="Open File", 
            command=self.open_file_dialog, 
            bg="#000000", 
            fg="white", 
            font=("Helvetica", 10), 
            width=20, 
            height=1, 
            relief="flat"
        )
        self.file_button.pack(pady=10)
        self.file_button.focus_set()

        # Label for showing selected file path
        self.label_clicked_file_path = tk.Label(self.decryption_frame, text="", bg="white")
        self.label_clicked_file_path.pack(pady=10)

        self.log_message("Decryption Application started!")

    def log_message(self, message):
        """Add message to both UI and log file"""
        # self.result_text.insert(tk.END, message + "\n")
        # self.result_text.see(tk.END)
        logging.info(message)

    def preview_excel(self):
        # Clear any previous preview
        self.log_message("Clearing widgets...")
        for widget in self.preview_frame.winfo_children():
            widget.destroy()

        try:
            self.log_message("Creating preview...")
            # Create self.Treeview to display data
            self.tree = ttk.Treeview(self.preview_frame)
            self.tree["columns"] = list(self.df.columns)
            self.tree["show"] = "headings"

            for col in self.df.columns:
                self.tree.heading(col, text=col)
                self.tree.column(col, width=150, anchor="center")

            for index, row in self.df.iterrows():
                self.tree.insert("", tk.END, values=list(row))

            # Add vertical scrollbar
            vsb = ttk.Scrollbar(self.preview_frame, orient="vertical", command=self.tree.yview)
            vsb.pack(side="right", fill="y")
            self.tree.configure(yscrollcommand=vsb.set)

            # Add horizontal scrollbar
            hsb = ttk.Scrollbar(self.preview_frame, orient="horizontal", command=self.tree.xview)
            hsb.pack(side="bottom", fill="x")
            self.tree.configure(xscrollcommand=hsb.set)

            self.tree.pack(fill="both", expand=True)
            self.log_message("Creating preview succeed")

        except Exception as e:
            self.log_message("Creating preview failed.")
            messagebox.showerror("Error", f"Failed to preview Excel file.\n\n{str(e)}")

    def save_to_excel(self, sheet_name):
        try:
            if not sheet_name:
                messagebox.showwarning("Input Error", "Please enter a sheet name!")
                self.log_message("No sheet_name inputted.")
                return
            
            self.log_message(f"Selecting save directory...")
            save_path = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx")],
                title="Save File"
            )            
            if save_path:
                self.df.to_excel(save_path, sheet_name=sheet_name, index=False)
                self.log_message(f"Saving decrypted file path to {save_path}.")
                messagebox.showinfo("Success", f"File saved successfully.")
                App(self.root)
                self.decryption_frame.destroy()
                
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save the file.\n\n{str(e)}")
            self.log_message("Saving decrypted file failed.")
            return
        
    def saving_options(self):
        self.save_button.destroy()

        # Entry for sheet name
        self.sheet_name_label = tk.Label(
            self.decryption_frame, 
            text="Enter Sheet Name:", 
            bg="white", 
            fg="black", 
            font=("Helvetica", 10)
        )
        self.sheet_name_label.pack(pady=10)

        self.sheet_name_entry = tk.Entry(
            self.decryption_frame, 
            font=("Helvetica", 12), 
            width=30
        )
        self.sheet_name_entry.insert(0, "Sheet1")
        self.sheet_name_entry.pack(pady=10)

        # Save button
        self.save_button = tk.Button(
            self.decryption_frame,
            text="Save", 
            command=lambda: self.save_to_excel(self.sheet_name_entry.get()), 
            bg="#169976", 
            fg="white", 
            font=("Helvetica", 10, "bold"), 
            width=20, 
            height=1, 
            relief="flat"
        )
        self.save_button.pack(pady=10)

    def decrypt_and_preview_df(
            self,
            file_path, 
            password
            ):

        self.log_message("Decrypting File...")
        with open(file_path, "rb") as file:
            full_content = file.read()

        self.salt = full_content[:16] 
        encrypted_data = full_content[16:] 

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )

            secret_key = base64.urlsafe_b64encode(kdf.derive(password))
            cipher = Fernet(secret_key)
            decrypted_data = cipher.decrypt(encrypted_data)
            decrypted_json = decrypted_data.decode()

            self.log_message("Reading json file...")
            self.df = pd.read_json(decrypted_json)

            self.preview_excel()

            self.decryption_key_label.destroy()
            self.decryption_key_entry.destroy()
            self.decrypt_button.destroy()
            self.label_clicked_file_path.destroy()

            # Save button
            self.save_button = tk.Button(
                self.decryption_frame,
                text="Save to Excel", 
                command=lambda: self.saving_options(), 
                bg="#169976", 
                fg="white", 
                font=("Helvetica", 10), 
                width=20, 
                height=1, 
                relief="flat"
            )
            self.save_button.pack(pady=10)

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt the file.\n\n{str(e)}")
            self.log_message("Decryption error!")
            return

    def clicked_file_path(self):
        self.label_clicked_file_path.config(text=f"You have selected:\n{self.encrypted_file_path}")

    def open_file_dialog(self):
        self.log_message("Opening file dialog...")
        self.encrypted_file_path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=[("Binary files", "*.bin")]
        )
        if not self.encrypted_file_path:
            messagebox.showwarning("No File", "No file was selected!")
            self.log_message("No file was selected!")
        else:
            self.clicked_file_path()
            self.file_button.destroy()
            self.log_message(f"Selected file: {self.encrypted_file_path}")

            self.decryption_key_label = tk.Label(
                self.decryption_frame, 
                text="Enter Encryption Key:", 
                bg="white", 
                fg="black", 
                font=("Helvetica", 14, "bold"), 
            )
            self.decryption_key_label.pack(pady=10)

            self.decryption_key_entry = tk.Entry(
                self.decryption_frame, 
                font=("Helvetica", 12), 
                width=30, 
                show="*"
            )
            self.decryption_key_entry.pack(pady=10)

            self.decrypt_button = tk.Button(
                self.decryption_frame,
                text="Decrypt Now", 
                command=lambda: self.decrypt_and_preview_df(
                    self.encrypted_file_path,
                    self.decryption_key_entry.get().encode()
                ), 
                bg="#222222", 
                fg="white", 
                font=("Helvetica", 10), 
                width=20, 
                height=1, 
                relief="flat"
            )
            self.decrypt_button.pack(pady=10)

            # Frame for preview table
            self.preview_frame = tk.Frame(self.decryption_frame, bg="white")
            self.preview_frame.pack(pady=10, fill="both", expand=True)

class EncryptionApp:
    def __init__(
            self,
            root
            ):

        # Global variables
        self.original_file_path = None
        self.sheet_dropdown = None
        self.tree = None
        self.df = None
        self.root = root
        
        self.root.geometry("1000x700")
        self.root.title("Encryption Tool")
        self.root.configure(bg="white")

        # Create a frame for the main menu
        self.encryption_frame = tk.Frame(self.root, bg="white")
        self.encryption_frame.pack(pady=20)

        # Label for title
        self.label_title = tk.Label(
            self.encryption_frame, 
            text="Encryption Tool".upper(), 
            bg="white", 
            fg="black", 
            font=("Helvetica", 24, "bold"), 
            width=30, 
            height=2, 
            relief="flat"
        )
        self.label_title.pack(pady=10)

        # Label for main instruction
        self.label_selectfile = tk.Label(
            self.encryption_frame, 
            text="Select password file (.xlsx):", 
            bg = "white", 
            fg = "black", 
            font=("Helvetica", 10), 
            width=30, height=2, 
            relief="flat"
        )
        self.label_selectfile.pack(pady=0)

        self.file_button = tk.Button(
            self.encryption_frame,
            text="Open File", 
            command=self.open_file_dialog, 
            bg="#102E50", 
            fg="white", 
            font=("Helvetica", 10), 
            width=20, 
            height=1, 
            relief="flat"
        )
        self.file_button.pack(pady=10)
        self.file_button.focus_set()

        self.label_clicked_file_path = tk.Label(self.encryption_frame, text="", bg="white")
        self.label_clicked_file_path.pack(pady=10)

        self.preview_frame = tk.Frame(self.encryption_frame, bg="white")
        self.preview_frame.pack(pady=10, fill="both", expand=True)

        self.log_message("Encryption Application started!")

    def log_message(self, message):
        """Add message to both UI and log file"""
        # self.result_text.insert(tk.END, message + "\n")
        # self.result_text.see(tk.END)
        logging.info(message)

    def encrypt_df(
            self,
            df,
            password
        ):
        
        self.log_message("Encrypting data")
        df_json = df.to_json()
        self.salt = os.urandom(16)  # 16 random bytes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )

        self.secret_key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(self.secret_key)
        self.encrypted_data = self.cipher.encrypt(df_json.encode())  # encode to bytes first

        # Save the encrypted data
        self.log_message(f"Selecting save directory...")
        self.encrypted_file_path = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin")],
            initialfile=os.path.splitext(os.path.basename(self.original_file_path))[0] + ".bin"
        )
        print(self.encrypted_file_path)

        self.log_message(f"Saving encrypted file path to {self.encrypted_file_path}.")
        if not self.encrypted_file_path:
            messagebox.showwarning("Cancelled", "No file was selected for saving.")
            return

        # Write self.salt + encrypted data into file
        try:
            with open(self.encrypted_file_path, "wb") as file:
                file.write(self.salt + self.encrypted_data)

            # Show success message after saving
            messagebox.showinfo("Success", "Data encrypted and saved successfully!")
            App(self.root)
            self.encryption_frame.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save the file.\n\n{str(e)}")
    
    def encrypt_file(self):
        self.log_message("Setting up encryption properties")
        for widget in self.encryption_frame.winfo_children():
            widget.destroy()

        self.root.title("Encryption Properties")

        # Label for title
        self.new_label_title = tk.Label(
            self.encryption_frame, 
            text="Encryption Properties".upper(), 
            bg="white", 
            fg="black", 
            font=("Helvetica", 24, "bold"), 
            width=30, 
            height=2, 
            relief="flat"
        )
        self.new_label_title.pack(pady=10)

        # Create an input text field for entering encryption key
        self.encryption_key_label = tk.Label(
            self.encryption_frame, 
            text="Enter Encryption Key:", 
            bg="white", 
            fg="black", 
            font=("Helvetica", 14, "bold"), 
        )
        self.encryption_key_label.pack(pady=10)

        self.encryption_key_entry = tk.Entry(
            self.encryption_frame, 
            width=30, 
            show="*",
            font=("Helvetica", 12),
        )
        self.encryption_key_entry.pack(pady=10)

        self.encryption_key_entry.focus_set()

        self.encryption_execute_button = tk.Button(
            self.encryption_frame, 
            text="Encrypt Now", 
            command=lambda: self.encrypt_df(self.df, self.encryption_key_entry.get().encode()), 
            bg="#BE3D2A", 
            fg="white", 
            font=("Helvetica", 12), 
            width=20, 
            height=2, 
            relief="flat"
        )
        self.encryption_execute_button.pack(pady=10)


    def preview_excel(self, file_path, sheet_name):

        # Clear any previous preview
        for widget in self.preview_frame.winfo_children():
            widget.destroy()

        try:
            self.df = pd.read_excel(file_path, sheet_name=sheet_name)

            # Create Treeview to display data
            self.tree = ttk.Treeview(self.preview_frame)
            self.tree["columns"] = list(self.df.columns)
            self.tree["show"] = "headings"

            for col in self.df.columns:
                self.tree.heading(col, text=col)
                self.tree.column(col, width=150, anchor="center")

            for index, row in self.df.iterrows():
                self.tree.insert("", tk.END, values=list(row))

            # Add vertical scrollbar
            vsb = ttk.Scrollbar(self.preview_frame, orient="vertical", command=self.tree.yview)
            vsb.pack(side="right", fill="y")
            self.tree.configure(yscrollcommand=vsb.set)

            # Add horizontal scrollbar
            hsb = ttk.Scrollbar(self.preview_frame, orient="horizontal", command=self.tree.xview)
            hsb.pack(side="bottom", fill="x")
            self.tree.configure(xscrollcommand=hsb.set)

            self.tree.pack(fill="both", expand=True)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to preview Excel file.\n\n{str(e)}")

    def on_sheet_selected(self, event):
        selected_sheet = self.sheet_dropdown.get()
        self.preview_excel(self.original_file_path, selected_sheet)

    def clicked_file_path(self):
        self.label_clicked_file_path.config(text=f"You have selected:\n{self.original_file_path}")


    def open_file_dialog(self):
        self.log_message("Opening file dialog...")

        self.original_file_path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=[("Excel files", "*.xlsx")]
        )
        if not self.original_file_path:
            messagebox.showwarning("No File", "No file was selected!")
            self.log_message("No file was selected!")
        else:
            self.clicked_file_path()
            self.log_message(f"Selected file: {self.original_file_path}")
            self.file_button.destroy()
            self.label_selectfile.destroy()

            # Get sheet names
            excel_file = pd.ExcelFile(self.original_file_path)
            sheets = excel_file.sheet_names

            # Create dropdown for selecting sheet
            if self.sheet_dropdown:
                self.sheet_dropdown.destroy()  # remove previous one if exists

            self.sheet_dropdown = ttk.Combobox(self.encryption_frame, values=sheets)
            self.sheet_dropdown.set(sheets[0])  # default to first sheet
            self.sheet_dropdown.bind("<<ComboboxSelected>>", self.on_sheet_selected)
            self.sheet_dropdown.pack(pady=10)

            self.preview_excel(self.original_file_path, sheets[0])

            self.encrypt_button = tk.Button(
                self.encryption_frame, 
                command= self.encrypt_file ,
                text="Encrypt File", 
                bg="#F5C45E", 
                fg = "black", 
                font=("Helvetica", 12), 
                width=20, 
                height=2, 
                relief="flat"
            )
            self.encrypt_button.pack(pady=10)

class App:
    def __init__(self,root):

        self.root = root
        self.root.title("🔐 Encryption - Decryption Tool 🗝️")
        self.root.geometry("1000x700")
        self.root.configure(bg="white")

        # Create a frame for the main menu
        self.main_frame = tk.Frame(self.root, bg="white")
        self.main_frame.pack(pady=20)

        # Title label
        self.label_title = tk.Label(
            self.main_frame, 
            text="Encryption/Decryption Tool".upper(), 
            bg="white", 
            fg="black",
            font=("Helvetica", 24, "bold"), 
            width=30, 
            height=2, 
            relief="flat"
        )
        self.label_title.pack(pady=10)

        self.encryption_button = tk.Button(
            self.main_frame,
            text="🔐 Encryption", 
            command=self.open_encryption_app, 
            bg="#F5C45E", 
            fg="black", 
            font=("Helvetica", 12), 
            width=20, 
            height=2, 
            relief="flat"
        )
        self.encryption_button.pack(pady=10)

        self.encryption_button.focus_set()
        self.decryption_button = tk.Button(
            self.main_frame,
            text="🗝️ Decryption", 
            command=self.open_decryption_app, 
            bg="#169976", 
            fg="white", 
            font=("Helvetica", 12), 
            width=20, 
            height=2, 
            relief="flat"
        )
        self.decryption_button.pack(pady=10)
        self.decryption_button.focus_set()

    def log_message(self, message):
        """Add message to both UI and log file"""
        # self.result_text.insert(tk.END, message + "\n")
        # self.result_text.see(tk.END)
        logging.info(message)
    
    def open_encryption_app(self):
        self.log_message("Encryption Started!")
        self.main_frame.destroy()
        self.encryption_app = EncryptionApp(self.root)

    def open_decryption_app(self):
        self.log_message("Encryption Started!")
        self.main_frame.destroy()
        self.decryption_app = DecryptionApp(self.root)

# Entry point of the application
if __name__ == "__main__":
    try:
        # Log system info
        logging.info(f"Python version: {sys.version}")
        logging.info(f"Running as executable: {getattr(sys, 'frozen', False)}")
        logging.info(f"Application path: {os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))}")

        # Create main window
        root = tk.Tk()
        app = App(root)
        root.mainloop() 
    except Exception as e:
        # Log any exceptions during startup
        logging.critical(f"Critical error during startup: {str(e)}")
        logging.critical(traceback.format_exc())
        
        # Try to show an error message box
        try:
            messagebox.showerror("Critical Error", 
                f"The application encountered a critical error and cannot start.\n\n{str(e)}\n\nCheck the log file: {log_file}")
        except:
            # If even the messagebox fails, write to stderr
            print(f"CRITICAL ERROR: {str(e)}", file=sys.stderr)

        
