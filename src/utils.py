from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pandas as pd
import os, base64
import tempfile
from io import StringIO

def encrypt_df(
        df,
        password
    ):
    
    df_json = df.to_json()
    salt = os.urandom(16)  # 16 random bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    secret_key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher = Fernet(secret_key)
    encrypted_data = cipher.encrypt(df_json.encode())
    return salt, encrypted_data

def decrypt_df(
        file_path, 
        password
        ):

    with open(file_path, "rb") as file:
        full_content = file.read()

    salt = full_content[:16] 
    encrypted_data = full_content[16:] 

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    secret_key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher = Fernet(secret_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_json = decrypted_data.decode()

    df = pd.read_json(StringIO(decrypted_json))
    return df
