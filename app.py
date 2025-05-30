import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pandas as pd
import os, base64
import tempfile, io

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

    try:
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

        df = pd.read_json(decrypted_json)
        return df

    except Exception as e:
        st.error(f"Decryption failed: {e}")
        return

st.markdown(
    """
    <style>
    /* Background */
    .stApp {
        background-color: #4B352A;
        color: #EAEAEA;
        font-family: 'Segoe UI', sans-serif;
    }

    /* Title */
    .main-title {
        text-align: center;
        color: #FBDB93;
        font-size: 42px;
        font-weight: bold;
        margin-top: 10px;
        margin-bottom: 0px;
    }

    /* Subtitle */
    .subtitle {
        text-align: center;
        color: #D5E8C4;
        font-size: 18px;
        margin-top: 0px;
        margin-bottom: 30px;
    }

    /* Center and enlarge radio group */
    section[data-testid="stRadio"] > div {
        display: flex;
        justify-content: center;
        gap: 40px;
        margin-bottom: 40px;
        margin-top: 10px;
    }

    /* Enlarge and style radio options */
    section[data-testid="stRadio"] label {
        font-size: 24px;
        padding: 20px 30px;
        border-radius: 12px;
        background-color: #5C4033;
        color: #F0F2BD;
        border: 2px solid #D5E8C4;
        transition: all 0.3s ease;
        cursor: pointer;
    }

    /* Highlight selected */
    section[data-testid="stRadio"] label[data-selected="true"] {
        background-color: #B2CD9C;
        color: #4B352A;
        border-color: #F0F2BD;
        font-weight: bold;
    }

    /* Hide the native radio input */
    section[data-testid="stRadio"] input {
        display: none;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# Render title and subtitle
st.markdown("<div class='main-title'>🔐 Cryptora: Secure Data Storage App</div>", unsafe_allow_html=True)
st.markdown(
    """
    <div class='subtitle'>
        Easily encrypt and decrypt your sensitive files.<br>
        Your data, secured — whether storing or retrieving.
    </div>
    """, 
    unsafe_allow_html=True
)

# Horizontal, styled radio buttons
mode = st.radio("📁 Select Mode:", ["🔒 Encryption", "🔓 Decryption"], horizontal=True)

st.markdown(
    """
    <div style="
        background-color: #F0F2BD;
        color: #4B352A;
        padding: 15px 25px;
        border-radius: 10px;
        border-left: 6px solid #B2CD9C;
        margin-top: 20px;
        font-size: 16px;
    ">
        ⚠️ <strong>Privacy Disclaimer:</strong> This application runs entirely on your device. <br>
        No data is uploaded, stored, or shared — your files and keys remain 100% private and secure.
    </div>
    """,
    unsafe_allow_html=True
)

if mode == "🔒 Encryption":
    st.markdown("## 🔒 Encrypt Data")

    upload_file_encrypted = st.file_uploader("📤 Upload a excel file to encrypt", type=["xlsx", "xls"])
    if 'process_encryption' not in st.session_state:
        st.session_state.process_encryption = False

    if upload_file_encrypted is not None:
        st.session_state.process_encryption = True
    else:
        st.info("👆 Upload a .xlsx or .xls file here.")
    
    if st.session_state.process_encryption:
        excel_file = pd.ExcelFile(upload_file_encrypted)
        sheets = excel_file.sheet_names
        selected_sheet = st.selectbox("Select a sheet:", sheets)
        df = pd.read_excel(upload_file_encrypted, sheet_name=selected_sheet)
        st.dataframe(df)

        encryption_key_entry = st.text_input("🗝️ Enter encryption key:", type="password")

        if st.button("Encrypt"):
            try:
                salt, encrypted_data = encrypt_df(df, encryption_key_entry.encode())
                st.session_state.encrypted_data = encrypted_data
                st.session_state.salt = salt
                st.success("✅ Data encrypted successfully!")
                
                if 'encrypted_data' in st.session_state and 'salt' in st.session_state:
                    download_bytes = st.session_state.salt + st.session_state.encrypted_data
                    file_name = os.path.splitext(upload_file_encrypted.name)[0]
                    st.download_button(
                        label="📥 Download Encrypted File",
                        data=download_bytes,
                        file_name=f"{file_name}.bin"
                    )
            except Exception as e:
                st.error(f"Encryption failed: {e}")
                st.session_state.process_encryption = False
elif mode == "🔓 Decryption":
    st.markdown("## 🔓 Decrypt Data")

    upload_file_decrypted = st.file_uploader("📤 Upload a .bin file to decrypt", type=["bin"])
    decryption_key_entry = st.text_input("🔑 Enter decryption key:", type="password")

    if 'process_decryption' not in st.session_state:
        st.session_state.process_decryption = False

    if upload_file_decrypted is not None and decryption_key_entry:
        if st.button("🚀 Decrypt"):
            st.session_state.process_decryption = True
    else:
        st.info("👆 Upload a .bin file and enter your key to start decryption.")

    if st.session_state.process_decryption:
        try:
            file_bytes = upload_file_decrypted.read()
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(file_bytes)
                tmp_file_path = tmp_file.name

            decrypted_df = decrypt_df(tmp_file_path, decryption_key_entry.encode())

            if decrypted_df is not None:
                st.success("✅ Data decrypted successfully!")
                st.session_state.decrypted_data = decrypted_df
                st.dataframe(decrypted_df)

                # Ask for output Excel details
                file_name = os.path.splitext(upload_file_decrypted.name)[0]
                sheet_name = st.text_input("📄 Enter sheet name for Excel file:")

                # Prepare download
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    decrypted_df.to_excel(writer, index=False, sheet_name=sheet_name)
                output.seek(0)

                if output is not None and sheet_name:
                    st.download_button(
                        label="📥 Download Decrypted Excel File",
                        data=output,
                        file_name=f"{file_name}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                else:
                    st.info("👆 Please provide a valid sheet name for the Excel file.")
            else:
                st.error("❌ Decryption failed. Please check your key or file.")

        except Exception as e:
            st.error(f"⚠️ An error occurred during decryption: {e}")
            st.session_state.process_decryption = False

        


            


    