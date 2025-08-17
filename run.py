import os
import sys

if __name__ == "__main__":
    option = sys.argv[1] if len(sys.argv) > 1 else "streamlit"

    if option == "streamlit":
        os.system("streamlit run src/streamlit_app.py")
    elif option == "tkinter":
        os.system("python src/tkinter_app.py")
    else:
        print("Usage: python run.py [streamlit|tkinter]")
