from flask import Flask, render_template, request
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

# AES requires a key of 16, 24, or 32 bytes
SECRET_KEY = b'mysecretpassword'  # 16 bytes key

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def encrypt(text):
    raw = pad(text).encode('utf-8')
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(raw)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(enc_text):
    enc = base64.b64decode(enc_text)
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(enc).decode('utf-8')
    return unpad(decrypted)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        action = request.form["action"]
        text = request.form["text"]
        if action == "encrypt":
            result = encrypt(text)
        elif action == "decrypt":
            result = decrypt(text)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
