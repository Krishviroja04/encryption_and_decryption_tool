import streamlit as st
import numpy as np
import random
import string

# ---------------- Caesar Cipher ----------------
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ---------------- Playfair Cipher ----------------
def generate_playfair_matrix(key):
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = key + "".join([c for c in alphabet if c not in key])
    return np.array(list(matrix)).reshape(5,5)

def playfair_encrypt_pair(pair, matrix):
    pos = {matrix[i,j]: (i,j) for i in range(5) for j in range(5)}
    a, b = pair
    ra, ca = pos[a]; rb, cb = pos[b]
    if ra == rb:  
        return matrix[ra,(ca+1)%5] + matrix[rb,(cb+1)%5]
    elif ca == cb:  
        return matrix[(ra+1)%5,ca] + matrix[(rb+1)%5,cb]
    else:  
        return matrix[ra,cb] + matrix[rb,ca]

def playfair_decrypt_pair(pair, matrix):
    pos = {matrix[i,j]: (i,j) for i in range(5) for j in range(5)}
    a, b = pair
    ra, ca = pos[a]; rb, cb = pos[b]
    if ra == rb:  
        return matrix[ra,(ca-1)%5] + matrix[rb,(cb-1)%5]
    elif ca == cb:  
        return matrix[(ra-1)%5,ca] + matrix[(rb-1)%5,cb]
    else:  
        return matrix[ra,cb] + matrix[rb,ca]

def playfair_encrypt(text, key):
    if not key: return "Please enter a keyword"
    matrix = generate_playfair_matrix(key)
    text = "".join([c for c in text.upper().replace("J","I") if c.isalpha()])
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i+1 < len(text):
            b = text[i+1]
            if a == b:
                pairs.append((a,"X"))
                i += 1
            else:
                pairs.append((a,b))
                i += 2
        else:
            pairs.append((a,"X"))
            i += 1
    return "".join(playfair_encrypt_pair(p,matrix) for p in pairs)

def playfair_decrypt(text, key):
    if not key: return "Please enter a keyword"
    matrix = generate_playfair_matrix(key)
    text = "".join([c for c in text.upper().replace("J","I") if c.isalpha()])
    if len(text) % 2 != 0: return "Invalid Ciphertext length"
    
    pairs = [(text[i], text[i+1]) for i in range(0, len(text), 2)]
    decrypted_text = "".join(playfair_decrypt_pair(p, matrix) for p in pairs)
    
    final_result = ""
    for i in range(len(decrypted_text)):
        if i > 0 and i < len(decrypted_text) - 1:
            if decrypted_text[i] == 'X' and decrypted_text[i-1] == decrypted_text[i+1]:
                continue # Skip the X
        final_result += decrypted_text[i]
    
    return final_result.rstrip('X')


# ---------------- Hill Cipher (Improved Math) ----------------
def modInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

def mod_inverse_matrix(matrix, modulus=26):
    # For 2x2 matrix: [[a, b], [c, d]]
    a, b, c, d = matrix[0,0], matrix[0,1], matrix[1,0], matrix[1,1]
    det = (a*d - b*c) % modulus
    det_inv = modInverse(det, modulus)
    if det_inv == -1:
        return None
    # Adjugate matrix mod 26
    inv_matrix = np.array([[d, -b], [-c, a]]) * det_inv
    return inv_matrix % modulus

def hill_encrypt(text, key_matrix):
    text = "".join([c for c in text.upper() if c.isalpha()])
    while len(text) % 2 != 0:
        text += "X"
    result = ""
    for i in range(0, len(text), 2):
        vec = np.array([ord(text[i])-65, ord(text[i+1])-65])
        enc = np.dot(key_matrix, vec) % 26
        result += chr(int(enc[0])+65) + chr(int(enc[1])+65)
    return result

def hill_decrypt(cipher, key_matrix):
    inv_matrix = mod_inverse_matrix(key_matrix, 26)
    if inv_matrix is None: return "Matrix is not invertible!"
    cipher = "".join([c for c in cipher.upper() if c.isalpha()])
    result = ""
    for i in range(0, len(cipher), 2):
        vec = np.array([ord(cipher[i])-65, ord(cipher[i+1])-65])
        dec = np.dot(inv_matrix, vec) % 26
        result += chr(int(dec[0])+65) + chr(int(dec[1])+65)
    
    # This line removes the padding 'X' at the very end
    return result.rstrip('X')


# ---------------- One-Time Pad ----------------
def generate_key(length):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def otp_encrypt(message, key):
    message = "".join([c for c in message.upper() if c.isalpha()])
    key = "".join([c for c in key.upper() if c.isalpha()])
    if len(key) < len(message): return "Key is too short!"
    result = ""
    for m,k in zip(message,key):
        result += chr(((ord(m)-65)+(ord(k)-65))%26 + 65)
    return result

def otp_decrypt(cipher, key):
    cipher = "".join([c for c in cipher.upper() if c.isalpha()])
    key = "".join([c for c in key.upper() if c.isalpha()])
    if len(key) < len(cipher): return "Key is too short!"
    result = ""
    for c,k in zip(cipher,key):
        result += chr(((ord(c)-65)-(ord(k)-65))%26 + 65)
    return result


# ---------------- Streamlit GUI ----------------
st.set_page_config(page_title="Cipher GUI", layout="wide")
st.title("🔐 Substitution Cipher GUI")

cipher_choice = st.sidebar.radio("Select Cipher:", 
                                 ["Caesar Cipher", "Playfair Cipher", "Hill Cipher", "One-Time Pad"])

col1, col2 = st.columns(2)

if cipher_choice == "Caesar Cipher":
    with col1:
        st.header("Encrypt")
        msg = st.text_area("Message to encrypt:", key="caesar_enc")
        shift = st.number_input("Shift:", min_value=0, max_value=25, value=3, key="caesar_enc_shift")
        if st.button("Encrypt", key="caesar_enc_btn"):
            st.success(caesar_encrypt(msg, shift))
    with col2:
        st.header("Decrypt")
        msg = st.text_area("Message to decrypt:", key="caesar_dec")
        shift = st.number_input("Shift:", min_value=0, max_value=25, value=3, key="caesar_dec_shift")
        if st.button("Decrypt", key="caesar_dec_btn"):
            st.success(caesar_decrypt(msg, shift))

elif cipher_choice == "Playfair Cipher":
    with col1:
        st.header("Encrypt")
        msg = st.text_area("Message to encrypt:", key="playfair_enc")
        key = st.text_input("Keyword:", key="playfair_key_enc")
        if st.button("Encrypt", key="playfair_enc_btn"):
            st.success(playfair_encrypt(msg, key))
    with col2:
        st.header("Decrypt")
        msg = st.text_area("Message to decrypt:", key="playfair_dec")
        key = st.text_input("Keyword:", key="playfair_key_dec")
        if st.button("Decrypt", key="playfair_dec_btn"):
            st.success(playfair_decrypt(msg, key))

elif cipher_choice == "Hill Cipher":
    with col1:
        st.header("Encrypt")
        msg = st.text_area("Message to encrypt:", key="hill_enc")
        st.write("Using fixed key matrix [[3,3],[2,5]]")
        key_matrix = np.array([[3,3],[2,5]])
        if st.button("Encrypt", key="hill_enc_btn"):
            st.success(hill_encrypt(msg, key_matrix))
    with col2:
        st.header("Decrypt")
        msg = st.text_area("Message to decrypt:", key="hill_dec")
        st.write("Using fixed key matrix [[3,3],[2,5]]")
        key_matrix = np.array([[3,3],[2,5]])
        if st.button("Decrypt", key="hill_dec_btn"):
            st.success(hill_decrypt(msg, key_matrix))

elif cipher_choice == "One-Time Pad":
    with col1:
        st.header("Encrypt")
        msg = st.text_area("Message to encrypt:", key="otp_enc")
        if st.button("Generate Key", key="otp_key_btn"):
            st.session_state['otp_key'] = generate_key(len(msg))
            st.info(f"Generated Key: {st.session_state['otp_key']}")
        
        current_key = st.session_state.get('otp_key', "")
        key = st.text_input("Key:", value=current_key, key="otp_key_enc")
        
        if st.button("Encrypt", key="otp_enc_btn"):
            st.success(otp_encrypt(msg, key))
    with col2:
        st.header("Decrypt")
        msg = st.text_area("Message to decrypt:", key="otp_dec")
        key = st.text_input("Key:", value=st.session_state.get('otp_key', ""), key="otp_key_dec")
        if st.button("Decrypt", key="otp_dec_btn"):
            st.success(otp_decrypt(msg, key))
