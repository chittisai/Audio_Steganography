import os
import wave
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask import jsonify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import smtplib



app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'wav'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download(filename):
    output_folder = 'output'
    return send_from_directory(output_folder, filename, as_attachment=True)

@app.route('/encode', methods=['POST'])
def encode():
    if 'en-fileInput' not in request.files or 'en-secret-msg' not in request.form or 'en-email' not in request.form:
        return redirect(url_for('index'))

    audio = request.files['en-fileInput']
    message = request.form.get('en-secret-msg')
    email = request.form.get('en-email')

    key = generate_key()
    send_email(email, key)
    message = encrypt_AES(message, key)

    filename = "upload"    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename_with_timestamp = f"{timestamp}_{filename}"
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    audio.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_timestamp))
    
    download_file = encode_aud_data(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_timestamp), message)
    download_link = url_for('download', filename=os.path.basename(download_file))

    # Return the download link as JSON response
    return jsonify({'download_link': download_link})

@app.route('/decode', methods=['POST'])
def decode():
    if 'de-fileInput' not in request.files or 'de-key' not in request.form:
        return redirect(url_for('index'))

    audio = request.files['de-fileInput']
    key = request.form.get('de-key')

    filename = "upload"
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    filename_with_timestamp = f"{timestamp}_{filename}"
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        
    audio.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_timestamp))
    
    encrypted_message = decode_aud_data(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_timestamp))

    message = decrypt_AES(encrypted_message, key)

    return render_template('index.html', message=message, display_message = True)  # Render the template and pass the message

def send_email(mail, key):
    sender_email = 'chittisai.t@gmail.com'
    receiver_email = mail
    password = "your_password"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Key for your Decoding"

    body = "This is your key: " + key
    msg.attach(MIMEText(body, 'plain'))

    

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    text = msg.as_string()
    server.sendmail(sender_email, receiver_email, text)
    server.quit()

def generate_key():
    key_bytes = get_random_bytes(16)  # 128-bit key
    return base64.b64encode(key_bytes).decode('utf-8')

def encrypt_AES(plaintext, key):
    key_bytes = base64.b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ciphertext

def decrypt_AES(ciphertext, key):
    try:
        key_bytes = base64.b64decode(key)
        iv = base64.b64decode(ciphertext[:24]) # 16 bytes IV (encoded in base64)
        ciphertext = base64.b64decode(ciphertext[24:]) # ciphertext (encoded in base64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
        return plaintext
    except Exception as e:
        return "The provided key is incorrect."

def encode_aud_data(audio, message):
    song = wave.open(audio, mode='rb') #opening the cover audio
    frame_bytes = bytearray(list(song.readframes(song.getnframes()))) 
    data = message + '*******'  # adding delimiter at the end of the message
    # converting text to bit array
    result = []
    for c in data: 
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits  # modify the carrier byte according to the text message
        result.extend([int(b) for b in bits])

    j = 0
    for i in range(0,len (result),1):
        res = bin(frame_bytes [j])[2:].zfill(8) 
        if res[len(res)-4] == result[i]:
            frame_bytes[j] = (frame_bytes[j] & 253)
        else:
            frame_bytes[j] = (frame_bytes [j] & 253) | 2 #we perform logical and between each frame byte and 253 #and then doing or operator with 2 to set 2nd lsb to 1
            frame_bytes[j] = (frame_bytes[j] & 254) | result[i] #again we perform logical and between each frame byte and 254 #which sets lsb to 0 then we do or operation with message bit #to store it in lsb
        j = j + 1

    frame_modified = bytes(frame_bytes)

    # Ensure the 'output' folder exists, if not create it
    output_folder = 'output'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Constructing the output filename with timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"{timestamp}-output.wav"
    output_filepath = os.path.join(output_folder, filename)

    # Writing bytes into a new wave audio file
    with wave.open(output_filepath, 'wb') as fd:
        fd.setparams(song.getparams()) 
        fd.writeframes(frame_modified)

    song.close()

    return output_filepath

def decode_aud_data(nameoffile):
    # Opening the stego audio

    song = wave.open(nameoffile, mode='rb')

    # Reading each frame and converting to byte array for storing the extracted bit
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    # Counter and variable for storing the extracted bits
    extracted = ""
    p = 0

    # Iterate through each frame byte
    for i in range(len(frame_bytes)):
        if p == 1:
            break  # Check if the recovered message has reached the delimiter (end point), then break

        # Convert the frame byte to its 8-bit binary format
        res = bin(frame_bytes[i])[2:].zfill(8)

        # Check 2nd LSB; if it is 0, add the 4th LSB to extracted, else add LSB
        if res[len(res)-2] == '0':
            extracted += res[len(res)-4]
        else:
            extracted += res[len(res)-1]

        # Convert the decoded bits to characters

        all_bytes = [extracted[i: i+8] for i in range(0, len(extracted), 8)]
        decoded_data = ""

        # Iterate through each byte and check for the delimiter
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data[-5:] == '*****':
                # Checking if we have reached the delimiter which is "*****"
                # Print the hidden message, separating the delimiter
                return decoded_data[:-5]
            
                # Change counter to 1
                p = 1
                break




if __name__ == '__main__':
    app.run(debug=True)
