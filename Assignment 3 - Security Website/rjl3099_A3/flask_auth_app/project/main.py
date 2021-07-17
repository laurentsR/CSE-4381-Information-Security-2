from flask import Flask, render_template, request, flash, redirect, session, url_for, Blueprint, send_from_directory, send_file
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import os
import base64
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.context import CryptContext
from werkzeug.utils import secure_filename
import zipfile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from io import BytesIO
import hashlib

pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

app = Flask(__name__)
mysql = MySQL(app)

main = Blueprint('main', __name__)

@main.route('/dashboard/')
def dashboard():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('dashboard.html')

@main.route('/logout/')
def logout():
    session.pop('username')
    return redirect('/')

@main.route('/account/')
def account():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('account.html')

@main.route('/account/', methods=['POST'])
def changePassword():
    if request.method == "POST":
        username = session.get('username')
        if username is None:
            flash(f"Please log in.")
            return redirect('/')
        else:
            details = request.form
            oldPassword = details['oldPassword']
            newPassword = details['newPassword']
            matchPassword = details['matchPassword']

            # Grab password from DB to compare
            cur = mysql.connection.cursor()
            cur.execute("SELECT (password) FROM users WHERE username = %s", [username])
            row = cur.fetchone()
            dbPass = row[0]
            mysql.connection.commit()
            cur.close()

            # compare entered pass and db pass
            if(pwd_context.verify(oldPassword, dbPass)):
                if(newPassword == matchPassword):
                    hashedPassword = pwd_context.encrypt(newPassword)
                    try:
                        cur = mysql.connection.cursor()
                        cur.execute("UPDATE users SET password = %s WHERE username = %s", (hashedPassword, username))
                        mysql.connection.commit()
                        cur.close()
                        flash(f"Password updated successfully!")
                        return redirect('/account/')
                    except:
                        flash(f"Unexpected error, please try again.")
                        return redirect('/account/')
                else:
                    flash(f"New passwords do not match. Please try again.")
                    return redirect('/account/')
            else:
                flash(f"Incorrect password, please try again.")
                return redirect('/account/')

@main.route('/delete/')
def deleteAccount():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        # Delete account from db
        try:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM users WHERE username = %s", [username])
            mysql.connection.commit()
            cur.close()
            session.pop('username')
            flash(f"Account deleted successfully.")
            return redirect('/')
        except:
            flash(f"Unexpected error when deleting account, please try again.")
            return redirect('/account/')

@main.route('/generatePassword/')
def generatePassword():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        chars = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*"
        length = 32
        generatedPassword = ''
        for i in range(length):
            generatedPassword += random.choice(chars)
        return render_template('generatedPassword.html', generatedPassword=generatedPassword)

@main.route('/fileManagement/')
def fileManagement():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('fileManagement.html')

@main.route('/upload/')
def upload():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('upload.html')

@main.route('/upload/', methods=['POST'])
def uploadFile():
    if request.method == 'POST':
      username = session.get('username')
      if username is None:
          flash(f"Please log in.")
          return redirect('/')
      else:
          try:
              f = request.files['file']
              cur = mysql.connection.cursor()
              cur.execute("INSERT INTO files (filename, owner) VALUES (%s, %s)", [f.filename, username])
              mysql.connection.commit()
              cur.close()
              filenameSecure = secure_filename(f.filename)
              f.save(os.path.join('project/Flask_Uploads/', filenameSecure))
              flash(f"File uploaded successfully")
              return redirect('/fileManagement/')
          except:
              flash(f"Unexpected error when uploading file, please try again. Remember: Duplicate files cannot be stored on the system.")
              return redirect('/upload/')

@main.route('/download/')
def download():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        cur = mysql.connection.cursor()
        cur.execute("SELECT filename FROM files WHERE owner = %s", [username])
        data = cur.fetchall()
        mysql.connection.commit()
        cur.close()
        return render_template('download.html', data=data)

@main.route('/download/<path:filename>', methods=['GET'])
def downloadFile(filename):
    return send_file('Flask_Uploads/'+filename, as_attachment=True)

@main.route('/encrypt/')
def encrypt():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('encrypt.html')

@main.route('/encrypt/symmetric/')
def symmetric():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('symmetric.html')

@main.route('/encrypt/symmetric/', methods=["POST"])
def symmetricEncryption():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        try:
            f = request.files['file']
            key = Fernet.generate_key()
            k = Fernet(key)
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO encryptions (filename, type, symmetric) VALUES (%s, %s, %s)", [f.filename, "symmetric", key])
            mysql.connection.commit()
            cur.close()
            filenameSecure = secure_filename(f.filename)
            f.save(os.path.join('project/Encrypted_Files/', filenameSecure))

            with open('project/Encrypted_Files/'+filenameSecure, "rb") as file:
                fileData = file.read()

            encryptedData = k.encrypt(fileData)

            with open('project/Encrypted_Files/'+filenameSecure, "wb") as file:
                file.write(encryptedData)
            return send_file('Encrypted_Files/'+f.filename, as_attachment=True)
        except:
            flash(f"Unexpected error when uploading file, please try again.")
            return redirect('/encrypt/symmetric/')

@main.route('/encrypt/asymmetric/')
def asymmetric():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('asymmetric.html')

@main.route('/encrypt/asymmetric/', methods=["POST"])
def asymmetricEncryption():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        try:
            keyPair = RSA.generate(3076)
            public_key = keyPair.publickey()
            pubKeyPEM = public_key.exportKey()
            publicKeySerialized = pubKeyPEM.decode('ascii')

            privateKeyPEM = keyPair.exportKey()
            privateKeySerialized = privateKeyPEM.decode('ascii')

            f = request.files['file']
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO encryptions (filename, type, public) VALUES (%s, %s, %s)", [f.filename, "asymmetric", publicKeySerialized])
            mysql.connection.commit()
            cur.close()

            filenameSecure = secure_filename(f.filename)
            f.save(os.path.join('project/Encrypted_Files/', filenameSecure))

            with open('project/Encrypted_Files/'+filenameSecure, "rb") as file:
                message = file.read()
            file.close()

            encryptor = PKCS1_OAEP.new(public_key)
            encryptedData = encryptor.encrypt(message)

            with open('project/Encrypted_Files/'+filenameSecure, "wb") as file:
                file.write(encryptedData)
            file.close()

            with open('project/keys/PK'+filenameSecure, "wb") as file:
                file.write(privateKeyPEM)
            file.close()

            # Zip the encrypted file with the private key and return to user
            memory_file = BytesIO()
            with zipfile.ZipFile(memory_file, 'w') as zf:
                files = ['project/Encrypted_Files/'+f.filename, 'project/keys/PK'+f.filename]
                for individualFile in files:
                    data = zipfile.ZipInfo(individualFile['fileName'])
                    data.date_time = time.localtime(time.time())[:6]
                    data.compress_type = zipfile.ZIP_DEFLATED
                    zf.writestr(data, individualFile['fileData'])
            zf.close()
            memory_file.seek(0)
            return send_file(memory_file, attachment_filename='capsule.zip', as_attachment=True)

        except:
            flash(f"Unexpected error when uploading file, please try again.")
            return redirect('/encrypt/asymmetric/')

@main.route('/decrypt/')
def decrypt():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('decrypt.html')

@main.route('/decrypt/symmetric/')
def symmetricD():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('symmetricD.html')

@main.route('/decrypt/symmetric/', methods=["POST"])
def symmetricDecryption():
    # save owner information to db
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        try:
            f = request.files['file']
            cur = mysql.connection.cursor()
            cur.execute("SELECT symmetric FROM encryptions WHERE filename = %s AND type = %s", [f.filename, "symmetric"])
            mysql.connection.commit()
            row = cur.fetchone()
            key = row[0]
            k = Fernet(key)
            cur.close()
            filenameSecure = secure_filename(f.filename)
            f.save(os.path.join('project/Decrypted_Files/', filenameSecure))

            with open('project/Decrypted_Files/'+filenameSecure, "rb") as file:
                fileData = file.read()

            decryptedData = k.decrypt(fileData)

            with open('project/Decrypted_Files/'+filenameSecure, "wb") as file:
                file.write(decryptedData)
            return send_file('Decrypted_Files/'+f.filename, as_attachment=True)
        except:
            flash(f"Unexpected error when uploading file, please try again.")
            return redirect('/decrypt/symmetric/')

@main.route('/decrypt/asymmetric/')
def asymmetricD():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('asymmetricD.html')

@main.route('/decrypt/asymmetric/', methods=['POST'])
def asymmetricDecryption():
    if request.method == 'POST':
        # save owner information to db
        username = session.get('username')
        if username is None:
            flash(f"Please log in.")
            return redirect('/')
        else:
            try:
                f = request.files.getlist('file')
                first = True
                fileData = ''
                privateKey = ''
                fileName = ''
                for file in f:
                    filenameSecure = secure_filename(file.filename)
                    fileName = filenameSecure
                    file.save(os.path.join('project/Decrypted_Files/', filenameSecure))
                    with open('project/Decrypted_Files/'+filenameSecure, "rb") as file:
                        if first == True:
                            fileData = file.read()
                            first = False
                        else:
                            privateKey = file.read()

                decoded = fileData.decode('utf-8')
                decryptedData = privateKey.decrypt(ast.literal_eval(str(decoded)))

                with open('project/Decrypted_Files/'+fileName, "wb") as file:
                    file.write(decryptedData)
                return send_file('project/Decrypted_Files/'+filename, as_attachment=True)
            except:
                flash(f"Unexpected error when uploading files, please try again.")
                return redirect('/decrypt/asymmetric/')

@main.route('/hashing/')
def hashing():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('hashing.html')

@main.route('/hashing/hash/')
def hashIndex():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('hash.html')

@main.route('/hashing/hash/', methods=["POST"])
def hash():
    if request.method == 'POST':
        username = session.get('username')
        if username is None:
            flash(f"Please log in.")
            return redirect('/')
        else:
            f = request.files['file']
            filenameSecure = secure_filename(f.filename)
            f.save(os.path.join('project/Flask_Uploads/', filenameSecure))
            BLOCK_SIZE = 65536

            file = os.path.join('project/Flask_Uploads/', filenameSecure)
            fileHash = hashlib.sha256()
            with open(file, 'rb') as f:
                fb = f.read(BLOCK_SIZE)
                while len(fb) > 0:
                    fileHash.update(fb)
                    fb = f.read(BLOCK_SIZE)
            return render_template('calculatedhash.html', hash=fileHash.hexdigest())

@main.route('/hashing/compare/')
def hashCompare():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        return render_template('hashcompare.html')

@main.route('/hashing/compare/', methods=["POST"])
def hashResult():
    if request.method == 'POST':
        username = session.get('username')
        if username is None:
            flash(f"Please log in.")
            return redirect('/')
        else:
            f = request.files.getlist('file')
            BLOCK_SIZE = 65536
            hashes = []
            for file in f:
                filenameSecure = secure_filename(file.filename)
                file.save(os.path.join('project/Flask_Uploads/', filenameSecure))
                file = os.path.join('project/Flask_Uploads/', filenameSecure)
                fileHash = hashlib.sha256()
                with open(file, 'rb') as f:
                    fb = f.read(BLOCK_SIZE)
                    while len(fb) > 0:
                        fileHash.update(fb)
                        fb = f.read(BLOCK_SIZE)
                hashes.append(fileHash.hexdigest())

            if(hashes[0] == hashes[1]):
                return render_template('hashresults.html', message="The file hashes match.")
            else:
                return render_template('hashresults.html', message="The file hashes do NOT match.")


@main.route('/key/')
def key():
    username = session.get('username')
    if username is None:
        flash(f"Please log in.")
        return redirect('/')
    else:
        chars = "1234567890"
        length = 32
        generatedKey = ''
        for i in range(length):
            generatedKey += random.choice(chars)
        return render_template('key.html', generatedKey=generatedKey)


if __name__ == '__main__':
    main.run(debug=True)
