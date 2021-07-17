from flask import Flask, render_template, request, flash, redirect, session, url_for, Blueprint
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.context import CryptContext

pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

app = Flask(__name__)
mysql = MySQL(app)

auth = Blueprint('auth', __name__)

@auth.route('/')
def loginRender():
    return render_template('login.html')

@auth.route('/', methods=['POST'])
def login():
    if request.method == "POST":
        details = request.form
        username = details['username']
        password = details['password']

        # check if user exists, then grab the password
        cur = mysql.connection.cursor()
        validInput = cur.execute("SELECT (username) FROM users WHERE username = %s", [username])
        mysql.connection.commit()
        cur.close()
        if(validInput > 0):
            # Grab password from DB to compare
            cur = mysql.connection.cursor()
            cur.execute("SELECT (password) FROM users WHERE username = %s", [username])
            row = cur.fetchone()
            dbPass = row[0]
            mysql.connection.commit()
            cur.close()

            # compare entered pass and db pass
            if(pwd_context.verify(password, dbPass)):
                session.clear()
                session['username'] = username
                return redirect('/dashboard/')
            else:
                flash(f"Incorrect password, please try again.")
                return redirect('/')
        else:
            flash(f"Please check your username and try again.")
            return redirect('/')





@auth.route('/createAccount/')
def createRender():
    return render_template('createAccount.html')

@auth.route('/createAccount/', methods=['POST'])
def createAccount():
    if request.method == "POST":
        details = request.form
        username = details['username']
        password = details['password']

        # # Encrypt password for storage in mysql database
        # salt = os.urandom(16)
        # saltDB = salt.decode('unicode-escape')
        # bytesPassword = bytes(password, 'utf-8')
        # kdf = PBKDF2HMAC(
        #     algorithm=hashes.SHA256(),
        #     length=32,
        #     salt=salt,
        #     iterations=100000,
        # )
        # key = base64.urlsafe_b64encode(kdf.derive(bytesPassword))
        # ciphered_suite = Fernet(key)
        # hashedPassword = ciphered_suite.encrypt(bytesPassword)

        hashedPassword = pwd_context.encrypt(password)

        # Open sql connection and insert data
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users(username, password) VALUES (%s, %s)", (username, hashedPassword))
            mysql.connection.commit()
            cur.close()
            flash(f"Account created successfully! Please log in to continue.")
            return redirect('/')
        except:
            flash(f"Unexpected error, please try again.")
            return redirect('/createAccount/')
