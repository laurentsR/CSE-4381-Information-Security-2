from flask import Flask, render_template, request, flash, redirect, session, url_for, Blueprint
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import os


def create_app():
    app = Flask(__name__)
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SECRET_KEY'] = os.urandom(24)

    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'newuser'
    app.config['MYSQL_PASSWORD'] = 'password123!@#'
    app.config['MYSQL_DB'] = 'cse4381_a3'

    app.config['UPLOAD_FOLDER'] = '/project/Flask_Uploads/'
    app.config['MAX_CONTENT_PATH'] = 100000000

    mysql = MySQL(app)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
