from . import db

class User(db.Model):
    username = db.Column(db.String(), primary_key=True, max_length = 15)
    password = db.Column(db.String(), max_length = 25)
