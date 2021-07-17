# Copyright 2015 Vinicius Chiele. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import hashlib
import os

from abc import ABCMeta
from abc import abstractmethod
from functools import lru_cache
from .utils import import_string


# Try to import the bcrypt library
# to be used by BCryptPasswordHasher class.
try:
    import bcrypt
except ImportError:
    bcrypt = None


class PasswordHasher(object):
    """
    Password hasher.
    """

    # The algorithm used to crypt the passwords.
    # if it is None, we will take the first password hasher from 'hashers' attribute as the default hasher.
    algorithm = None

    # Hashers supported.
    hashers = [
        'flask_password.hashers.PBKDF2PasswordHasher',
        'flask_password.hashers.BCryptPasswordHasher',
        'flask_password.hashers.MD5PasswordHasher',
        'flask_password.hashers.SHA1PasswordHasher'
    ]

    def __init__(self, app=None):
        self.__hashers = {}

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Loads the configuration from Flask app."""

        self.algorithm = app.config.get('PASSWORD_ALGORITHM')
        self.hashers = app.config.get('PASSWORD_HASHERS', self.hashers)

        for hasher in self.get_hashers():
            hasher.init_app(app)

        if self.algorithm is None:
            hasher = self.get_hashers()[0]
            self.algorithm = hasher.algorithm

    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """

        algorithm = self.get_algorithm(hashed_password)
        hasher = self.get_hasher(algorithm)
        return hasher.check_password(password, hashed_password)

    def hash_password(self, password, salt=None, algorithm=None):
        """
        Encrypt a password.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :param algorithm: The algorithm used to encrypt the password.
        :type algorithm: str
        :return: The hashed password.
        """

        if not algorithm:
            algorithm = self.algorithm

        hasher = self.get_hasher(algorithm)

        if not salt:
            salt = hasher.salt()

        return hasher.hash_password(password, salt)

    @staticmethod
    def get_algorithm(hashed_password):
        """
        Gets the algorithm from the hashed password.
        :param hashed_password: hashed password.
        :type hashed_password: str
        :return: The algorithm extract from the hashed password.
        """
        return hashed_password.split('$', 1)[0]

    def get_hasher(self, algorithm):
        """
        Gets a hasher for the specified algorithm.
        :param algorithm: The algorithm to be found.
        :return: A password hasher or exception.
        """

        hashers = self.get_hashers()

        if algorithm is None:
            return hashers[0]

        for hasher in hashers:
            if hasher.algorithm == algorithm:
                return hasher

        raise ValueError("Unknown password hashing algorithm '%s'. " % algorithm)

    @lru_cache()
    def get_hashers(self):
        """
        Gets all hashers registered.
        :return: A list of hashers.
        """
        hashers = []

        for class_name in self.hashers:
            hasher_cls = import_string(class_name)
            hasher = hasher_cls()
            hashers.append(hasher)

        return hashers


class BasePasswordHasher(metaclass=ABCMeta):
    """
    Base class for the password hashers.
    """

    # Name of algorithm used to encrypt the password.
    algorithm = None

    def init_app(self, app):
        pass

    @abstractmethod
    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """
        pass

    @abstractmethod
    def hash_password(self, password, salt):
        """
        Encrypt a password.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :return: The hashed password.
        """
        pass

    def salt(self):
        """Generate a new salt."""
        return base64.b64encode(os.urandom(16)).decode()


class BCryptPasswordHasher(BasePasswordHasher):
    """
    BCrypt Password hashing.
    This hashing is strong and recommended.
    """

    algorithm = 'bcrypt'
    rounds = 12

    def init_app(self, app):
        """Loads the configuration from Flask app."""

        rounds = app.config.get('BCRYPT_ROUNDS')
        if rounds:
            self.rounds = rounds

    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a bcrypt hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """

        self.__check_bcrypt()

        algorithm, data = hashed_password.split('$', 1)

        password = password.encode()
        hashed_password = data.encode()

        return bcrypt.checkpw(password, hashed_password)

    def hash_password(self, password, salt):
        """
        Encrypt a password using bcrypt algorithm.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :return: The hashed password.
        """

        self.__check_bcrypt()

        password = password.encode()

        data = bcrypt.hashpw(password, salt)
        return "%s$%s" % (self.algorithm, data)

    def salt(self, rounds=None):
        """Generate a new salt."""

        self.__check_bcrypt()

        if not rounds:
            rounds = self.rounds
        return bcrypt.gensalt(rounds)

    @staticmethod
    def __check_bcrypt():
        """Checks whether bcrypt library has been loaded."""
        if not bcrypt:
            raise ImportError('bcrypt library is not installed. (pip install py-bcrypt)')


class PBKDF2PasswordHasher(BasePasswordHasher):
    """
    PBKDF2 Password hashing.
    This hashing is strong and recommended.
    """

    algorithm = "pbkdf2"
    iterations = 24000
    digest = hashlib.sha256

    def init_app(self, app):
        """Loads the configuration from Flask app."""

        iterations = app.config.get('PBKDF2_ITERATIONS')
        if iterations:
            self.iterations = iterations

    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a PBKDF2 hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """

        algorithm, iterations, salt, hash = hashed_password.split('$', 3)
        return self.hash_password(password, salt, int(iterations)) == hashed_password

    def hash_password(self, password, salt, iterations=None):
        """
        Encrypt a password using PBKDF2 algorithm.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :return: The hashed password.
        """

        if not iterations:
            iterations = self.iterations

        password_bytes = password.encode()
        salt_bytes = salt.encode()

        hash = hashlib.pbkdf2_hmac(self.digest().name, password_bytes, salt_bytes, iterations)
        hash = base64.b64encode(hash).decode('ascii').strip()
        return "%s$%s$%s$%s" % (self.algorithm, iterations, salt, hash)


class MD5PasswordHasher(BasePasswordHasher):
    """
    MD5 Password hashing.
    This hashing is too weak so it is not recommended.
    """

    algorithm = "md5"

    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a MD5 hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """

        algorithm, salt, hash = hashed_password.split('$', 2)
        return self.hash_password(password, salt) == hashed_password

    def hash_password(self, password, salt):
        """
        Encrypt a password using MD5 algorithm.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :return: The hashed password.
        """

        hash = hashlib.md5((salt + password).encode()).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)


class SHA1PasswordHasher(BasePasswordHasher):
    """
    SHA1 Password hashing.
    This hashing is too weak so it is not recommended.
    """

    algorithm = "sha1"

    def check_password(self, password, hashed_password):
        """
        Compares one plain text password against a SHA1 hashed password.
        :param password: A plain text password.
        :type password: str
        :param hashed_password: An hashed password
        :type hashed_password: str
        :return: True if the password are equal; otherwise, false.
        """

        algorithm, salt, hash = hashed_password.split('$', 2)
        return self.hash_password(password, salt) == hashed_password

    def hash_password(self, password, salt):
        """
        Encrypt a password using SHA1 algorithm.
        :param password: A plain text password to be hashed.
        :type password: str
        :param salt: The salt used to encrypt the password.
        :type salt: str
        :return: The hashed password.
        """

        hash = hashlib.sha1((salt + password).encode()).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)
