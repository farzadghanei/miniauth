"""
miniauth.auth
~~~~~~~~~~~~~
MiniAuth authentication library.
"""
from __future__ import absolute_import
import string
import random
from hashlib import sha512, sha384, sha256, sha224, sha1, md5
from .storage import AbstractStorage, SqliteStorage
from .typing import Text


DEFAULT_HASH_FUNC = 'sha512'  # type: str


def create_salt(length=8):
    # type: (int) -> str
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


class MiniAuth(object):
    hash_functions = {
        'sha512': sha512,
        'sha384': sha384,
        'sha256': sha256,
        'sha224': sha224,
        'md5': md5,
    }

    def __init__(self, db_path, storage=None):
        # type: (Text, AbstractStorage) -> None
        """MiniAuth library, provides methods to modify a local user/password
        DB and methods to verify user information.
        Most operations are idempotant unless specified otherwise.
        """
        self._db_path = db_path
        if storage and not isinstance(storage, AbstractStorage):
            raise ValueError('storage should subclass AbstractStorage')
        self._storage = storage or SqliteStorage(db_path)  # type: AbstractStorage
        self._default_hash_func = self._storage.choose_default_hash_func(
                self.hash_functions.keys()) or DEFAULT_HASH_FUNC  # type: str

    @property
    def storage(self):
        # type: () -> AbstractStorage
        return self._storage

    @property
    def default_hash_func(self):
        # type: () -> str
        return self._default_hash_func

    def password_hash(self, password, hash_func='', salt=''):
        # type: (Text, str, Text) -> Text
        hash_input = salt + password if salt else password
        if not hash_func:
            hash_func = self._default_hash_func
        hash_ = self.hash_functions[hash_func](hash_input.encode('utf-8'))
        return hash_.hexdigest() if hasattr(hash_, 'hexdigest') else str(hash_)

    def create_user(self, username, password, hash_func=''):
        # type: (Text, Text, str) -> bool
        """Create the user record with the specified password.
        This operation is idempotent, so if the user exists, will
        update the record with the specified password
        Return True if new user is created, or False if user already existed
        and just was updated.
        """
        if not hash_func:
            hash_func = self._default_hash_func
        salt = create_salt()
        password_hash = self.password_hash(password, hash_func, salt)
        if self.user_exists(username):
            self._storage.update_record(username, password_hash, hash_func, salt)
            return False
        self._storage.create_record(username, password_hash, hash_func, salt)
        return True

    def delete_user(self, username):
        # type: (Text) -> bool
        """Delete the user record, returning True if user existed, or False
        otherwise.
        """
        if self.user_exists(username):
            self._storage.delete_record(username)
            return True
        return False

    def disable_user(self, username):
        # type: (Text) -> bool
        """Disable the user record, returning True if user existed, or False
        otherwise.
        """
        if self.user_exists(username):
            return self._storage.disable_record(username)
        return False

    def enable_user(self, username):
        # type: (Text) -> bool
        if self.user_exists(username):
            return self._storage.enable_record(username)
        return False

    def user_exists(self, username):
        # type: (Text) -> bool
        return self._storage.record_exists(username)

    def user_is_disabled(self, username):
        # type: (Text) -> bool
        record = self._storage.get_record(username)
        return bool(record.get('disabled', False))

    def verify_user(self, username, password):
        # type: (Text, Text) -> bool
        record = self._storage.get_record(username)
        password_hash = self.password_hash(password, record['hash_func'], record['salt'])
        return password_hash == record['password']
