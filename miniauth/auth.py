"""
miniauth.auth
~~~~~~~~~~~~~
MiniAuth library.
"""
import os


def create_salt(length=8):
    # type: (int) -> bytes
    # @TODO: support platforms without os.urandom
    return os.urandom(length)


class MiniAuth(object):
    def __init__(self, db_path):
        # type: (str) -> None
        """MiniAuth library, provides methods to modify a local user/password
        DB and methods to verify user information.
        Most operations are idempotant unless specified otherwise.
        """
        self._db_path = db_path

    def password_hash(self, password, scheme='sha512'):
        # type: (str, str) -> str
        return ''

    def create_user(self, username, password):
        # type: (str, str) -> None
        """Create the user record with the specified password.
        This operation is idempotent, so if the user exists, will
        update the record with the specified password
        """
        pass

    def delete_user(self, username):
        # type: (str) -> bool
        """Delete the user record, returning True if user existed, or False
        otherwise.
        """
        pass

    def disable_user(self, username):
        # type: (str) -> bool
        """Disable the user record, returning True if user existed, or False
        otherwise.
        """
        pass

    def enable_user(self, username):
        # type: (str) -> bool
        pass

    def user_exists(self, username):
        # type: (str) -> bool
        pass

    def user_is_disabled(self, username):
        # type: (str) -> bool
        pass

    def verify_user(self, username, password):
        # type: (str, str) -> bool
        pass
