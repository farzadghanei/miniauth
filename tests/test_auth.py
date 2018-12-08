from unittest import TestCase
from miniauth.auth import MiniAuth, create_salt
from miniauth.storage import SqliteStorage


class TestCreateSalt(TestCase):
    def test_create_salt_returns_str_of_length(self):
        salt = create_salt(5)
        self.assertIsInstance(salt, str)
        self.assertEqual(len(salt), 5)

    def test_create_salt_returns_unique_values(self):
        salts = [create_salt(6) for i in range(100)]
        unique_salts = set(salts)
        self.assertEqual(len(unique_salts), 100)


class TestMiniAuth(TestCase):
    def setUp(self):
        self.miniauth = MiniAuth('testing')
        self.password = 'abcd1234'

    def test_miniauth_uses_sqlite_storage_by_default(self):
        self.assertIsInstance(self.miniauth.storage, SqliteStorage)

    def test_miniauth_uses_sha512_as_default_hash_function(self):
        self.assertEqual(self.miniauth.default_hash_func, 'sha512')

    def test_miniauth_hash_password_with_default_hash_function(self):
        hashed_password = self.miniauth.password_hash(self.password)
        self.assertIsInstance(hashed_password, str)
        self.assertNotEqual(hashed_password, self.password)
        self.assertEqual(self.miniauth.password_hash(self.password), hashed_password)
        self.assertEqual(
            self.miniauth.password_hash(self.password, self.miniauth.default_hash_func),
            hashed_password
        )

    def test_miniauth_hash_password_accepts_md5_hash_function(self):
        hashed_password = self.miniauth.password_hash(self.password, 'md5')
        self.assertIsInstance(hashed_password, str)
        self.assertNotEqual(self.miniauth.password_hash(self.password), hashed_password)
        self.assertNotEqual(hashed_password, self.password)
        self.assertEqual(self.miniauth.password_hash(self.password, 'md5'), hashed_password)

    def test_miniauth_hash_password_accepts_sha224_hash_function(self):
        hashed_password = self.miniauth.password_hash(self.password, 'sha224')
        self.assertIsInstance(hashed_password, str)
        self.assertNotEqual(hashed_password, self.password)
        self.assertNotEqual(self.miniauth.password_hash(self.password), hashed_password)
        self.assertEqual(self.miniauth.password_hash(self.password, 'sha224'), hashed_password)

    def test_miniauth_hash_password_accepts_sha256_hash_function(self):
        hashed_password = self.miniauth.password_hash(self.password, 'sha256')
        self.assertIsInstance(hashed_password, str)
        self.assertNotEqual(hashed_password, self.password)
        self.assertNotEqual(self.miniauth.password_hash(self.password), hashed_password)
        self.assertEqual(self.miniauth.password_hash(self.password, 'sha256'), hashed_password)

    def test_miniauth_hash_password_accepts_sha384_hash_function(self):
        hashed_password = self.miniauth.password_hash(self.password, 'sha384')
        self.assertIsInstance(hashed_password, str)
        self.assertNotEqual(hashed_password, self.password)
        self.assertNotEqual(self.miniauth.password_hash(self.password), hashed_password)
        self.assertEqual(self.miniauth.password_hash(self.password, 'sha384'), hashed_password)

    def test_miniauth_hash_password_accepts_salt(self):
        salted_hash = self.miniauth.password_hash(self.password, salt='foobar')
        self.assertIsInstance(salted_hash, str)
        self.assertEqual(self.miniauth.password_hash(self.password, salt='foobar'), salted_hash)
        self.assertNotEqual(self.miniauth.password_hash(self.password), salted_hash)
