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

    def test_miniauth_uses_sqlite_storage_by_default(self):
        self.assertIsInstance(self.miniauth.storage, SqliteStorage)

    def test_miniauth_hash_password_without_pepper(self):
        hashed_password = self.miniauth.password_hash('foobar')
        self.assertIsInstance(hashed_password, str)
