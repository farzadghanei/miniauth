from miniauth.auth import MiniAuth, create_salt
from miniauth.storage import SqliteStorage
from mock import Mock
from tests.helpers import BaseTestCase


class TestCreateSalt(BaseTestCase):
    def test_create_salt_returns_str_of_length(self):
        salt = create_salt(5)
        self.assertIsInstance(salt, str)
        self.assertEqual(len(salt), 5)

    def test_create_salt_returns_unique_values(self):
        salts = [create_salt(6) for i in range(100)]
        unique_salts = set(salts)
        self.assertEqual(len(unique_salts), 100)


class TestMiniAuth(BaseTestCase):
    def setUp(self):
        self.mock_storage = Mock(spec=SqliteStorage)
        self.mock_storage.choose_default_hash_func.return_value = ''
        # fixed salt for assertions
        self.mock_create_salt = self.patch('miniauth.auth.create_salt')
        self.mock_create_salt.return_value = '1111aaaa'
        self.miniauth = MiniAuth('testing', self.mock_storage)
        self.password = 'abcd1234'
        self.password_hashed = 'ad59f4bde6e616d13b818b393427ac6803d5c2b90fbdc873f8921e1e5183d6fe'  # sha256, salted
        self.mock_record = {
            'username': 'test',
            'password': self.password_hashed,
            'disabled': True,
            'hash_func': 'sha256',
            'salt': '1111aaaa',
        }
        self.mock_storage.get_record.return_value = self.mock_record

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

    def test_miniauth_create_user_checks_if_user_already_exists(self):
        self.miniauth.create_user('test', self.password, 'sha256')
        self.mock_storage.record_exists.assert_called_once_with('test')

    def test_miniauth_create_user_calls_storage_create_record_with_hashed_password(self):
        self.mock_storage.record_exists.return_value = False
        ret = self.miniauth.create_user('test', self.password, 'sha256')

        self.assertTrue(ret)
        self.mock_create_salt.assert_called_once_with()
        self.mock_storage.create_record.assert_called_once_with(
            'test',
            self.password_hashed,
            'sha256',
            '1111aaaa'
        )

    def test_miniauth_create_user_updates_the_existing_records_without_creation(self):
        self.mock_storage.record_exists.return_value = True
        ret = self.miniauth.create_user('test', self.password, 'sha256')

        self.assertFalse(ret)
        self.mock_create_salt.assert_called_once_with()
        self.mock_storage.update_record.assert_called_once_with(
            'test',
            self.password_hashed,
            'sha256',
            '1111aaaa'
        )
        self.mock_storage.create_record.assert_not_called()

    def test_miniauth_delete_user_checks_user_exists(self):
        self.miniauth.delete_user('test')
        self.mock_storage.record_exists.assert_called_once_with('test')

    def test_miniauth_delete_user_deletes_record_rets_true_when_user_exists(self):
        self.mock_storage.record_exists.return_value = True
        ret = self.miniauth.delete_user('test')
        self.assertTrue(ret)
        self.mock_storage.delete_record.assert_called_once_with('test')

    def test_miniauth_delete_user_wont_delete_record_and_rets_false_when_user_doesnt_exist(self):
        self.mock_storage.record_exists.return_value = False
        ret = self.miniauth.delete_user('test')
        self.assertFalse(ret)
        self.mock_storage.delete_record.assert_not_called()

    def test_miniauth_disable_user_checks_user_exists(self):
        self.miniauth.disable_user('test')
        self.mock_storage.record_exists.assert_called_once_with('test')

    def test_miniauth_disable_user_disables_record_rets_true_when_user_exists(self):
        self.mock_storage.record_exists.return_value = True
        self.mock_storage.disable_record.return_value = True
        ret = self.miniauth.disable_user('test')
        self.assertTrue(ret)
        self.mock_storage.disable_record.assert_called_once_with('test')

    def test_miniauth_disable_user_wont_disable_record_and_rets_false_when_user_doesnt_exist(self):
        self.mock_storage.record_exists.return_value = False
        ret = self.miniauth.disable_user('test')
        self.assertFalse(ret)
        self.mock_storage.disable_record.assert_not_called()

    def test_miniauth_enable_user_checks_user_exists(self):
        self.miniauth.enable_user('test')
        self.mock_storage.record_exists.assert_called_once_with('test')

    def test_miniauth_enable_user_enables_record_rets_true_when_user_exists(self):
        self.mock_storage.record_exists.return_value = True
        self.mock_storage.enable_record.return_value = True
        ret = self.miniauth.enable_user('test')
        self.assertTrue(ret)
        self.mock_storage.enable_record.assert_called_once_with('test')

    def test_miniauth_enable_user_wont_enable_record_and_rets_false_when_user_doesnt_exist(self):
        self.mock_storage.record_exists.return_value = False
        ret = self.miniauth.enable_user('test')
        self.assertFalse(ret)
        self.mock_storage.enable_record.assert_not_called()

    def test_miniauth_user_exists_calls_storage_record_exists(self):
        self.mock_storage.record_exists.return_value = True
        ret = self.miniauth.user_exists('test')
        self.assertTrue(ret)
        self.mock_storage.record_exists.assert_called_once_with('test')

    def test_miniauth_user_is_disabled_return_disabled_field_of_record(self):
        self.mock_storage.get_record.return_value = self.mock_record
        ret = self.miniauth.user_is_disabled('test')
        self.assertTrue(ret)
        self.mock_storage.get_record.assert_called_once_with('test')

    def test_miniauth_user_is_disabled_return_false_if_record_has_no_disabled(self):
        del self.mock_record['disabled']
        self.mock_storage.get_record.return_value = self.mock_record
        ret = self.miniauth.user_is_disabled('test')
        self.assertFalse(ret)

    def test_miniauth_verify_user_gets_the_user_record_from_storage(self):
        ret = self.miniauth.verify_user('test', 'abcd1234')
        self.mock_storage.get_record.assert_called_once_with('test')

    def test_miniauth_verify_user_returns_true_if_password_hash_matches(self):
        self.assertTrue(self.miniauth.verify_user('test', 'abcd1234'))

    def test_miniauth_verify_user_returns_false_if_password_hash_matches(self):
        self.assertFalse(self.miniauth.verify_user('test', 'somethingelse'))

    def test_miniauth_verify_user_returns_false_if_password_is_empty(self):
        self.assertFalse(self.miniauth.verify_user('test', ''))

    def test_miniauth_verify_user_returns_false_if_user_does_not_exist(self):
        self.mock_record['username'] = 'test2'
        self.mock_record['password'] = ''
        self.mock_record['hash_func'] = ''
        self.mock_record['salt'] = ''
        self.assertFalse(self.miniauth.verify_user('test2', 'abcd1234'))

    def test_miniauth_verify_user_returns_false_if_user_does_not_exist_and_password_is_empty(self):
        self.mock_record['username'] = 'test2'
        self.mock_record['password'] = ''
        self.mock_record['hash_func'] = ''
        self.mock_record['salt'] = ''
        self.assertFalse(self.miniauth.verify_user('test2', ''))
