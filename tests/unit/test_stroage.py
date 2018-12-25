import sqlite3
from contextlib import closing
from miniauth.storage import SqliteStorage
from tests.helpers import HasTempfileTestCase


class TestSqliteStorage(HasTempfileTestCase):
    def setUp(self):
        HasTempfileTestCase.setUp(self)
        self.storage = SqliteStorage(self._tempfile_name)

    def _db_connect(self):
        return sqlite3.connect(self._tempfile_name)

    def _query_db(self, query, args=()):
        db_con = self._db_connect()
        cursor = db_con.cursor()
        with closing(db_con):
            with closing(cursor):
                cursor.execute(query, args)
                db_con.commit()
                return cursor.fetchall()

    def _assertTablesExist(self, tables):
        all_tables = [row[0] for row in self._query_db('SELECT tbl_name FROM sqlite_master WHERE type = "table"')]
        for table in tables:
            self.assertIn(table, all_tables)

    def _assertDbVersion(self, version):
        all_versions = sorted([row[0] for row in self._query_db('SELECT version FROM meta')])
        self.assertEqual(all_versions.count(version), 1, 'versoin {} record exists more than once'.format(version))
        self.assertEqual(max(all_versions), version)

    def test_db_path_returns_the_path_to_file(self):
        self.assertEqual(self.storage.db_path, self._tempfile_name)

    def test_db_path_is_readonly(self):
        with self.assertRaises(AttributeError):
            self.storage.db_path = 'foo'

    def test_new_storage_wont_create_db_yet(self):
        self.assertEqual(b'', self._tempfile.read())

    def test_create_record_creates_db_schema_if_does_not_exist(self):
        self.storage.create_record('user2', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self._assertTablesExist(('user', 'meta'))

    def test_create_record_wont_create_schmea_if_exists(self):
        self.storage.create_record('user1', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self.storage.create_record('user2', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self._assertTablesExist(('user', 'meta'))
        self._assertDbVersion(1)

    def test_create_record_creates_user_record(self):
        self.storage.create_record('testuser', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        rows = self._query_db('SELECT username, password, hash, salt, disabled FROM user')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], (u'testuser', u'81956f2bdddda4b253af6c0a0fc63c05', u'md5', u'asalt', False))

    def test_record_exists_return_true_if_user_exists(self):
        self.storage.create_record('testuser', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self.assertTrue(self.storage.record_exists('testuser'))

    def test_record_exists_return_false_if_record_does_not_exist_yet_creates_schmea(self):
        self.assertFalse(self.storage.record_exists('testuser'))
        self._assertTablesExist(('user', 'meta'))

    def test_get_record_returns_dict_with_empty_data_if_no_such_user_exist_and_creates_schema(self):
        self.assertEqual(
            self.storage.get_record('testuser'),
            {
                'username': 'testuser',
                'password': '',
                'hash_func': '',
                'salt': '',
                'disabled': False,
            }
        )
        self._assertTablesExist(('user', 'meta'))

    def test_get_record_returns_dictionary_if_user_info_exists(self):
        self.storage.create_record('testuser', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self.assertEqual(
            self.storage.get_record('testuser'),
            {
                'username': 'testuser',
                'password': '81956f2bdddda4b253af6c0a0fc63c05',
                'hash_func': 'md5',
                'salt': 'asalt',
                'disabled': False,
            }
        )

    def test_disable_record_sets_disabled_field_to_true_and_returns_true(self):
        self.assertFalse(self.storage.record_exists('testuser'))  # create schema
        self._query_db(
            'INSERT INTO user VALUES (NULL, "testuser", "81956f2bdddda4b253af6c0a0fc63c05", "md5", "asalt", 0)'
        )
        self.assertTrue(self.storage.disable_record('testuser'))
        record = self.storage.get_record('testuser')
        self.assertEqual(record['password'], '81956f2bdddda4b253af6c0a0fc63c05')  # ensure record is read from storage
        self.assertTrue(record['disabled'])

    def test_disable_record_returns_false_when_user_does_not_exist_yet_creates_schema(self):
        self.assertFalse(self.storage.disable_record('testuser'))
        self._assertTablesExist(('user', 'meta'))

    def test_enable_record_sets_disabled_field_to_false_and_returns_true(self):
        self.assertFalse(self.storage.record_exists('testuser'))  # create schema
        self._query_db(
            'INSERT INTO user VALUES (NULL, "testuser", "81956f2bdddda4b253af6c0a0fc63c05", "md5", "asalt", 1)'
        )
        self.storage.enable_record('testuser')
        record = self.storage.get_record('testuser')
        self.assertEqual(record['password'], '81956f2bdddda4b253af6c0a0fc63c05')  # ensure record is read from storage
        self.assertFalse(record['disabled'])

    def test_enable_record_returns_false_when_user_does_not_exist_yet_creates_schema(self):
        self.assertFalse(self.storage.enable_record('testuser'))
        self._assertTablesExist(('user', 'meta'))

    def test_delete_record_removes_deletes_the_row_and_returns_true(self):
        self.assertFalse(self.storage.record_exists('testuser'))  # create schema
        self._query_db(
            'INSERT INTO user VALUES (NULL, "testuser", "81956f2bdddda4b253af6c0a0fc63c05", "md5", "asalt", 1)'
        )
        self.assertTrue(self.storage.delete_record('testuser'))
        self.assertFalse(self.storage.record_exists('testuser'))

    def test_delete_record_returns_false_when_user_does_not_exist_yet_creates_schema(self):
        self.assertFalse(self.storage.delete_record('testuser'))
        self._assertTablesExist(('user', 'meta'))

    def test_update_record_updates_password_and_hash_and_salt_returns_true(self):
        self.assertFalse(self.storage.record_exists('testuser'))  # create schema
        self._query_db(
            'INSERT INTO user VALUES (NULL, "testuser", "81956f2bdddda4b253af6c0a0fc63c05", "md5", "asalt", 0)'
        )
        self.assertTrue(
            self.storage.update_record('testuser', '662adlj2l3j232lkj11121', 'sha256', 'othersalt')
        )
        record = self.storage.get_record('testuser')
        self.assertEqual(record['password'], '662adlj2l3j232lkj11121')  # ensure record is read from storage
        self.assertEqual(record['salt'], 'othersalt')
        self.assertEqual(record['hash_func'], 'sha256')
        self.assertFalse(record['disabled'])

    def test_update_record_returns_false_when_user_does_not_exist_yet_creates_schema(self):
        self.assertFalse(
            self.storage.update_record('testuser', '662adlj2l3j232lkj11121', 'sha256', 'othersalt')
        )
        self._assertTablesExist(('user', 'meta'))

    def test_storage_methods_in_sequence_operate_as_expected(self):
        self.storage.create_record('user2', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self._assertTablesExist(('user', 'meta'))
        self.assertTrue(self.storage.record_exists('user2'))
        record = self.storage.get_record('user2')
        self.assertEqual(record['password'], '81956f2bdddda4b253af6c0a0fc63c05')
        self.assertTrue(self.storage.disable_record('user2'))
        self.assertTrue(self.storage.get_record('user2')['disabled'])
        self.assertTrue(self.storage.enable_record('user2'))
        self.assertFalse(self.storage.get_record('user2')['disabled'])
        self.assertTrue(
            self.storage.update_record('user2', '662adlj2l3j232lkj11121', 'sha256', 'othersalt')
        )
        self.assertEqual(self.storage.get_record('user2')['salt'], 'othersalt')
        self.assertTrue(self.storage.delete_record('user2'))
        self.assertFalse(self.storage.record_exists('user2'))
        self._assertDbVersion(1)
