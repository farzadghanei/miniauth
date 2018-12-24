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

    def test_create_record_creates_user_record(self):
        self.storage.create_record('testuser', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        rows = self._query_db('SELECT username, password, hash, salt FROM user')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], (u'testuser', u'81956f2bdddda4b253af6c0a0fc63c05', u'md5', u'asalt'))

    def test_record_exists_creates_db_schema_if_does_not_exist(self):
        self.storage.record_exists('testuser')
        self._assertTablesExist(('user', 'meta'))

    def test_record_exists_return_true_if_user_exists(self):
        self.storage.create_record('testuser', '81956f2bdddda4b253af6c0a0fc63c05', 'md5', 'asalt')
        self.assertTrue(self.storage.record_exists('testuser'))

    def test_record_exists_return_false_if_record_does_not_exist(self):
        self.assertFalse(self.storage.record_exists('testuser'))

    def test_get_record_creates_db_schema_if_does_not_exist(self):
        self.storage.get_record('testuser')
        self._assertTablesExist(('user', 'meta'))

    def test_get_record_returns_dict_with_empty_data_if_no_such_user_exist(self):
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
