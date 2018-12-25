"""
miniauth.storage
~~~~~~~~~~~~~~~~
Storage impelentations
"""
from __future__ import absolute_import
import sqlite3
from logging import getLogger
from abc import ABCMeta, abstractmethod
from contextlib import closing
from .typing import Any, AnyStr, Iterable, List, Mapping, Text, Tuple


logger = getLogger(__name__)


class AbstractStorage(object):
    """Abstract base class for classes providing storage backend for
    authentication.
    MiniAuth can use any storage backend that implements abstract methods
    of this class. This ensures the storage supports CRUD methods to
    store user information, plus any extra metadata (if applicable or desired).

    :Note: storage implementations should take of care of handling race conditions
    (by using locks, etc.) if applicable.
    """
    __metaclass__ = ABCMeta

    def __init__(self, db_path):
        # type: (Text) -> None
        self._db_path = db_path  # type: Text

    @property
    def db_path(self):
        # type: () -> Text
        return self._db_path

    def choose_default_hash_func(self, hash_funcs):
        # type: (Iterable[str]) -> str
        """Choose the default hash function preferred by the storage.
        An external storage (possibly shared by other systems)
        may have a different convention for default hash function than mini auth.

        Return empty string (default behavior) to let minitauth choose the default hash
        function.
        """
        return ''

    @abstractmethod
    def create_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, str) -> None
        pass

    @abstractmethod
    def record_exists(self, user):
        # type: (Text) -> bool
        pass

    @abstractmethod
    def get_record(self, user):
        # type: (Text) -> Mapping[Text, Any]
        """Return the record regarding the user.
        If user does not exist, return empty values for the record.
        Return dict keys should be:
            username: (str) the same as the user
            password: (str) the user password (hashed)
            hash_func: (str) function name used to hash the password
            salt: (str) salt used for hashing
            disabled: (bool) if user is disabled [optional]
        """
        return {
            'username': user,
            'password': '',
            'hash_func': '',
            'salt': '',
            'disabled': False,
        }

    @abstractmethod
    def update_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, str) -> bool
        pass

    @abstractmethod
    def enable_record(self, user):
        # type: (Text) -> bool
        """Mark the record as enabled and return True.
        If the storage does not support disabling/enabling users, or failed to
        enable the user return False.
        """
        return False

    @abstractmethod
    def disable_record(self, user):
        # type: (Text) -> bool
        """Mark the record as disabled and return True.
        If the storage does not support disabling/enabling users, or failed to
        disable the user return False.
        """
        return False

    @abstractmethod
    def delete_record(self, user):
        # type: (Text) -> bool
        pass


SQLITE_SCHEMA = {
    1: {
        'tables': {
            'meta': 'CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY ASC, version INTEGER UNIQUE)',
            'user': 'CREATE TABLE IF NOT EXISTS user ('
                    'id INTEGER PRIMARY KEY ASC, username TEXT UNIQUE,'
                    'password TEXT, salt TEXT, hash TEXT, disabled INTEGER DEFAULT 0)',
        },
        'data': [
            'INSERT INTO meta (version) VALUES (1)',
        ]
    }
}  # type: Mapping[int, Mapping[str, Any]]


class SqliteStorage(AbstractStorage):
    """Storage backend using SQLite database files"""

    def _query_db(self, query, params=()):
        # type: (AnyStr, Iterable[AnyStr]) -> Tuple[List[Any], int, int]
        """Run the query with optional parameters, return
        all result rows, row count and last row id as a tuple
        """
        db_con = sqlite3.connect(self.db_path)
        cursor = db_con.cursor()
        with closing(db_con):
            with closing(cursor):
                cursor.execute(str(query), params)
                db_con.commit()
                query_results = cursor.fetchall()
                row_count = cursor.rowcount
                last_row_id = cursor.lastrowid
        return query_results, row_count, last_row_id

    def _multi_query(self, queries):
        # type: (Iterable[AnyStr]) -> None
        """Run the queries against the database. Useful for DDL queries."""
        db_con = sqlite3.connect(self.db_path)
        cursor = db_con.cursor()
        with closing(db_con):
            with closing(cursor):
                for query in queries:
                    cursor.execute(str(query))
                db_con.commit()

    def _get_schema_version(self):
        # type: () -> int
        """Return current DB schema version, return 0 if version can't be detected"""
        try:
            rows, _, _ = self._query_db('SELECT MAX(version) FROM meta')
            if rows:
                return rows[0][0]
        except sqlite3.OperationalError as exp:
            pass
        return 0

    def _apply_schema_version(self, version):
        # type: (int) -> None
        self._multi_query(SQLITE_SCHEMA[version]['tables'].values())
        self._multi_query(['INSERT OR REPLACE INTO meta (version) VALUES ({})'.format(version)])
        logger.info('DB schema updated to version {} on "{}"'.format(self.db_path, version))

    def _ensure_schema(self):
        # type: () -> None
        cur_version = self._get_schema_version()
        if not cur_version:
            # no schema yet (new database), create latest schema
            logger.info('No DB detected on "{}". Creating latest DB schema ...'.format(self.db_path))
            version = max(SQLITE_SCHEMA.keys())
            self._apply_schema_version(version)
        # @TODO: implement migrating from previous schema

    def _pre_write(self):
        # type: () -> None
        self._ensure_schema()

    def _pre_read(self):
        # type: () -> None
        self._ensure_schema()

    def create_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, str) -> None
        self._pre_write()
        self._query_db(
            'INSERT INTO user (username, password, hash, salt) VALUES (?, ?, ?, ?)',
            (user, password_hash, hash_func, salt)
        )

    def record_exists(self, user):
        # type: (Text) -> bool
        self._pre_read()
        rows, _, _ = self._query_db(
            'SELECT username FROM user WHERE username = ?',
            (user,)
        )
        return len(rows) > 0

    def get_record(self, user):
        # type: (Text) -> Mapping
        self._pre_read()
        rows, _, _ = self._query_db(
            'SELECT password, hash, salt, disabled FROM user WHERE username = ?',
            (user,)
        )
        record = {
            'username': user,
            'password': '',
            'hash_func': '',
            'salt': '',
            'disabled': False,
        }
        if rows:
            row = rows[0]
            record['password'] = row[0]
            record['hash_func'] = row[1]
            record['salt'] = row[2]
            record['disabled'] = bool(row[3])
        return record

    def update_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, str) -> bool
        self._pre_write()
        _, row_count, _ = self._query_db(
            'UPDATE user SET password = ?, hash = ?, salt = ? WHERE username = ?',
            (password_hash, hash_func, salt, user)
        )
        return row_count == 1

    def enable_record(self, user):
        # type: (Text) -> bool
        self._pre_write()
        _, row_count, _ = self._query_db(
            'UPDATE user set disabled = 0 WHERE username = ?',
            (user,)
        )
        return row_count == 1

    def disable_record(self, user):
        # type: (Text) -> bool
        self._pre_write()
        _, row_count, _ = self._query_db(
            'UPDATE user set disabled = 1 WHERE username = ?',
            (user,)
        )
        return row_count == 1

    def delete_record(self, user):
        # type: (Text) -> bool
        self._pre_write()
        _, row_count, _ = self._query_db(
            'DELETE FROM user WHERE username = ?',
            (user,)
        )
        return row_count == 1
