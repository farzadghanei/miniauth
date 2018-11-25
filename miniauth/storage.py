from __future__ import absolute_import
from abc import ABCMeta, abstractmethod
from .typing import Any, Mapping, Text


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
        self.db_path = db_path

    def get_default_hash_func(self):
        # type: () -> str
        return ''

    @abstractmethod
    def create_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, Text) -> None
        pass

    @abstractmethod
    def record_exists(self, user):
        # type: (Text) -> bool
        pass

    @abstractmethod
    def get_record(self, user):
        # type: (Text) -> Mapping[Text, Any]
        pass

    @abstractmethod
    def update_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, Text) -> None
        pass

    @abstractmethod
    def enable_record(self, user):
        # type: (Text) -> bool
        pass

    @abstractmethod
    def disable_record(self, user):
        # type: (Text) -> bool
        pass

    @abstractmethod
    def delete_record(self, user):
        # type: (Text) -> bool
        pass


class SqliteStorage(AbstractStorage):
    """Storage backend using SQLite database files"""
    def create_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, Text) -> None
        raise NotImplementedError()

    def record_exists(self, user):
        # type: (Text) -> bool
        raise NotImplementedError()

    def get_record(self, user):
        # type: (Text) -> Mapping
        raise NotImplementedError()

    def update_record(self, user, password_hash, hash_func, salt):
        # type: (Text, Text, str, Text) -> None
        raise NotImplementedError()

    def enable_record(self, user):
        # type: (Text) -> bool
        raise NotImplementedError()

    def disable_record(self, user):
        # type: (Text) -> bool
        raise NotImplementedError()

    def delete_record(self, user):
        # type: (Text) -> bool
        raise NotImplementedError()
