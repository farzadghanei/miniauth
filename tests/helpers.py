from abc import ABCMeta, abstractmethod
from tempfile import NamedTemporaryFile
from unittest import TestCase
from mock import Mock, patch


class BaseTestCase(TestCase):
    def patch(self, target, mock_=None):
        if not mock_:
            mock_ = Mock()
        patcher = patch(target, mock_)
        self.addCleanup(patcher.stop)
        return patcher.start()


class HasTempfileTestCase(BaseTestCase):
    _temp_file_mode = 'w+b'
    _temp_file_prefix = 'tmp'
    _temp_file_dir = None

    def _create_temp_file(self, auto_close=True):
        temp_file = NamedTemporaryFile(
                mode=self._temp_file_mode,
                prefix=self._temp_file_prefix,
                dir=self._temp_file_dir
               )
        if auto_close:
            self.addCleanup(temp_file.close)
        return temp_file

    def setUp(self):
        self._tempfile = self._create_temp_file()
        self._tempfile_name = self._tempfile.name
