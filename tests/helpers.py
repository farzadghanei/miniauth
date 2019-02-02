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
    _tempfile_mode = 'w+b'
    _tempfile_prefix = 'tmp'
    _tempfile_dir = None

    def _create_temp_file(self):
        return NamedTemporaryFile(
                mode=self._tempfile_mode,
                prefix=self._tempfile_prefix,
                dir=self._tempfile_dir
               )

    def setUp(self):
        self._tempfile = self._create_temp_file()
        self.addCleanup(self._tempfile.close)
        self._tempfile_name = self._tempfile.name
