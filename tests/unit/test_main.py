import sys
from logging import NullHandler, StreamHandler, INFO, DEBUG
from miniauth.auth import MiniAuth
from miniauth.main import (main, save_user, remove_user, disable_user,
                           enable_user, verify_user, verify_user_from_opts,
                           EX_ALREADY_EXISTS, EX_OK, EX_NOUSER, EX_SOFTWARE,
                           EX_VERIFYFAILD)
from mock import Mock
from tests.helpers import BaseTestCase


class TestSaveUser(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_auth = Mock()
        self.mock_auth.user_exists.return_value = False

    def test_save_user_checks_user_exists_then_creates_user_and_returns_ok(self):
        self.assertEqual(
            save_user(self.mock_auth, 'testuser', 'testpassword', 'sha512'),
            EX_OK
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.mock_auth.create_user.assert_called_once_with(
            'testuser',
            'testpassword',
            hash_func='sha512'
        )

    def test_save_user_returns_already_exists_code_by_default_when_user_exists(self):
        self.mock_auth.user_exists.return_value = True
        self.assertEqual(
            save_user(self.mock_auth, 'test', 'test', 'sha512'),
            EX_ALREADY_EXISTS
        )
        self.assertFalse(self.mock_auth.create_user.called)

    def test_save_user_creates_user_and_returns_ok_when_user_exists_by_force_set(self):
        self.mock_auth.user_exists.return_value = True
        self.assertEqual(
            save_user(self.mock_auth, 'testuser', 'testpassword', 'sha512', force=True),
            EX_OK
        )
        self.mock_auth.create_user.assert_called_once_with(
            'testuser',
            'testpassword',
            hash_func='sha512'
        )


class TestRemoveUser(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_auth = Mock()
        self.mock_auth.delete_user.return_value = False

    def test_remove_user_deletes_user_and_returns_ok_if_existed(self):
        self.mock_auth.delete_user.return_value = True
        self.assertEqual(
            remove_user(self.mock_auth, 'testuser'),
            EX_OK
        )
        self.mock_auth.delete_user.assert_called_once_with('testuser')

    def test_remove_user_returns_ex_nouser_if_user_didnt_exist(self):
        self.assertEqual(
            remove_user(self.mock_auth, 'testuser'),
            EX_NOUSER
        )

    def test_remove_user_returns_ex_ok_if_user_didnt_exist_but_ignore_missing_set(self):
        self.assertEqual(
            remove_user(self.mock_auth, 'testuser', True),
            EX_OK
        )
        self.mock_auth.delete_user.assert_called_once_with('testuser')


class TestDisableUser(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_auth = Mock()
        self.mock_auth.user_exists.return_value = True
        self.mock_auth.disable_user.return_value = True

    def test_disable_user_checks_user_exists_disables_if_not_and_return_ok(self):
        self.assertEqual(
            disable_user(self.mock_auth, 'testuser'),
            EX_OK
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.mock_auth.disable_user.assert_called_once_with('testuser')

    def test_disable_user_wont_call_disable_but_returns_no_user_when_user_doesnt_exist(self):
        self.mock_auth.user_exists.return_value = False
        self.assertEqual(
            disable_user(self.mock_auth, 'testuser'),
            EX_NOUSER
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.assertFalse(self.mock_auth.disable_user.called)

    def test_disable_user_wont_disable_returns_ok_when_user_doesnt_exist_and_ignore_missing_set(self):
        self.mock_auth.user_exists.return_value = False
        self.assertEqual(
            disable_user(self.mock_auth, 'testuser', True),
            EX_OK
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.assertFalse(self.mock_auth.disable_user.called)

    def test_disable_user_returns_ex_software_if_failed_to_disable(self):
        self.mock_auth.disable_user.return_value = False
        self.assertEqual(
            disable_user(self.mock_auth, 'testuser', True),
            EX_SOFTWARE
        )


class TestEnableUser(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_auth = Mock()
        self.mock_auth.user_exists.return_value = True
        self.mock_auth.enable_user.return_value = True

    def test_enable_user_checks_user_exists_enables_if_not_and_return_ok(self):
        self.assertEqual(
            enable_user(self.mock_auth, 'testuser'),
            EX_OK
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.mock_auth.enable_user.assert_called_once_with('testuser')

    def test_enable_user_wont_call_enable_but_returns_no_user_when_user_doesnt_exist(self):
        self.mock_auth.user_exists.return_value = False
        self.assertEqual(
            enable_user(self.mock_auth, 'testuser'),
            EX_NOUSER
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.assertFalse(self.mock_auth.enable_user.called)

    def test_enable_user_wont_enable_returns_ok_when_user_doesnt_exist_and_ignore_missing_set(self):
        self.mock_auth.user_exists.return_value = False
        self.assertEqual(
            enable_user(self.mock_auth, 'testuser', True),
            EX_OK
        )
        self.mock_auth.user_exists.assert_called_once_with('testuser')
        self.assertFalse(self.mock_auth.enable_user.called)

    def test_enable_user_returns_ex_software_if_failed_to_enable(self):
        self.mock_auth.enable_user.return_value = False
        self.assertEqual(
            enable_user(self.mock_auth, 'testuser', True),
            EX_SOFTWARE
        )


class TestVerifyUser(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_auth = Mock()
        self.mock_auth.verify_user.return_value = True

    def test_verify_user_calls_auth_verify_returns_ok_when_verified(self):
        self.assertEqual(
            verify_user(self.mock_auth, 'testuser', 'testpassword'),
            EX_OK
        )
        self.mock_auth.verify_user.assert_called_once_with('testuser', 'testpassword')

    def test_verify_returns_verifyfailed_when_not_verified(self):
        self.mock_auth.verify_user.return_value = False
        self.assertEqual(
            verify_user(self.mock_auth, 'testuser', 'testpassword'),
            EX_VERIFYFAILD
        )


class TestVerifyUserFromOpts(BaseTestCase):
    def setUp(self):
        self.mock_auth = Mock()
        self.mock_getpass = self.patch('miniauth.main.getpass')
        self.mock_getpass.return_value = 'fromgetpass'
        self.mock_prompt = self.patch('miniauth.main.prompt')
        self.mock_prompt.return_value = 'fromprompt'
        self.mock_read_lines = self.patch('miniauth.main.read_lines_from_file')
        self.mock_verify = self.patch('miniauth.main.verify_user')
        self.mock_verify.return_value = EX_OK
        self.opts = Mock()
        self.opts.user = 'testuser'
        self.opts.password = 'testpassword'
        self.opts.creds_file = ''
        self.opts.password_file = ''

    def test_verify_user_from_opts_gets_user_password_from_opts_calls_verify(self):
        self.assertEqual(
            verify_user_from_opts(self.mock_auth, self.opts),
            EX_OK
        )
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'testuser',
            'testpassword'
        )
        self.assertFalse(self.mock_prompt.called)
        self.assertFalse(self.mock_getpass.called)
        self.assertFalse(self.mock_read_lines.called)

    def test_verify_user_from_opts_prompts_user_password_if_empty(self):
        self.opts.user = ''
        self.opts.password = ''
        verify_user_from_opts(self.mock_auth, self.opts)
        self.assertTrue(self.mock_prompt.called)
        self.assertTrue(self.mock_getpass.called)
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'fromprompt',
            'fromgetpass'
        )

    def test_verify_user_from_opts_prompts_password_if_password_empty(self):
        self.opts.password = ''
        verify_user_from_opts(self.mock_auth, self.opts)
        self.assertFalse(self.mock_prompt.called)
        self.assertTrue(self.mock_getpass.called)
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'testuser',
            'fromgetpass'
        )

    def test_verify_user_from_opts_reads_password_from_creds_file_if_password_empty(self):
        self.opts.creds_file = '/tmp/creds_file'
        self.opts.password = ''
        self.mock_read_lines.return_value = ['userline', 'passline']

        verify_user_from_opts(self.mock_auth, self.opts)

        self.mock_read_lines.assert_called_once_with('/tmp/creds_file', 2)
        self.assertFalse(self.mock_prompt.called)
        self.assertFalse(self.mock_getpass.called)
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'testuser',
            'passline'
        )

    def test_verify_user_from_opts_reads_user_password_from_creds_file_if_empty(self):
        self.opts.creds_file = '/tmp/creds_file'
        self.opts.user = ''
        self.opts.password = ''
        self.mock_read_lines.return_value = ['userline', 'passline']

        verify_user_from_opts(self.mock_auth, self.opts)

        self.mock_read_lines.assert_called_once_with('/tmp/creds_file', 2)
        self.assertFalse(self.mock_prompt.called)
        self.assertFalse(self.mock_getpass.called)
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'userline',
            'passline'
        )

    def test_verify_user_from_opts_raises_valerr_when_user_is_empty_in_opts_and_creds_file(self):
        self.opts.creds_file = '/tmp/creds_file'
        self.opts.user = ''
        self.mock_read_lines.return_value = ['', 'passline']

        with self.assertRaises(ValueError):
            verify_user_from_opts(self.mock_auth, self.opts)

    def test_verify_user_from_opts_raises_valerr_when_passowrd_is_empty_in_opts_and_creds_file(self):
        self.opts.creds_file = '/tmp/creds_file'
        self.opts.password = ''
        self.mock_read_lines.return_value = ['userline', '']

        with self.assertRaises(ValueError):
            verify_user_from_opts(self.mock_auth, self.opts)

    def test_verify_user_from_opts_reads_password_from_password_file_if_password_empty(self):
        self.opts.password_file = '/tmp/password_file'
        self.opts.password = ''
        self.mock_read_lines.return_value = ['passline']

        verify_user_from_opts(self.mock_auth, self.opts)

        self.mock_read_lines.assert_called_once_with('/tmp/password_file', 1)
        self.assertFalse(self.mock_prompt.called)
        self.assertFalse(self.mock_getpass.called)
        self.mock_verify.assert_called_once_with(
            self.mock_auth,
            'testuser',
            'passline'
        )

    def test_verify_user_from_opts_raises_valerr_when_passowrd_is_empty_in_opts_and_passfile(self):
        self.opts.password_file = '/tmp/password_file'
        self.opts.password = ''
        self.mock_read_lines.return_value = ['']

        with self.assertRaises(ValueError):
            verify_user_from_opts(self.mock_auth, self.opts)


class TestMain(BaseTestCase):
    def setUp(self):
        self.mock_logger = self.patch('miniauth.main.logger')
        self.mock_getpass = self.patch('miniauth.main.getpass')
        self.mock_getpass.return_value = 'fromgetpass'
        self.mock_verify = self.patch('miniauth.main.verify_user_from_opts')
        self.mock_verify.return_value = EX_VERIFYFAILD
        self.mock_save = self.patch('miniauth.main.save_user')
        self.mock_save.return_value = EX_OK
        self.mock_remove = self.patch('miniauth.main.remove_user')
        self.mock_remove.return_value = EX_NOUSER
        self.mock_disable = self.patch('miniauth.main.disable_user')
        self.mock_disable.return_value = EX_SOFTWARE
        self.mock_enable = self.patch('miniauth.main.enable_user')
        self.mock_enable.return_value = EX_OK

    def test_main_calls_verify_on_verify_action_returns_the_result(self):
        self.assertEqual(
            main(['verify', 'testuser', 'testpassword']),
            EX_VERIFYFAILD
        )
        self.assertTrue(self.mock_verify.called)
        auth, opts = self.mock_verify.call_args[0]
        self.assertEqual(opts.user, 'testuser')
        self.assertEqual(opts.password, 'testpassword')
        self.assertIsInstance(auth, MiniAuth)

    def test_main_calls_save_user_on_save_action_returns_the_result(self):
        self.assertEqual(
            main(['save', '-p', 'testpassword', '--force', '--hash', 'sha256', 'testuser']),
            EX_OK
        )
        self.assertTrue(self.mock_save.called)
        auth, user, password, hash_, force = self.mock_save.call_args[0]
        self.assertEqual(user, 'testuser')
        self.assertEqual(password, 'testpassword')
        self.assertTrue(force)
        self.assertEqual(hash_, 'sha256')
        self.assertIsInstance(auth, MiniAuth)

    def test_main_prompts_password_if_password_is_not_set(self):
        self.assertEqual(
            main(['save', 'testuser']),
            EX_OK
        )
        self.assertTrue(self.mock_getpass.called)
        self.assertTrue(self.mock_save.called)
        auth, user, password, hash_, force = self.mock_save.call_args[0]
        self.assertEqual(user, 'testuser')
        self.assertEqual(password, 'fromgetpass')
        self.assertFalse(force)
        self.assertEqual(hash_, 'sha512')
        self.assertIsInstance(auth, MiniAuth)

    def test_main_calls_remove_user_on_remove_action_returns_the_result(self):
        self.assertEqual(
            main(['remove', '--ignore-missing', 'testuser']),
            EX_NOUSER
        )
        self.assertTrue(self.mock_remove.called)
        auth, user, ignore_missing = self.mock_remove.call_args[0]
        self.assertEqual(user, 'testuser')
        self.assertTrue(ignore_missing)
        self.assertIsInstance(auth, MiniAuth)

    def test_main_calls_disable_user_on_disable_action_returns_the_result(self):
        self.assertEqual(
            main(['disable', '--ignore-missing', 'testuser']),
            EX_SOFTWARE
        )
        self.assertTrue(self.mock_disable.called)
        auth, user, ignore_missing = self.mock_disable.call_args[0]
        self.assertEqual(user, 'testuser')
        self.assertTrue(ignore_missing)
        self.assertIsInstance(auth, MiniAuth)

    def test_main_calls_enable_user_on_enable_action_returns_the_result(self):
        self.assertEqual(
            main(['enable', '--ignore-missing', 'testuser']),
            EX_OK
        )
        self.assertTrue(self.mock_enable.called)
        auth, user, ignore_missing = self.mock_enable.call_args[0]
        self.assertEqual(user, 'testuser')
        self.assertTrue(ignore_missing)
        self.assertIsInstance(auth, MiniAuth)

    def test_main_configures_logger_with_stream_handler_by_default(self):
        main(['verify', 'testuser', 'testpassword']),
        self.assertEqual(self.mock_logger.addHandler.call_count, 1)
        handler = self.mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler, StreamHandler)
        self.assertEqual(handler.level, INFO)

    def test_main_configures_logger_with_stream_handler_debug_level_on_verbose(self):
        main(['--verbose', 'verify', 'testuser', 'testpassword']),
        self.assertEqual(self.mock_logger.addHandler.call_count, 1)
        handler = self.mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler, StreamHandler)
        self.assertEqual(handler.level, DEBUG)

    def test_main_configures_logger_with_null_handler_in_quiet_mode(self):
        main(['--quiet', 'verify', 'testuser', 'testpassword']),
        self.assertEqual(self.mock_logger.addHandler.call_count, 1)
        handler = self.mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler, NullHandler)
