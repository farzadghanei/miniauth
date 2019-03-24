"""
miniauth.main
~~~~~~~~~~~~~
MiniAuth program interface.
"""
import sys
from argparse import ArgumentParser
from getpass import getpass
from logging import getLogger, INFO, DEBUG, StreamHandler, Logger, NullHandler
from miniauth import __version__
from miniauth.auth import MiniAuth
from miniauth.typing import Any, Text, Tuple
from miniauth.utils import prompt, read_lines_from_file

# corresponding os.EX_* if available
EX_OK = 0
EX_ALREADY_EXISTS = 1
EX_NOUSER = 67
EX_VERIFYFAILD = 68
EX_SOFTWARE = 70
EX_TEMPFAIL = 75

logger = getLogger()  # type: Logger


def parse_args(args=None):
    parser = ArgumentParser(prog='miniauth', description="manage a database of users")
    parser.add_argument('-s', '--storage', default='miniauth.db', help='the auth storage. default is miniauth.db')
    parser.add_argument('-q', '--quiet', action='store_true', help='run in quiet mode (overwrites verbose)')
    parser.add_argument('-v', '--verbose', action='store_true', help='run in verbose mode')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    subparsers = parser.add_subparsers(dest='action', help='available actions')

    parser_user = subparsers.add_parser('save', help='create or update a user')
    parser_user.add_argument('--hash', default='sha512', help='hash function to use (default: sha512)')
    parser_user.add_argument('--password', '-p', help='password')
    parser_user.add_argument('--force', '-f', action='store_true', help='force update user, overwrite existing')
    parser_user.add_argument('user', help='username (is unique)')

    parser_remove = subparsers.add_parser('remove', help='remove a user')
    parser_remove.add_argument('--ignore-missing', '-i', action='store_true', help='ignore missing user')
    parser_remove.add_argument('user', help='username to remove')

    parser_disable = subparsers.add_parser('disable', help='disable an existing user')
    parser_disable.add_argument('--ignore-missing', '-i', action='store_true', help='ignore missing user')
    parser_disable.add_argument('user', help='username to remove')

    parser_enable = subparsers.add_parser('enable', help='enable an existing user')
    parser_enable.add_argument('--ignore-missing', '-i', action='store_true', help='ignore missing user')
    parser_enable.add_argument('user', help='username to remove')

    parser_verify = subparsers.add_parser('verify', help='verify user credentials')
    verify_mutual_ex_args = parser_verify.add_mutually_exclusive_group()
    verify_mutual_ex_args.add_argument(
        '--password-file',
        help='read password from the first line of the file (- for stdin). disables prompting'
    )
    verify_mutual_ex_args.add_argument(
        '--creds-file',
        help='read username and password from a first and 2nd lines of a file (- for stdin). disables prompting'
    )
    parser_verify.add_argument('user', nargs='?', help='username to verify')
    parser_verify.add_argument('password', nargs='?', help='password to verify')

    return parser.parse_args(args)


def configure_logger(logger, quiet=False, debug=False):
    # type: (Logger, bool, bool) -> None
    logger.setLevel(DEBUG)
    if quiet:
        logger.addHandler(NullHandler())
    else:
        stdout_handler = StreamHandler(stream=sys.stdout)
        stdout_handler.setLevel(DEBUG if debug else INFO)
        logger.addHandler(stdout_handler)


def save_user(mini_auth, user, password, hash_, force=False):
    # type: (MiniAuth, Text, Text, str, bool) -> int
    if mini_auth.user_exists(user) and not force:
        logger.warning("user {} already exists. use force to update".format(user))
        return EX_ALREADY_EXISTS
    created = mini_auth.create_user(user, password, hash_func=hash_)
    logger.debug(
        "{} user {}".format('created' if created else 'updated', user)
    )
    return EX_OK


def remove_user(mini_auth, user, ignore_missing=False):
    # type: (MiniAuth, Text, bool) -> int
    if mini_auth.delete_user(user):
        logger.debug("removed user {}".format(user))
        return EX_OK
    logger.info("user {} didn't exit".format(user))
    return EX_OK if ignore_missing else EX_NOUSER


def disable_user(mini_auth, user, ignore_missing=False):
    # type: (MiniAuth, Text, bool) -> int
    if not mini_auth.user_exists(user):
        logger.warning("user {} does not exist".format(user))
        return EX_OK if ignore_missing else EX_NOUSER
    if mini_auth.disable_user(user):
        logger.debug("disabled user {}".format(user))
        return EX_OK
    logger.warning("could not disable user {}".format(user))
    return EX_SOFTWARE


def enable_user(mini_auth, user, ignore_missing=False):
    # type: (MiniAuth, Text, bool) -> int
    if not mini_auth.user_exists(user):
        logger.warning("user {} does not exist".format(user))
        return EX_OK if ignore_missing else EX_NOUSER
    if mini_auth.enable_user(user):
        logger.debug("enabled user {}".format(user))
        return EX_OK
    logger.warning("could not enable user {}".format(user))
    return EX_SOFTWARE


def verify_user(mini_auth, user, password):
    # type: (MiniAuth, Text, Text) -> int
    if mini_auth.verify_user(user, password):
        logger.debug("user {} credentials are correct".format(user))
        return EX_OK
    logger.info("invalid credentias for user {}".format(user))
    return EX_VERIFYFAILD


def _get_user_password_from_opts(opts):
    # type: (Any) -> Tuple[Text, Text]
    """Gets the user/password from provided options, if necessary would
    read from files or streams.
    """
    user, password = opts.user, ''
    if opts.user and opts.password:
        password = opts.password
    elif opts.creds_file:
        lines = read_lines_from_file(opts.creds_file, 2)
        user = opts.user or lines[0]
        if not user:
            raise ValueError("user is not specified, nor could be read from creds file")
        password = opts.password or lines[1]
        if not password:
            raise ValueError("password is not specified, nor could be read from creds file")
    elif opts.password_file:
        lines = read_lines_from_file(opts.password_file, 1)
        password = opts.password or lines[0]
        if not password:
            raise ValueError("password is not specified, nor could be read from password file")
    if not user:
        user = prompt('User: ')
    if not password:
        password = getpass()

    return user, password


def verify_user_from_opts(mini_auth, opts):
    # type: (MiniAuth, Any) -> int
    user, password = _get_user_password_from_opts(opts)
    return verify_user(mini_auth, user, password)


def main(args=None):
    try:
        opts = parse_args(args)
        configure_logger(logger, quiet=opts.quiet)

        mini_auth = MiniAuth(db_path=opts.storage)
        if opts.action == 'verify':
            return verify_user_from_opts(mini_auth, opts)
        if opts.action == 'save':
            password = opts.password or getpass()
            return save_user(mini_auth, opts.user, password, opts.hash, opts.force)
        if opts.action == 'remove':
            return remove_user(mini_auth, opts.user, opts.ignore_missing)
        if opts.action == 'disable':
            return disable_user(mini_auth, opts.user, opts.ignore_missing)
        if opts.action == 'enable':
            return enable_user(mini_auth, opts.user, opts.ignore_missing)
    except KeyboardInterrupt:
        logger.debug("process interrupted")
        return EX_TEMPFAIL


if __name__ == '__main__':
    sys.exit(main())
