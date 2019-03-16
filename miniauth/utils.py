"""
miniauth.utils
~~~~~~~~~~~~~~
utility functions and helpers
"""
import sys
from contextlib import closing
from .typing import List
from io import BytesIO, StringIO

# Python 2 StringIO uses unicode, but Python 2 argparser returns str.
# By using BytesIO we can avoids this. MemTextIO is a safe alias
# to use for any text based memory IO.
MemTextIO = BytesIO if sys.version_info[0] == 2 else StringIO

try:
    _raw_input = raw_input
except NameError:  # Python 3 renamed raw_input to input
    _raw_input = input


def prompt(message='', on_empty_msg='Please enter a value'):
    while True:
        resp = _raw_input(message).strip()
        if resp:
            return resp
        print(on_empty_msg)


def read_lines_from_stream(stream, count=None):
    """Read lines from the stream/file object. If a count is specified
    would limit the number of lines read.  If there are fewer lines than count,
    the rest of the list would be None items.
    Empty lines are not filtered out and count as a line.
    """
    # type (Any, int) -> List[Text]
    if not count:
        return [l.strip("\n") for l in stream.readlines()]
    lines = []
    line_counter = 0
    for line in stream:
        line_counter += 1
        lines.append(line.strip("\n"))
        if line_counter >= count:
            break
    if line_counter < count:
        lines.extend([None] * (count - line_counter))
    return lines


def read_lines_from_file(file_name, count=None):
    """Read lines from the file. If a count is specified
    would limit the number of lines read from the file.
    If the file has fewer lines than count, the rest of the list would be None items
    Empty lines are not filtered out and count as a line.

    file_name can be a path to a file, or '-' for standard input.
    file handlers are closed, but not stdin.
    """
    # type (Text, int) -> List[Text]
    if file_name == '-':
        return read_lines_from_stream(sys.stdin, count)

    with closing(open(file_name, 'rt')) as fh:
        return read_lines_from_stream(fh, count)
