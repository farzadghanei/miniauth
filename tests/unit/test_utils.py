from miniauth.utils import (MemTextIO, prompt,
                            read_lines_from_stream,
                            read_lines_from_file)
from tests.helpers import BaseTestCase, HasTempfileTestCase


class TestPrompt(BaseTestCase):
    def setUp(self):
        self.mock_input = self.patch('miniauth.utils._raw_input')
        self.mock_input.return_value = 'test\n'

    def test_prompt_passes_message_to_raw_input(self):
        prompt('context?')
        self.mock_input.assert_called_once_with('context?')

    def test_prompt_returns_stripped_raw_input_results(self):
        self.assertEqual(prompt(), 'test')


class TestReadLinesFromStream(BaseTestCase):
    def setUp(self):
        self.stream = MemTextIO()
        self.stream.write("\n".join([str(v) for v in range(3)]))
        self.stream.seek(0)

    def test_read_lines_from_stream_reads_all_lines_when_no_count(self):
        self.assertEqual(
            read_lines_from_stream(self.stream),
            ['0', '1', '2']
        )

    def test_read_lines_from_stream_reads_specified_lines_count_only(self):
        self.assertEqual(
            read_lines_from_stream(self.stream, 1),
            ['0']
        )

    def test_read_lines_from_stream_returns_none_for_missing_lines(self):
        self.assertEqual(
            read_lines_from_stream(self.stream, 5),
            ['0', '1', '2', None, None]
        )

    def test_read_lines_from_stream_returns_lines_stripping_new_lines_only(self):
        self.stream.write(" left space\n")
        self.stream.write("right space \n")
        self.stream.write("\n")
        self.stream.write(" both space \n")
        self.stream.seek(0)
        self.assertEqual(
            read_lines_from_stream(self.stream),
            [' left space', 'right space ', '', ' both space ']
        )


class TestReadLinesFromFrop(HasTempfileTestCase):
    _temp_file_mode = 'w+t'

    def setUp(self):
        HasTempfileTestCase.setUp(self)
        self._tempfile.write("\n".join([str(v) for v in range(3)]))
        self._tempfile.flush()
        self._tempfile.seek(0)

    def test_read_lines_from_file_reads_all_lines_when_no_count(self):
        self.assertEqual(
            read_lines_from_file(self._tempfile_name),
            ['0', '1', '2']
        )

    def test_read_lines_from_file_reads_specified_lines_count_only(self):
        self.assertEqual(
            read_lines_from_file(self._tempfile_name, 1),
            ['0']
        )

    def test_read_lines_from_line_returns_none_for_missing_lines(self):
        self.assertEqual(
            read_lines_from_file(self._tempfile_name, 5),
            ['0', '1', '2', None, None]
        )

    def test_read_lines_from_line_returns_lines_stripping_new_lines_only(self):
        self._tempfile.write(" left space\n")
        self._tempfile.write("right space \n")
        self._tempfile.write("\n")
        self._tempfile.write(" both space \n")
        self._tempfile.flush()
        self._tempfile.seek(0)
        self.assertEqual(
            read_lines_from_file(self._tempfile_name),
            [' left space', 'right space ', '', ' both space ']
        )
