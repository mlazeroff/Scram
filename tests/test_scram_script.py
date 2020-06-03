from base64 import b64decode
from pathlib import Path
import pytest
from subprocess import PIPE
import subprocess
import os
import sys
from scram import scrammer

OUTPUT_SWITCHES = ['-hc', '-b64']

RESOURCES = Path(__file__).parent / 'resources'
PYTHON_CMD = 'py' if sys.platform == 'win32' else 'python3'


class TestArguments:
    ONLY_PLAINTEXT = ['hello']

    def test_default_salt(self):
        args = scrammer.parse_args(['hello'])
        assert args.salt is None

    def test_default_iterations(self):
        args = scrammer.parse_args(['hello'])
        assert args.iterations == 4096

    def test_passed_plaintext(self):
        args = scrammer.parse_args(['hello'])
        assert args.plaintext == 'hello'

    def test_no_plaintext(self):
        args = scrammer.parse_args([])
        assert args.plaintext is None

    def test_passed_salt_short(self):
        args = scrammer.parse_args(['hello', '-s', 'QSXCR+Q6sek8bf92'])
        assert args.salt == 'QSXCR+Q6sek8bf92'

    def test_passed_salt_long(self):
        args = scrammer.parse_args(['hello', '--salt', 'QSXCR+Q6sek8bf92'])
        assert args.salt == 'QSXCR+Q6sek8bf92'

    def test_passed_iterations_short(self):
        args = scrammer.parse_args(['hello', '-i', '5000'])
        assert args.iterations == 5000

    def test_passed_iterations_long(self):
        args = scrammer.parse_args(['hello', '--iter', '5000'])
        assert args.iterations == 5000

    def test_format_short(self):
        args = scrammer.parse_args(['hello', '-fmt', 'b64'])
        assert args.format == 'b64'

    def test_format_long(self):
        args = scrammer.parse_args(['hello', '--format', 'b64'])
        assert args.format == 'b64'

    @pytest.mark.parametrize('arg', ['plaintext', 'salt', 'iterations', 'format', 'input_file'])
    def test_arg_in_arg_namespace(self, arg):
        args = scrammer.parse_args(self.ONLY_PLAINTEXT)
        assert arg in args

    @pytest.mark.parametrize('mode', ['b64', 'hashcat'])
    def test_output_switches(self, mode):
        args = scrammer.parse_args(['hello', '--format', mode])
        assert args.format == mode

    def test_default_format(self):
        args = scrammer.parse_args(['hello'])
        assert args.format == 'hex'

    def test_input_mutual_exclusion(self):
        proc_data = subprocess.run([PYTHON_CMD, scrammer.__file__, 'hello', '-f', 'hi.txt'], stderr=PIPE)
        assert proc_data.returncode != 0 and proc_data.stderr != b''

    def test_output_file_flag_true(self):
        args = scrammer.parse_args(['hello', '-o', 'hi.txt'])
        assert args.output_file == 'hi.txt'

    def test_no_output_file_flag(self):
        args = scrammer.parse_args(['hello'])
        assert args.output_file is None


class TestHashFormat:
    HASH = bytes.fromhex('e9d94660c39d65c38fbad91c358f14da0eef2bd6')
    SALT = 'QSXCR+Q6sek8bf92'
    ITERATIONS = 4096

    @pytest.mark.parametrize('mode, output', [('hex', 'e9d94660c39d65c38fbad91c358f14da0eef2bd6'),
                                              ('b64', '6dlGYMOdZcOPutkcNY8U2g7vK9Y='),
                                              ('hashcat', '4096:QSXCR+Q6sek8bf92:6dlGYMOdZcOPutkcNY8U2g7vK9Y=')])
    def test_output(self, mode, output):
        result = scrammer.hash_format(self.HASH, self.SALT, self.ITERATIONS, mode)
        assert result == output

    def test_not_a_format(self):
        with pytest.raises(ValueError):
            scrammer.hash_format(b'', '', 20, mode='fake')


class TestModes:
    SALT = '1234'

    def test_gen_salt(self):
        salt = scrammer.gen_salt(20)
        assert isinstance(salt, str)
        # ensure salt decodes
        stuff = b64decode(salt, validate=True)

    def test_single_mode_gen_salt(self, mocker):
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main(['hello'])
        assert mocked_salter.call_count == 1

    def test_single_mode_no_gen_salt(self, mocker):
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main(['hello', '-s', self.SALT])
        assert mocked_salter.call_count == 0

    def test_file_mode_gen_salt(self, mocker):
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        file_path = RESOURCES / 'small_dictionary.txt'
        scrammer.main(['-f', str(file_path)])
        assert mocked_salter.call_count == len(TestScriptOutput.SMALL_DICT_HEX)

    def test_file_mode_no_gen_salt(self, mocker):
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        file_path = RESOURCES / 'small_dictionary.txt'
        scrammer.main(['-f', str(file_path), '-s', '1234'])
        assert mocked_salter.call_count == 0

    def test_one_stdin_mode_gen_salt(self, mocker):
        mocker.patch('scram.scrammer.input', side_effect=['pencil', ''])
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main([])
        assert mocked_salter.call_count == 1

    def test_multi_stdin_mode_gen_salt(self, mocker):
        mocker.patch('scram.scrammer.input', side_effect=['pencil'] * 10 + [''])
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main([])
        assert mocked_salter.call_count == 10

    def test_one_stdin_mode_no_gen_salt(self, mocker):
        mocker.patch('scram.scrammer.input', side_effect=['pencil', ''])
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main(['-s', '1234'])
        assert mocked_salter.call_count == 0

    def test_multi_stdin_mode_no_gen_salt(self, mocker):
        mocker.patch('scram.scrammer.input', side_effect=['pencil'] * 10 + [''])
        mocked_salter = mocker.patch('scram.scrammer.gen_salt', return_value=self.SALT)
        scrammer.main(['-s', '1234'])
        assert mocked_salter.call_count == 0

    def test_stdin_eof(self, mocker):
        mock = mocker.patch('scram.scrammer.input', side_effect=EOFError('eof'))
        scrammer.main([])
        assert mock.call_count == 1

    def test_stdin_keyboard_interrupt(self, mocker):
        mock = mocker.patch('scram.scrammer.input', side_effect=KeyboardInterrupt('inter'))
        scrammer.main([])
        assert mock.call_count == 1

    def test_stdin_random_error(self, mocker, capsys):
        mock = mocker.patch('scram.scrammer.input', side_effect=TypeError('random'))
        scrammer.main([])
        assert mock.call_count == 1
        captured = capsys.readouterr().err
        assert captured.strip() == 'random'


class TestOutputFunction:

    def test_output_single_hash_to_file(self, tmp_path):
        fp = tmp_path / 'test.txt'
        with open(fp, 'w') as file:
            data = ['e9d94660c39d65c38fbad91c358f14da0eef2bd6']
            scrammer.output_data(data, file=file)
        with open(fp) as file:
            file_data = file.readline().strip()

        assert data[0] == file_data

    def test_output_multiple_hashes_to_file(self, tmp_path):
        fp = tmp_path / 'multiple.txt'
        with open(fp, 'w') as file:
            data = ['c89a8efabda245d57e178bbf1b23a0fb282301f7', '7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                    '1907d2a38a46200722a30e9f2c3c20edf20a051e', 'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                    '29a7bca35ab4817e9460506912c1d3e69c8efcb0']
            scrammer.output_data(data, file=file)
        with open(fp) as file:
            for ind, line in enumerate(file):
                line = line.strip()
                assert line == data[ind]

    def test_output_single_hash_to_stdout(self, capsys):
        data = ['e9d94660c39d65c38fbad91c358f14da0eef2bd6']
        scrammer.output_data(data)
        captured = capsys.readouterr()
        assert captured.out.strip() == data[0]

    def test_output_multiple_hashes_to_stdout(self, capsys):
        data = ['c89a8efabda245d57e178bbf1b23a0fb282301f7', '7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                '1907d2a38a46200722a30e9f2c3c20edf20a051e', 'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                '29a7bca35ab4817e9460506912c1d3e69c8efcb0']
        scrammer.output_data(data)
        captured = capsys.readouterr()
        for ind, line in enumerate(captured.out.split('\n')):
            if line != '':
                assert line.strip() == data[ind]


class TestScriptOutput:
    RUN_ARGS = [PYTHON_CMD, scrammer.__file__]
    PENCIL_SALT = 'QSXCR+Q6sek8bf92'
    PENCIL_HEX = 'e9d94660c39d65c38fbad91c358f14da0eef2bd6'
    SMALL_DICT_SALT = '1234'
    SMALL_DICT_HEX = ['c89a8efabda245d57e178bbf1b23a0fb282301f7', '7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                      '1907d2a38a46200722a30e9f2c3c20edf20a051e', 'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                      '29a7bca35ab4817e9460506912c1d3e69c8efcb0']

    def test_pencil_scram(self, capsys):
        args = ['pencil', '-s', 'QSXCR+Q6sek8bf92']
        scrammer.main(args)
        captured = capsys.readouterr()
        out = captured.out
        assert out.strip() == 'e9d94660c39d65c38fbad91c358f14da0eef2bd6'

    def test_pencil_hex(self, capsys):
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'hex']
        scrammer.main(scrammer_args)
        captured = capsys.readouterr()
        out = captured.out
        assert out.strip() == 'e9d94660c39d65c38fbad91c358f14da0eef2bd6'

    def test_pencil_hashcat(self, capsys):
        """
        test pencil with hashcat output
        """
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'hashcat']
        scrammer.main(scrammer_args)
        captured = capsys.readouterr()
        out = captured.out
        assert out.strip() == '4096:QSXCR+Q6sek8bf92:6dlGYMOdZcOPutkcNY8U2g7vK9Y='

    def test_pencil_b64(self, capsys):
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'b64']
        scrammer.main(scrammer_args)
        captured = capsys.readouterr()
        out = captured.out
        assert out.strip() == '6dlGYMOdZcOPutkcNY8U2g7vK9Y='

    def test_small_dictionary(self, capsys):
        file_path = RESOURCES / 'small_dictionary.txt'
        scrammer_args = ['-f', str(file_path), '-s', '1234', '--format', 'hex']
        scrammer.main(scrammer_args)
        captured = capsys.readouterr()
        out = captured.out
        correct = ['c89a8efabda245d57e178bbf1b23a0fb282301f7', '7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                   '1907d2a38a46200722a30e9f2c3c20edf20a051e', 'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                   '29a7bca35ab4817e9460506912c1d3e69c8efcb0']
        for ind, line in enumerate(out.split()):
            line = line.strip()
            assert line == correct[ind]

    def test_stdin_pencil_to_stdout(self, mocker, capsys):
        mocked_input = mocker.patch('scram.scrammer.input')
        mocked_input.side_effect = ['pencil', '']
        scrammer.main(['-s', self.PENCIL_SALT])
        assert mocked_input.call_count == 2
        out = capsys.readouterr().out
        line = out.split()[0]
        assert line == self.PENCIL_HEX

    def test_stdin_pencil_to_file(self, mocker, tmp_path):
        mocked_input = mocker.patch('scram.scrammer.input')
        mocked_input.side_effect = ['pencil', '']
        file = tmp_path / 'stdin_one.txt'
        scrammer.main(['-s', self.PENCIL_SALT, '-o', str(file)])
        assert os.path.exists(file)
        with open(file) as content:
            line = content.read().split()[0]
            assert line == self.PENCIL_HEX

    def test_stdin_multiple_to_stdout(self, mocker, capsys):
        """
        tests for interactive input
        """
        mocked_input = mocker.patch('scram.scrammer.input')
        mocked_input.side_effect = ['pencil', 'pencil', '']
        scrammer.main(['-s', self.PENCIL_SALT])
        assert mocked_input.call_count == 3
        captured = capsys.readouterr()
        out = captured.out
        lines = [line for line in out.split() if line != '']
        for line in lines:
            assert line == self.PENCIL_HEX

    def test_stdin_small_dictionary_to_stdout(self, capsys):
        file_path = RESOURCES / 'small_dictionary.txt'
        with open(file_path, encoding='utf8') as file:
            content = file.read()
        args = self.RUN_ARGS + ['-s', self.SMALL_DICT_SALT]
        proc_data = subprocess.run(args, shell=True, input=content, encoding='utf8',
                                   stdout=PIPE, stderr=PIPE)
        out = proc_data.stdout
        lines = [(ind, line) for ind, line in enumerate(out.split()) if line != '']
        for ind, line in lines:
            assert line == self.SMALL_DICT_HEX[ind]

    def test_stdin_small_dictionary_to_file(self, tmp_path):

        file_path = RESOURCES / 'small_dictionary.txt'
        with open(file_path, encoding='utf8') as file:
            content = file.read()
        file = tmp_path / 'dict_to_file.txt'
        args = self.RUN_ARGS + ['-s', self.SMALL_DICT_SALT, '-o', str(file)]
        proc_data = subprocess.run(args, shell=True, input=content, encoding='utf8')
        assert os.path.exists(file)
        with open(file) as content:
            lines = [(ind, line.strip()) for ind, line in enumerate(content) if line != '']
            for ind, line in lines:
                assert line == self.SMALL_DICT_HEX[ind]

