import pytest
import subprocess
from scram import scrammer

OUTPUT_SWITCHES = ['-hc', '-b64']


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

    def test_missing_plaintext(self):
        proc_data = subprocess.run(['py', scrammer.__file__], capture_output=True)
        assert proc_data.returncode != 0 and proc_data.stderr != b''

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
        proc_data = subprocess.run(['py', scrammer.__file__, 'hello', '-f', 'hi.txt'], capture_output=True)
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
    RUN_ARGS = ['py', scrammer.__file__]

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
        scrammer_args = ['-f', 'resources/small_dictionary.txt', '-s', '1234', '--format', 'hex']
        scrammer.main(scrammer_args)
        captured = capsys.readouterr()
        out = captured.out
        correct = ['c89a8efabda245d57e178bbf1b23a0fb282301f7', '7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                   '1907d2a38a46200722a30e9f2c3c20edf20a051e', 'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                   '29a7bca35ab4817e9460506912c1d3e69c8efcb0']
        for ind, line in enumerate(out.split()):
            line = line.strip()
            assert line == correct[ind]
