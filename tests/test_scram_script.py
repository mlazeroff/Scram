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


class TestOutput:
    RUN_ARGS = ['py', scrammer.__file__]

    def test_pencil_scram(self):
        proc_data = subprocess.run(['py', scrammer.__file__, 'pencil', '-s', 'QSXCR+Q6sek8bf92'], capture_output=True)
        assert proc_data.stdout.strip() == b'e9d94660c39d65c38fbad91c358f14da0eef2bd6'

    def test_pencil_hex(self):
        """
        test with hex output
        """
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'hex']
        args = self.RUN_ARGS + scrammer_args
        proc_data = subprocess.run(args, capture_output=True)
        assert proc_data.stdout.strip() == b'e9d94660c39d65c38fbad91c358f14da0eef2bd6'

    def test_pencil_hashcat(self):
        """
        test pencil with hashcat output
        """
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'hashcat']
        args = self.RUN_ARGS + scrammer_args
        proc_data = subprocess.run(args, capture_output=True)
        assert proc_data.stdout.strip() == b'4096:QSXCR+Q6sek8bf92:6dlGYMOdZcOPutkcNY8U2g7vK9Y='

    def test_pencil_b64(self):
        scrammer_args = ['pencil', '-s', 'QSXCR+Q6sek8bf92', '--format', 'b64']
        args = self.RUN_ARGS + scrammer_args
        proc_data = subprocess.run(args, capture_output=True)
        assert proc_data.stdout.strip() == b'6dlGYMOdZcOPutkcNY8U2g7vK9Y='

    def test_small_dictionary(self):
        scrammer_args = ['-f', 'resource/small_dictionary.txt', '-s', '1234', '--format', 'hex']
        args = self.RUN_ARGS + scrammer_args
        proc_data = subprocess.run(args, capture_output=True)
        correct = [b'c89a8efabda245d57e178bbf1b23a0fb282301f7', b'7bcc94a7fad21b166a46ea5f6e7ace3a53f83583',
                   b'1907d2a38a46200722a30e9f2c3c20edf20a051e', b'd63705b127777e7aa8ace460a5aa1c6a91051a55',
                   b'29a7bca35ab4817e9460506912c1d3e69c8efcb0']
        for ind, line in enumerate(proc_data.stdout.split()):
            line = line.strip()
            assert line == correct[ind]

