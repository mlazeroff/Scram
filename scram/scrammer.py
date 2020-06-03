import argparse
from base64 import b64decode, b64encode
import os
import sys
from typing import List
from scram.scramsha1 import SCRAMSHA1

OUTPUT_FORMATS = ['hex', 'b64', 'hashcat']
HASH_LEN = 20


def gen_salt(byte_num: int):
    """
    Generates a B64 encoded slat
    :param byte_num: number of bytes
    :return: str
    """
    salt = b64encode(os.urandom(byte_num)).decode('utf8')
    return salt


def hash_format(scram_res: bytes, salt: str, iterations: int, mode='hex'):
    """
    Formats the SCRAM result according to the mode
    :param scram_res: bytes
    :param salt: b64 encoded str
    :param iterations: int
    :param mode: [hex, b64, hashcat]
    :return: str
    """

    if mode == 'hex':
        output_content = scram_res.hex()
    elif mode == 'b64':
        output_content = b64encode(scram_res).decode('utf8')
    elif mode == 'hashcat':
        output_content = f'{iterations}:{salt}:{b64encode(scram_res).decode("utf8")}'
    else:
        raise ValueError(f'Not a valid output mode: {mode}')

    return output_content


def output_data(data: List[str], file=None):
    """
    Outputs the data to the file, else to stdout
    :param data: List[str]
    :param file: optional file
    """
    for item in data:
        if file:
            file.write(item + '\n')
        else:
            print(item)


def single_mode(args):
    # gen salt if not given
    if args.salt is None:
        salt = gen_salt(HASH_LEN)
    else:
        salt = args.salt

    plaintext = args.plaintext.encode('utf8')
    iterations = args.iterations

    hash_res = SCRAMSHA1(plaintext, salt, iterations)
    data = [hash_format(hash_res, salt, iterations, mode=args.format)]

    output_data(data, file=args.output_file)


def file_mode(args):

    with open(args.input_file, 'r') as input_file:
        data = []
        for line in input_file:
            if args.salt is None:
                salt = gen_salt(HASH_LEN)
            else:
                salt = args.salt
            plaintext = line.strip().encode('utf8')
            iterations = args.iterations
            hash_res = SCRAMSHA1(plaintext, salt, iterations)
            data.append(hash_format(hash_res, salt, iterations, mode=args.format))

    output_data(data, file=args.output_file)


def main(args=None):
    if args is None:
        args = parse_args(sys.argv[1:])
    else:
        args = parse_args(args)

    # activate modes
    if args.plaintext is not None:
        single_mode(args)
    elif args.input_file is not None:
        file_mode(args)
    else:
        print('Please provide input data or data file', file=sys.stderr)
        exit(1)


def parse_args(args):
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('plaintext', help='data fed to SCRAM-SHA1', nargs='?')
    input_group.add_argument('-f', '--file', help='input file', dest='input_file')
    parser.add_argument('-s', '--salt', help='B64 encoded salt', default=None,
                        type=str, metavar='salt', dest='salt')
    parser.add_argument('-i', '--iter', help='iteration count', default=4096,
                        type=int, metavar='iterations', dest='iterations')
    parser.add_argument('-o', help='output file', type=str, metavar='output_file', dest='output_file')
    parser.add_argument('--format', '-fmt', choices=OUTPUT_FORMATS, help='output format',
                        default='hex', dest='format')
    args = parser.parse_args(args)
    return args


if __name__ == '__main__':
    main()
