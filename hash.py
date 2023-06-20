#!/usr/bin/python3
import argparse
import numpy

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))


def push_function_hash(function_name):
    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    return ("push " + hex(edx))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Calculate hash value for function names.')
    parser.add_argument('function_names', type=str, help='Comma-separated names of the functions')
    args = parser.parse_args()

    function_names = args.function_names.split(',')

    max_name_length = max(len(name.strip()) for name in function_names)

    for function_name in function_names:
        name = function_name.strip()
        function_hash = push_function_hash(name)
        output = '[ {:<{}} ]: {}'.format(name, max_name_length, function_hash)
        print(output)