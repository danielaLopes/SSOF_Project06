import sys
import json
import pprint

def read(filename):

    # Open File and Parse it
    try:
        f = open(filename)
        data = json.load(f)
        return data
    except FileNotFoundError:
        print('File not found!')
    except json.decoder.JSONDecodeError:
        print('Error trying to parse')


if __name__ == "__main__":

    # Check if file is in arguments
    if (len(sys.argv) != 3):
        print('You need to insert two file!')
        exit(1)

    read1 = read(sys.argv[1])
    read2 = read(sys.argv[2])

    if len(read1) != len(read2):
        print('NOT EQUAL!')
        exit(1)


    for dict in read2:
        if dict not in read1:
            print(dict)
            print('NOT EQUAL!')
            exit(1)

    print('EQUAL!')
    exit(1)

