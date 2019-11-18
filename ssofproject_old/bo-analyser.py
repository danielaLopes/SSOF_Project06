import json
import sys
import re
import os
from operator import itemgetter

from analyser.program import Program


if __name__ == "__main__":

	# Check if file is in arguments
	if( len(sys.argv) != 2 ):
		print('You need to insert a file!')
		exit(1)

	# Read Input Json File
	input_file = sys.argv[1]	

	program = Program(input_file)
	program.analyse()
	program.dump()
