import os
import json

def intersection(a,b):
	a1,a2 = a
	b1,b2 = b
	return not ((min([b1,b2]) >= max([a1,a2])) or (min([a1,a2]) >= max([b1,b2])))

def del_nones(obj):
	for key,value in list(obj.items()):
		if value is None:
			del obj[key]
		elif isinstance(value, dict):
			del_nones(value)
	return obj

def read(filename):
	# Open File and Parse it
	try:
		f = open(filename)
		data = json.load(f)
		return data, os.path.basename(f.name)
	except FileNotFoundError:
		print('File not found!')
	except json.decoder.JSONDecodeError:
		print('Error trying to parse')
