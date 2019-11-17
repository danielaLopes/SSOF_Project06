#!/usr/bin/python3
import json

def find_vulnerability(slice_file,pattern_list):
	slice = json.load(slice_file)
	recursive(slice,pattern_list)


def recursive(slice,pattern_list):
	for key,value in slice.items():
		#print(str(key),'->',str(value))

		if type(value) == type(dict()):
			recursive(value,pattern_list)
		elif type(value) == type(list()):
			for v in value:
				#if type(v) == type(str()):
					#print('v string ',v)
				#elif type(v) == type(list()):
					#print('v list ',v)
				#else:
					#print('v ',v)
					recursive(v,pattern_list)

		elif type(value) == type(str()):
			#print('FINAL: ',value)
			for pattern in pattern_list:
				#print('sinks ',pattern.sinks)
				if value in pattern.sinks:
					print('vulnerability ',value, ' DETECTED')
			
