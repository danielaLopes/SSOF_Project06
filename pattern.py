#!/usr/bin/python3
import json

class Pattern:
	def __init__(self, vulnerability, sources,sanitizers,sinks):
		self.vulnerability= vulnerability
		self.sources= sources
		self.sanitizers= sanitizers
		self.sinks= sinks


def parse(json_pattern_file):
	pattern_list = []
	parsed_json_pattern_list = json.load(json_pattern_file)
	#print(parsed_json_pattern_list)

	for json_pattern in parsed_json_pattern_list:
		#print(json_pattern)
		pattern = Pattern(json_pattern['vulnerability'],json_pattern['sources'],json_pattern['sanitizers'],json_pattern['sinks'])
		#print(pattern)
		pattern_list.append(pattern)
		
	return pattern_list