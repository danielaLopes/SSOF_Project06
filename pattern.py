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
		add = True
		
		#print(pattern)
		if(len(pattern_list) != 0):
			for e in pattern_list:
				if(json_pattern['vulnerability'] == e.vulnerability):
					e.sources = e.sources + list(set(json_pattern['sources']) - set(e.sources))
					e.sanitizers = e.sanitizers + list(set(json_pattern['sanitizers']) - set(e.sanitizers))
					e.sinks = e.sinks + list(set(json_pattern['sinks']) - set(e.sinks))
					add = False
		if(add):	
			pattern = Pattern(json_pattern['vulnerability'],json_pattern['sources'],json_pattern['sanitizers'],json_pattern['sinks'])
			pattern_list.append(pattern)
		
	for e in pattern_list:
		print(e.vulnerability)
		print(e.sources)
		print(e.sanitizers)
		print(e.sinks)
	return pattern_list