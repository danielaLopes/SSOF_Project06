#!/usr/bin/python3
import json

def find_vulnerability(slice_file,pattern_list):
	slice = json.load(slice_file)
	for key,value in slice.items():
		print(key,value)
		
