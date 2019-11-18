#!/usr/bin/python3
import json
import ast


def find_vulnerability(slice_file,pattern_list):
	slice = json.load(slice_file)
	#recursive_old(slice,pattern_list)
	slice_items = recursive(slice,[])
	result(slice_items,pattern_list)


def recursive_old(slice,pattern_list):
	for key,value in slice.items():
		#print(str(key),'->',str(value))
		if type(value) == type(dict()):
			recursive(value,pattern_list)
			#print('test')
		elif type(value) == type(list()):
			for value_list in value:
				#print('list:',key)
				recursive(value_list,pattern_list)

		elif type(value) == type(str()) or type(value) == type(int()):
			#print('FINAL-> key:',key,' value:',value)
			for pattern in pattern_list:
				#print('sinks ',pattern.sinks)
				if value in pattern.sinks or value in pattern.sources or value in pattern.sanitizers:
					print('vulnerability ',value, ' DETECTED')


def recursive(slice,slice_items):
	for key,value in slice.items():
		#print(str(key),'->',str(value))
		if type(value) == type(dict()):
			recursive(value,slice_items)
			#print('test')
		elif type(value) == type(list()):
			for value_list in value:
				#print('list:',key)
				recursive(value_list,slice_items)

		elif type(value) == type(str()) or type(value) == type(int()):
			#print('FINAL-> key:',key,' value:',value)
			slice_items.append([key,value])
	return slice_items
			

def result(slice_items,pattern_list):
	leaf = []
	current_col = 0
	i = 0
	#print(slice_items)
	for items in slice_items:
		leaf.append(items)
		if (items[0] == 'col_offset' and current_col!= items[1]) or (i+1)==len(slice_items):
			current_col = items[1]
			#print('LEAF')
			#print(leaf[:-2])

			for current_leaf in leaf[:-2]:
				leaf_value = current_leaf[1]
				#print(leaf_value)
				#print('test',leaf[2:])

				for pattern in pattern_list:
					if leaf_value in pattern.sinks or leaf_value in pattern.sources or leaf_value in pattern.sanitizers:
						print('vulnerability ',leaf_value, ' DETECTED')
						
				for pattern in pattern_list:
					if leaf_value in pattern.sinks and 'attr'==current_leaf[0] and in_leaf('Call',leaf[:-2]) and in_leaf('cursor',leaf[:-2]):
						print('vulnerability ',leaf_value, ' SQL INJECTION DETECTED')
			leaf = [slice_items[i-1],items]
		i=i+1

def in_leaf(name,leaf):
	for current_leaf in leaf:
		if name == current_leaf[1]:
			return True
	return False
				