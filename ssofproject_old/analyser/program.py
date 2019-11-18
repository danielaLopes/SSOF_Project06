import json
import sys
import re
import os

from analyser.primitives import Stack, Function, Register, Vulnerability
from analyser.util import *

####
# Program Class
#	@desc: Represents all the program internals: variables, functions, instructions
#      		and has methods to analyse if stack buffer overflows happen
#   @param: json parsed input file
#
class Program:
	dangerousFunctions = ['gets', 'strcpy', 'strcat', 'fgets', 'strncpy', 'strncat', '__isoc99_scanf', '__isoc99_fscanf', 'read', 'sprintf', 'snprintf']
	
	ops = ['ret', 'leave', 'nop', 'push', 'pop', 'call', 'mov', 'lea', 'sub', 'add', 'cmp', 'jmp', 'jne', 'je']

	###
	# Program constructor
	# 	@desc: initializes all properties from json parsed filed
	###
	def __init__(self, input_file):
			functions, filename = read(input_file)
			self.input_filename = filename

			self.functions = {}
			self.memory = {}
			self.current_number_arguments = 0
			self.vulnerabilities = list()
			self.zf = False
			#load program functions
			for function in functions:
				self.functions[function] = Function(function, functions[function])

			#bootstrap registers
			self.registers = {
				'rax' : Register(None,None), 'rbx' : Register(None,None), 'rcx' : Register(None,None), 'rdx' : Register(None,None),
				'rdi' : Register(None,None), 'rsi' : Register(None,None),  'r8' : Register(None,None),  'r9' : Register(None,None),
				'r10' : Register(None,None), 'r11' : Register(None,None), 'r12' : Register(None,None), 'r13' : Register(None,None),
				'r14' : Register(None,None), 'r15' : Register(None,None), 'rbp' : Register(None,None), 'rsp' : Register(None,None),
				'rip' : Register(None,None)
			}
			self.parameters = [
				'rdi', 'rsi', 'rdx',\
				'rcx', 'r8' , 'r9'
			]
			#check if program has entry point
			if not 'main' in self.functions:
				raise Exception('Program entry point (main) not found!')

			#bootstrap stack with main program
			self.stack = Stack(self.functions['main'].instructions)
			self.frame = list(['main'])

	def newVulnerability(self, vtype, function, address, ffname=None, overflow_var=None, overflown_var=None, overflown_address=None, op=None):
		self.vulnerabilities.append(Vulnerability(vtype, function, address, ffname, overflow_var, overflown_var, overflown_address, op))
	def getActiveFrame(self):
		return self.frame[-1]
	def getActiveFunction(self):
		current_frame = self.getActiveFrame()
		return self.functions[current_frame]
	# Operations
	
	###
	# MOV Instruction
	#	@desc: emulates a mov instruction 
	###
	def mov(self, inst, step):
		curr_frame = self.frame[len(self.frame)-1]
		dest = inst.args['dest']
		value = inst.args['value']

		if dest[0] == 'e': #convert to 64bits registers we dont care about bits just content
			aux = list(dest)
			aux[0] = 'r'
			dest = "".join(aux)

		#TODO check for QWORD AND PWORD
		if dest in self.registers:
			if value in self.registers:
				self.registers[dest] = Register(self.registers[value].value, self.registers[value].function)
				
				if dest in self.parameters:
					self.current_number_arguments = max([self.current_number_arguments,self.parameters.index(dest)+1])

			else:
				try:
					v = Register(int(value, 0),curr_frame)
				except ValueError:
					if value in self.memory:
						v = Register(self.memory[value].value, self.memory[value].function)
					else:
						v = Register(value,curr_frame)

				self.registers[dest] = v
				
		else:
			assert dest not in self.memory
			flag = True
			if "BYTE PTR" in dest:
				value_of_int = int(value,16)
				address = int(dest[14:-1],16)
				for var in self.functions[curr_frame].variables:
					addressv = int(var.bpaddress(),16)
					finaladdress = addressv - var.size
					if addressv >= address and address > finaladdress:
						flag = False
						if value_of_int == 0:
							aux_value = addressv - address + 1
							var.null_character = aux_value if var.null_character == -1 else min([aux_value,var.null_character])
						break

			if flag and "BYTE PTR" in dest:
				address = dest[14:-1]
				self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, op='mov',
									  overflown_address='rbp-' + address)

			if value in self.registers:
				self.memory[dest] = Register(self.registers[value].value, self.registers[value].function)
			else:
				self.memory[dest] = Register(value,curr_frame)
		###
	
	###
	# CALL Instruction
	#	@desc: emulates a call instruction
	#	@return: next_step
	###
	def call(self,inst,step):
		next_step = step + 1
		fname = inst.extractFunctionName() #extract function name
		if fname in self.dangerousFunctions:
			self.simulateDangerousFunction(fname, inst)

		elif fname in self.functions:
			 #branch to another function
			self.getActiveFunction().last_step = step
			self.frame.append(fname)
			next_step = 0
		

		self.current_number_arguments = 0
		return next_step
	
	###
	# RET Instruction
	#	@desc: emulates a ret instruction
	#	@return: next_step
	###
	def ret(self,inst,step):
		_from = self.frame.pop()
		next_step = 0
		if(self.frame):
			next_step = self.getActiveFunction().last_step + 1
		for register in self.parameters:
			self.registers[register].clean()

		return next_step
	
	###
	# LEA Instruction
	#	@desc: emulates a lea instruction
	###
	def lea(self,inst,step):
		curr_frame = self.frame[len(self.frame)-1]
		dest = inst.args['dest']
		value = inst.args['value'].strip("[]")
		self.registers[dest] = Register(value,curr_frame)
		
		if dest in self.parameters:
			self.current_number_arguments = max([self.current_number_arguments, self.parameters.index(dest) + 1])
	
	###
	# SUB Instruction
	#	@desc: emulates a sub instruction
	###
	def sub(self,inst,step):

		dest = inst.args['dest']
		value = inst.args['value']

		try:
			v = int(value, 0)
			if dest in self.registers:
				vi = int(self.registers[dest], 0)
				result = vi-v
				self.registers[dest] =  hex(result)
			elif dest in self.memory:
				vi = int(self.memory[dest], 0)
				result = vi-v
				self.memory[dest] =  hex(result)
		except :
			()

	###
	# ADD Instruction
	#	@desc: emulates a add instruction
	###
	def add(self,inst,step):
		dest = inst.args['dest']
		value = inst.args['value']
		try:
			v = int(value, 0)
			if dest in self.registers:
				vi = int(self.registers[dest], 0)
				result = vi+v
				self.registers[dest] =  hex(result)
			elif dest in self.memory:
				vi = int(self.memory[dest], 0)
				result = vi+v
			self.memory[dest] =  hex(result)
		except :
			()
	
	###
	# CMP Instruction
	#	@desc: emulates a cmp instruction
	###
	def cmp(self,inst,step):
		arg0 = inst.args['arg0']
		arg1 = inst.args['arg1']

		if arg0 in self.registers and arg1 in self.registers:
			
			self.zf = (self.registers[arg0].value == self.registers[arg1].value)
		elif arg0 in self.registers and arg1 in self.memory:
			self.zf = self.registers[arg0].value == self.memory[arg1].value
		elif arg0 in self.memory and arg1 in self.registers:
			self.zf = self.memory[arg0].value == self.registers[arg1].value
		elif arg0 in self.memory and arg1 in self.memory:
			self.zf = self.memory[arg0].value == self.memory[arg1].value
		else:
			if arg0 in self.registers:
				self.zf = (self.registers[arg0].value == arg1)
			elif arg0 in self.memory:
				self.zf = (self.memory[arg0].value == arg1)
			elif arg1 in self.registers:
				self.zf = (self.registers[arg1].value == arg0)
			elif arg1 in self.memory:
				self.zf = (self.memory[arg1].value == arg0)

	###
	# JMP Instruction
	#	@desc: emulates a JMP instruction
	#	@return: next_step
	###
	def jmp(self,inst,step):
		active_function = self.getActiveFunction()
		for i in active_function.instructions:
			if(i.address == inst.args['address']):
				return i.pos
		return step

	###
	# JE Instruction
	#	@desc: emulates a JE instruction
	#	@return: next_step
	###
	def je(self, inst, step):
		if self.zf:
			return self.jmp(inst, step)
		return step + 1

	###
	# JNE Instruction
	#	@desc: emulates a JNE instruction
	#	@return: next_step
	###
	def jne(self, inst, step):
		if not self.zf:
			return self.jmp(inst, step)
		return step + 1
	
	# Dangerous calls
	###
	# strcpy dangerous function
	#	@desc: emulates a strcpy function
	###
	def _strcpy(self, inst):
		#char *strcpy(char *dest, const char *src);
		dest = self.registers.get(self.parameters[0]) #this will be a register
		src = self.registers.get(self.parameters[1])

		dest_buf = None
		src_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var
		for var in self.functions[src.getFunction()].variables:
			if var.address == src.getValue():
				src_buf = var

		# If buffer has size lower than input
		if (src_buf.size_of_buffer > dest_buf.size and src_buf.null_character == -1) or ( src_buf.null_character >  dest_buf.size):
			address_of_buffer = int(dest_buf.bpaddress(),16)
			address_overflow = address_of_buffer - src_buf.size_of_buffer
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(),16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='strcpy', overflow_var=dest_buf.name,
						  overflown_var=var.name)

			overflow_interval = (address_of_buffer,address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval,interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='strcpy', overflow_var=dest_buf.name,
						 overflown_address='rbp-'+starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='strcpy', overflow_var=dest_buf.name,
						)
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='strcpy', overflow_var=dest_buf.name,
						)
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='strcpy', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = src_buf.size_of_buffer

	###
	# strncpy dangerous function
	#	@desc: emulates a strncpy function
	###
	def _strncpy(self, inst):
		#char *strncpy(char *dest, const char *src, size_t n);
		#If the length of src is less than n, strncpy() writes additional 
		#null bytes to dest to ensure that a total of n bytes are written.
		dest = self.registers.get(self.parameters[0])  # this will be a register
		src = self.registers.get(self.parameters[1])
		n = self.registers.get(self.parameters[2])

		dest_buf = None
		src_buf = None
		size = n.getValue()

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var
		for var in self.functions[src.getFunction()].variables:
			if var.address == src.getValue():
				src_buf = var

		size_copied = min([src_buf.size_of_buffer, size])

		# If buffer has size lower than input
		if src_buf.size_of_buffer >= dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - size_copied
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='strncpy',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer,address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval,interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='strncpy', overflow_var=dest_buf.name,
						 overflown_address='rbp-'+starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='strncpy', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='strncpy', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='strncpy', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

			dest_buf.size_of_buffer = sys.maxsize

		else:
			dest_buf.size_of_buffer = size_copied

	###
	# gets dangerous function
	#	@desc: emulates a gets function
	###
	def _gets(self, inst):
		#char *gets(char *s);
		#the data passed to buffer s comes from stdin so it can be anything
		#so lets throw all vulns
		# char *strcat(char *dest, const char *src);
		# If src contains n or more bytes, strncat() writes n+1 bytes to dest (n from src plus the terminating null byte). Therefore, the size of dest must be at least strlen(dest)+n+1.

		dest = self.registers.get(self.parameters[0])  # this will be a register

		dest_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var

		# Size of input
		_size = sys.maxsize

		# If buffer has size lower than input
		if _size > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - _size
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='gets', overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer,address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval,interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='gets', overflow_var=dest_buf.name,
						 overflown_address='rbp-'+starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='gets', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='gets', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='gets', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = _size

	###
	# fgets dangerous function
	#	@desc: emulates a fgets function
	###
	def _fgets(self, inst):
		# char *strcat(char *dest, const char *src);
		# If src contains n or more bytes, strncat() writes n+1 bytes to dest (n from src plus the terminating null byte). Therefore, the size of dest must be at least strlen(dest)+n+1.

		dest = self.registers.get(self.parameters[0])  # this will be a register
		size = self.registers.get(self.parameters[1])

		dest_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var

		# Size of input
		_size = int(size.getValue())

		# If buffer has size lower than input
		if _size > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - _size
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='fgets', overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer,address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval,interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='fgets', overflow_var=dest_buf.name,
						 overflown_address='rbp-'+starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='fgets', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='fgets', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='fgets', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = _size

	###
	# strcat dangerous function
	#	@desc: emulates a strcat function
	###
	def _strcat(self, inst):
		#char *strcat(char *dest, const char *src);
		#If src contains n or more bytes, strncat() writes n+1 bytes to dest (n from src plus the terminating null byte). Therefore, the size of dest must be at least strlen(dest)+n+1. 
		dest = self.registers.get(self.parameters[0])  # this will be a register
		src = self.registers.get(self.parameters[1])

		dest_buf = None
		src_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var
		for var in self.functions[src.getFunction()].variables:
			if var.address == src.getValue():
				src_buf = var

		size_copied = dest_buf.size_of_buffer + src_buf.size_of_buffer

		# If buffer has size lower than input
		if size_copied > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - size_copied
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='strcat',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer,address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval,interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='strcat', overflow_var=dest_buf.name,
						 overflown_address='rbp-'+starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='strcat', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='strcat', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='strcat', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = size_copied

	###
	# strncat dangerous function
	#	@desc: emulates a strncat function
	###
	def _strncat(self, inst):
		# char * strncat ( char * destination, const char * source, size_t num );
		# If src contains n or more bytes, strncat() writes n+1 bytes to dest (n from src plus the terminating null byte). Therefore, the size of dest must be at least strlen(dest)+n+1.
		dest = self.registers.get(self.parameters[0])  # this will be a register
		src = self.registers.get(self.parameters[1])
		n = self.registers.get(self.parameters[2])

		dest_buf = None
		src_buf = None
		size = n.value

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var
		for var in self.functions[src.getFunction()].variables:
			if var.address == src.getValue():
				src_buf = var

		size_copied = dest_buf.size_of_buffer + min([src_buf.size_of_buffer, size])

		# If buffer has size lower than input
		if size_copied > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - size_copied
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, ffname='strncat',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer, address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval, interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, ffname='strncat',
										  overflow_var=dest_buf.name,
										  overflown_address='rbp-' + starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, ffname='strncat', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, ffname='strncat', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, ffname='strncat',
									  overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = size_copied

	###
	# scanf dangerous function
	#	@desc: emulates a scanf function
	###
	def _scanf(self, inst):

		buffers = []
		for i in range(1,self.current_number_arguments):
			buffers.append(self.parameters[i])

		for input in buffers:
			dest = self.registers.get(input)  # this will be a register
			dest_buf = None

			for var in self.functions[dest.getFunction()].variables:
				if var.address == dest.getValue():
					dest_buf = var

			# Size of input
			_size = sys.maxsize

			# If buffer has size lower than input
			if _size > dest_buf.size:
				address_of_buffer = int(dest_buf.bpaddress(), 16)
				address_overflow = address_of_buffer - _size
				for var in self.functions[dest.getFunction()].variables:
					if var == dest_buf:
						continue
					address_of_var = int(var.bpaddress(), 16)
					if address_of_var > address_overflow and address_of_var < address_of_buffer:
						self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_scanf', overflow_var=dest_buf.name,
											  overflown_var=var.name)

				overflow_interval = (address_of_buffer,address_overflow)
				for interval in self.functions[dest.getFunction()].unreserved_memory:
					if intersection(overflow_interval,interval):
						starting_address = hex(interval[0])
						self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, '__isoc99_scanf', overflow_var=dest_buf.name,
							 overflown_address='rbp-'+starting_address)

				# If it overwrites RBP
				if address_overflow < 0:
					self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_scanf', overflow_var=dest_buf.name,
										  )
				# If it overwrites RET
				if address_overflow < -8:
					self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_scanf', overflow_var=dest_buf.name,
										  )
				# If it overwrites other frame
				if address_overflow < -16:
					self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, '__isoc99_scanf', overflow_var=dest_buf.name,
										  overflown_address="rbp+0x10")

			dest_buf.size_of_buffer = _size

	###
	# fscanf dangerous function
	#	@desc: emulates a fscanf function
	###
	def _fscanf(self, inst):

		buffers = []
		for i in range(2,self.current_number_arguments):
			buffers.append(self.parameters[i])

		for input in buffers:
			dest = self.registers.get(input)  # this will be a register
			dest_buf = None

			for var in self.functions[dest.getFunction()].variables:
				if var.address == dest.getValue():
					dest_buf = var

			# Size of input
			_size = sys.maxsize

			# If buffer has size lower than input
			if _size > dest_buf.size:
				address_of_buffer = int(dest_buf.bpaddress(), 16)
				address_overflow = address_of_buffer - _size
				for var in self.functions[dest.getFunction()].variables:
					if var == dest_buf:
						continue
					address_of_var = int(var.bpaddress(), 16)
					if address_of_var > address_overflow and address_of_var < address_of_buffer:
						self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_fscanf', overflow_var=dest_buf.name,
											  overflown_var=var.name)

				overflow_interval = (address_of_buffer,address_overflow)
				for interval in self.functions[dest.getFunction()].unreserved_memory:
					if intersection(overflow_interval,interval):
						starting_address = hex(interval[0])
						self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, '__isoc99_fscanf', overflow_var=dest_buf.name,
							 overflown_address='rbp-'+starting_address)

				# If it overwrites RBP
				if address_overflow < 0:
					self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_fscanf', overflow_var=dest_buf.name,
										  )
				# If it overwrites RET
				if address_overflow < -8:
					self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, '__isoc99_fscanf', overflow_var=dest_buf.name,
										  )
				# If it overwrites other frame
				if address_overflow < -16:
					self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, '__isoc99_fscanf', overflow_var=dest_buf.name,
										  overflown_address="rbp+0x10")

			dest_buf.size_of_buffer = _size

	###
	# read dangerous function
	#	@desc: emulates a read function
	###
	def _read(self, inst):


		dest = self.registers.get(self.parameters[1])  # this will be a register
		size = self.registers.get(self.parameters[2])
		

		dest_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var

		# Size of input
		_size = int(size.getValue())

		# If buffer has size lower than input
		if _size > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - _size
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, 'read',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer, address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval, interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, 'read',
										  overflow_var=dest_buf.name,
										  overflown_address='rbp-' + starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, 'read', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, 'read', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, 'read', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = _size

	###
	# snprintf dangerous function
	#	@desc: emulates a snprintf function
	###
	def _snprintf(self, inst):
		dest = self.registers.get(self.parameters[0])  # this will be a register
		size = self.registers.get(self.parameters[1]).value

		size_aux = 0
		for i in range(2,self.current_number_arguments):
			src = self.registers.get(self.parameters[i])
			for var in self.functions[src.getFunction()].variables:
				if var.address == src.getValue():
					size_aux += var.size_of_buffer

		dest_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var

		# Size of input
		_size = min([size_aux,size])

		# If buffer has size lower than input
		if _size > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - _size
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, 'snprintf',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer, address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval, interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, 'snprintf',
										  overflow_var=dest_buf.name,
										  overflown_address='rbp-' + starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, 'snprintf', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, 'snprintf', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, 'snprintf', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = _size

	###
	# sprintf dangerous function
	#	@desc: emulates a sprintf function
	###
	def _sprintf(self, inst):
		dest = self.registers.get(self.parameters[0])  # this will be a register

		size_aux = 0
		for i in range(2,self.current_number_arguments):
			src = self.registers.get(self.parameters[i])
			for var in self.functions[src.getFunction()].variables:
				if var.address == src.getValue():
					size_aux += var.size_of_buffer

		dest_buf = None

		for var in self.functions[dest.getFunction()].variables:
			if var.address == dest.getValue():
				dest_buf = var

		# Size of input
		_size = size_aux

		# If buffer has size lower than input
		if _size > dest_buf.size:
			address_of_buffer = int(dest_buf.bpaddress(), 16)
			address_overflow = address_of_buffer - _size
			for var in self.functions[dest.getFunction()].variables:
				if var == dest_buf:
					continue
				address_of_var = int(var.bpaddress(), 16)
				if address_of_var > address_overflow and address_of_var < address_of_buffer:
					self.newVulnerability('VAROVERFLOW', self.getActiveFrame(), inst.address, 'sprintf',
										  overflow_var=dest_buf.name,
										  overflown_var=var.name)

			overflow_interval = (address_of_buffer, address_overflow)
			for interval in self.functions[dest.getFunction()].unreserved_memory:
				if intersection(overflow_interval, interval):
					starting_address = hex(interval[0])
					self.newVulnerability('INVALIDACCS', self.getActiveFrame(), inst.address, 'sprintf',
										  overflow_var=dest_buf.name,
										  overflown_address='rbp-' + starting_address)

			# If it overwrites RBP
			if address_overflow < 0:
				self.newVulnerability('RBPOVERFLOW', self.getActiveFrame(), inst.address, 'sprintf', overflow_var=dest_buf.name,
									  )
			# If it overwrites RET
			if address_overflow < -8:
				self.newVulnerability('RETOVERFLOW', self.getActiveFrame(), inst.address, 'sprintf', overflow_var=dest_buf.name,
									  )
			# If it overwrites other frame
			if address_overflow < -16:
				self.newVulnerability('SCORRUPTION', self.getActiveFrame(), inst.address, 'sprintf', overflow_var=dest_buf.name,
									  overflown_address="rbp+0x10")

		dest_buf.size_of_buffer = _size

	###
	# simulateDangerousFunction
	#	@desc: simulates the behavior of a dangerous function from its function name
	###
	def simulateDangerousFunction(self,name, inst):

		# Basic
		if   name == 'gets':
			self._gets(inst) #done

		elif name == 'strcpy': #done
			self._strcpy(inst)

		elif name == 'strcat':
			self._strcat(inst) #done

		elif name == 'fgets': #done
			self._fgets(inst)

		elif name == 'strncpy': #done
			self._strncpy(inst)

		elif name == 'strncat':
			self._strncat(inst)

		# Advanced
		elif name == 'sprintf':
			self._sprintf(inst)

		elif name == '__isoc99_scanf':
			self._scanf(inst)

		elif name == '__isoc99_fscanf':
			self._fscanf(inst)

		elif name == 'snprintf':
			self._snprintf(inst)

		elif name == 'read':
			self._read(inst)

	###
	# execute
	#	@desc: executes instruction
	###
	def execute(self, inst, step):
		next_step = step + 1
		if inst.op == 'mov':
			self.mov(inst,step)

		elif inst.op == 'call':
			next_step = self.call(inst,step)

		elif inst.op == 'ret':
			next_step = self.ret(inst,step)

		elif inst.op == 'lea':
			self.lea(inst,step)

		elif inst.op == 'sub':
			self.sub(inst,step)

		elif inst.op == 'add':
			self.add(inst,step)

		elif inst.op == 'cmp':
			self.cmp(inst,step)

		elif inst.op == 'jmp':
			next_step = self.jmp(inst, step)
		
		elif inst.op == 'je':
			next_step = self.je(inst, step)
		
		elif inst.op == 'jne':
			next_step = self.jne(inst, step)
		
		return next_step

	###
	# analyse
	#	@desc: starts the static analysis
	###
	def analyse(self):
		step = 0
		while len(self.frame) > 0:
			inst = self.getActiveFunction().getInstruction(step) #get instruction object
			step = self.execute(inst, step)
	###
	# dump
	#	@desc: dumps all vulnerabilities found to a file in the script folder
	###		
	def dump(self):
		output_file = self.input_filename.split('.')[0]+".output.json"
		output_vuls = []

		for vul in self.vulnerabilities:
			fixed_vul = del_nones(vul.__dict__)
			output_vuls.append(fixed_vul)
				
		with open(output_file, 'w') as f:
				json.dump(output_vuls, f, indent=4)

            # with open(output_file, 'w') as f:
            #     f.write(str)