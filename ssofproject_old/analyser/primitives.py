import re
###
# Stack Class
#	@desc: object that represents instruction stack
###
class Stack:
	def __init__(self, items=None):
		if items:
			self.mem = list(items)
			self.mem.reverse() #FILO
		else:	
			self.mem = []
	
	def pop(self):
		return self.mem.pop()
	
	def push(self, item):
		return self.mem.append(item)
	
	def empty(self):
		return len(self.mem) == 0

	def peek(self):
		return self.mem[len(self.mem)-1]
    
	def getItem(self, position):
		try:
			item = self.mem[position]
			return item
		except IndexError:
			return None
    
	#This way we can branch to another function and then come back to the same place just by popping
	def branch(self, step, items):
		rvr = list(items)
		rvr.reverse()
		self.mem[step:step] = rvr

###
# Variable
#	@desc: object that represents a function variable
###
class Variable:
	def __init__(self, obj):
		self.size = obj['bytes']
		self.type = obj['type']
		self.name = obj['name']
		self.address = obj['address']
		self.size_of_buffer = 0
		self.null_character = -1

	def bpaddress(self):
		return self.address[4:]

###
# Instruction
#	@desc: object that represents a instruction
###
class Instruction:
	def __init__(self, obj):
		self.op = obj['op']
		self.pos = obj['pos']
		self.address = obj['address']
		if 'args' in obj:
			self.args = obj['args']

	###
	# extractFunctionName
	#	@desc: extracts function name from instruction
	#	@return: string - function name or Nome if not found
	###
	def extractFunctionName(self):
		if self.op == 'call':
			matches = re.search('<(\w+)(@(\w+))?>', self.args['fnname']).groups()
			return matches[0]
		return None

###
# Function Class
#	@desc: object that represents a user defined function
###
class Function:
	def __init__(self, name, obj):
		self.name = name
		self.variables = []
		self.instructions = []
		self.unreserved_memory = [] # Intervals (ebp-0xA, ebp-0xB) === (A,B)
		
		self.last_step = None
		
		for v in obj['variables']:
			self.variables.append(Variable(v))

		for i in obj['instructions']:
			self.instructions.append(Instruction(i))

		self.variables = sorted(self.variables, key=lambda d: int(d.address[4:],16))

		# Intervals
		for v in range(len(self.variables)-1):
			variable1 = self.variables[v]
			variable2 = self.variables[v+1]
			address1 = int(variable1.bpaddress(),16)
			address2 = int(variable2.bpaddress(),16)
			diff = address2 - variable2.size
			if diff > address1:
				self.unreserved_memory.append((diff,address1))


		if len(self.variables) > 0:
			variable1 = self.variables[0]
			address1 = int(variable1.bpaddress(), 16)
			diff = address1 - variable1.size
			if diff > 0:
				self.unreserved_memory.append((diff, 0))
	###
	# getInstruction
	#	@desc: returns instruction from position (x) in the stack
	#	@returns: instruction object or None if not found
	###
	def getInstruction(self, position):
		try:
			inst = self.instructions[position]
			return inst
		except:
			return None
		
###
# Register Class
#	@desc: represents a virtual register
###
class Register:
	def __init__(self, value, function):
		self.value = value
		self.function = function
	
	###
	# clean
	#	@desc: cleans a register
	###
	def clean(self):
		self.value = None
		self.function = None
		self.size = None

	###
	# getValue
	#	@desc: returns register value
	#	@return: regiter value
	###
	def getValue(self):
		return self.value

	###
	# getFunction
	#	@desc: returns register function i.e. the function where the register was last set
	#	@return: function object
	###
	def getFunction(self):
		return self.function
	
	###
	# __str__
	#	@desc: magic method to print the register tupple
	###
	def	__str__(self):
		return str(self.value) + ' ' + str(self.function)

###
# Vulnerability Class
#	@desc: object that represents a vulnerability in the given program
###
class Vulnerability:

	types = ['VAROVERFLOW', 'RBPOVERFLOW', 'RETOVERFLOW', 'INVALIDCCS', 'SCORRUPTION']

	def __init__(self, vtype, function, address, ffname=None, overflow_var=None, overflown_var=None, overflown_address=None, op=None):
		self.vulnerability = vtype
		self.vuln_function = function
		self.address = address
		self.fnname = ffname
		self.overflow_var = overflow_var
		self.overflown_var = overflown_var
		self.overflown_address = overflown_address
		self.op = op

