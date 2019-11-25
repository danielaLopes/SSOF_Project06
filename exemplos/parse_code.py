import ast
import json
from ast2json import ast2json
import sys

parsed = ast2json(ast.parse(open(sys.argv[1]).read()))
f = open(sys.argv[1]+".json", "w")
f.write(json.dumps(parsed, indent=4))
f.close()

