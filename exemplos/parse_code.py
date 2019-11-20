import ast
import json
from ast2json import ast2json

exemplo = ast2json(ast.parse(open('exemplo1.py').read()))
print(json.dumps(exemplo, indent=4))
