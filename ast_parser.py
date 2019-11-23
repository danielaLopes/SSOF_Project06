from analyzer_ast import *
import json


class AstParser:

    def __init__(self):
        self.type_string = None

    """def parse(self, slice_file):
        slice = json.load(slice_file)
        if "ast_type" in slice:
            self.type_string = "ast_type"
        else:
            self.type_string = "_type"
        return self.recursive(slice, [])

    def recursive(self, slice, slice_items):
        if type(slice) == type(dict()):
            if slice[self.type_string] == "Assign":
                arg1 = self.recursive(slice["targets"][0], [])
                arg2 = self.recursive(slice["value"], [])
                slice_items.append(Assign(arg1[0], arg2[0]))
            elif slice[self.type_string] == "Name":
                slice_items.append(VarExpr(slice["id"]))
            elif slice[self.type_string] == "Num":
                slice_items.append(NumExpr(slice["n"]))
            elif slice[self.type_string] == "Call":
                # args, func
                # missing attribute!!!
                args = []
                for arg in slice["args"]:
                    args.extend(self.recursive(arg, []))
                print("args {}".format(args))
                slice_items.append(FuncCall(args, Func(slice["func"]["id"])))
            elif slice[self.type_string] == "Expr":
                self.recursive(slice["value"], slice_items)
            else:
                for key, value in slice.items():

                    if type(value) == type(list()):
                        print("list key:{}, value:{}\n".format(key, value))
                        for value_list in value:

                            self.recursive(value_list, slice_items)

                    elif type(value) == type(str()) or type(value) == type(int()):
                        print("string key:{}, value:{}\n".format(key, value))


        return slice_items

    #def create_node(self, ):"""

    def parse(self, slice_file):
        slice = json.load(slice_file)
        # to enable both teacher's given ast and python's ast
        if "ast_type" in slice:
            self.type_string = "ast_type"
        else:
            self.type_string = "_type"
        return self.parseAST(slice)

    def parse_ast(self, slice):
        return AST(self.parse_body(slice["body"]))

    def parse_body(self, lst):
        nodes = []
        for dict in lst:
            print(dict)
            nodes.append(self.parse_body_node(dict[self.type_string]))
        return Body(nodes)

    def parse_body_node(self, node):
        if node[self.type_string] == 'Assign':
            return self.parse_assign(node['targets'], node['value'])
        elif node[self.type_string] == 'If':
            return self.parseIf()
        elif node[self.type_string] == 'While':
            return self.parseWhile()

    def parse_assign(self, targets, value):
        return Assign(self.parse_targets(targets), self.parse_expr(value))

    def parse_if(self):
        pass

    def parse_while(self):
        pass

    def parse_targets(self, targets):
        pass

    def parse_expr(self, value):
        if value[self.type_string] == 'Num':
            return NumExpr(value['n'])
        elif value[self.type_string] == 'Name':
            return VarExpr(value['id'])
        elif value[self.type_string] == 'Str':
            return StrExpr(value['s'])
        elif value[self.type_string] == 'Call':
            return self.parse_func_call(value['args'], value['func'])

    def parse_func_call(self, args, func):
        argList = []
        for arg in args:
            argList.append(parseExpr(arg))
        return FuncCall(argList, Func(func['id']))