from analyzer_ast import *
import json


class AstParser:

    def __init__(self):
        self.type_string = None

    def parse(self, slice_file):
        slice = json.load(slice_file)
        # to enable both teacher's given ast and python's ast
        if "ast_type" in slice:
            self.type_string = "ast_type"
        else:
            self.type_string = "_type"
        return self.parse_ast(slice)

    def parse_ast(self, slice):
        return AST(self.parse_body(slice["body"]))

    def parse_body(self, lst):
        nodes = []
        for dict in lst:
            nodes.append(self.parse_body_node(dict))
        return Body(nodes)

    def parse_body_node(self, node):
        if node[self.type_string] == 'Assign':
            # TODO TEMPORARY if we can to enable a,b = 3, we need to change this,
            # for now we only need to enable a = 3
            return self.parse_assign(node['targets'], node['value'])
        elif node[self.type_string] == 'Expr':
            return self.parse_expr(node['value'])
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
        targetList = []
        for target in targets:
            targetList.append(self.parse_expr(target))
        return targetList

    def parse_expr(self, value):
        if value[self.type_string] == 'Num':
            return NumExpr(value['n'])
        elif value[self.type_string] == 'Name':
            return self.parse_var_expr(value['id'])
        elif value[self.type_string] == 'Str':
            return StrExpr(value['s'])
        elif value[self.type_string] == 'Call':
            return self.parse_func_call(value['args'], value['func'])

    def parse_var_expr(self, id):
        return VarExpr(id)

    def parse_func_call(self, args, func):
        argList = []
        for arg in args:
            argList.append(self.parse_expr(arg))
        return FuncCall(argList, Func(func['id']))