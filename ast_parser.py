#!/usr/bin/python3
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
            return self.parse_assign(node['targets'], node['value'])
        elif node[self.type_string] == 'Expr':
            return self.parse_expr(node['value'])
        elif node[self.type_string] == 'If':
            return self.parse_if(node['body'], node['orelse'], node['test'])
        elif node[self.type_string] == 'While':
            return self.parse_while(node['body'], node['test'])

    def parse_assign(self, targets, value):
        # we only support assign for a varible at a time
        return Assign(self.parse_expr(targets[0]), self.parse_expr(value))

    def parse_if(self, body, orelse, test):
        test_node = self.parse_expr(test)

        body_nodes = []
        for dict in body:
            body_nodes.append(self.parse_body_node(dict))
        orelse_nodes = []
        for dict in orelse:
            orelse_nodes.append(self.parse_body_node(dict))

        return If(body_nodes, orelse_nodes, test_node)

    def parse_while(self, body, test):
        test_node = self.parse_expr(test)

        body_nodes = []
        for dict in body:
            body_nodes.append(self.parse_body_node(dict))

        return While(body_nodes, test_node)

    def parse_expr(self, value):
        if value[self.type_string] == 'Num':
            return NumExpr(value['n'])
        elif value[self.type_string] == 'Name':
            return self.parse_var_expr(value['id'])
        elif value[self.type_string] == 'Str':
            return StrExpr(value['s'])
        elif value[self.type_string] == 'NameConstant':
            return NameConstantExpr(value['value'])
        elif value[self.type_string] == 'Call':
            return self.parse_func_call(value['args'], value['func'])
        elif value[self.type_string] == 'Attribute':
            return self.parse_attribute(value['attr'], value['value'])
        elif value[self.type_string] == 'BinOp':
            return self.parse_bin_op(value['left'], value['right'])
        elif value[self.type_string] == 'Compare':
            return self.parse_bin_op(value['left'], value['comparators'][0])
        elif value[self.type_string] == 'BoolOp':
            return self.parse_bool_op(value['values'][0], value['values'][1])
        elif value[self.type_string] == 'UnaryOp':
            return self.parse_unary_op(value['operand'])
        elif value[self.type_string] == 'Tuple':
            return self.parse_tuple(value['elts'])

    def parse_var_expr(self, id):
        return VarExpr(id)

    def parse_func_call(self, args, func):
        argList = []
        for arg in args:
            argList.append(self.parse_expr(arg))
        # distinguish cases where func is an attribute
        if 'id' in func:
            return FuncCall(argList, Func(func['id']))
        elif 'attr' in func:
            return FuncCall(argList, Func(func['attr']))

    def parse_attribute(self, attr, value):
        return Attribute(self.parse_var_expr(attr), self.parse_expr(value))

    def parse_bin_op(self, left, right):
        left_node = self.parse_expr(left)
        right_node = self.parse_expr(right)
        return BinOp(left_node, right_node)

    def parse_bool_op(self, left, comparator):
        left_node = self.parse_expr(left)
        comparator_node = self.parse_expr(comparator)
        return BoolOp(left_node, comparator_node)

    def parse_unary_op(self, operand):
        operand_node = self.parse_expr(operand)
        return UnaryOp(operand_node)

    def parse_tuple(self, elements):
        el1 = self.parse_expr(elements[0])
        el2 = self.parse_expr(elements[1])
        return Tuple(el1, el2)