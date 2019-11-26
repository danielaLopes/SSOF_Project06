class AST(object):
    def __init__(self, body):
        self.body = body

    def __repr__(self):
        return 'AST(%s)' % self.body

    def get_analyzed(self, analyzer):
        return analyzer.analyze_ast(self)


class Body(object):
    def __init__(self, nodes):
        # list of all the ast tree nodes
        self.nodes = nodes

    def __repr__(self):
        return 'Body(%s)' % self.nodes

    def get_analyzed(self, analyzer):
        return analyzer.analyze_body(self)


class BodyNode(Body):
    def get_analyzed(self, analyzer):
        analyzer.analyze_body_node(self)


class Assign(BodyNode):
    def __init__(self, vars, expr):
        self.vars = vars
        self.expr = expr

    def __repr__(self):
        return 'Assign(%s, %s)' % (self.vars, self.expr)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_assign(self)


class If(BodyNode):
    def __init__(self, body, orelse, test):
        self.body = body
        self.orelse = orelse
        self.test = test

    def __repr__(self):
        return 'If(%s, %s, %s)' % (self.test, self.body, self.orelse)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_if(self)


class While(BodyNode):
    def __init__(self, body, test):
        self.body = body
        self.test = test

    def __repr__(self):
        return 'While(%s, %s)' % (self.test, self.body)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_while(self)


class Expr(BodyNode):
    def get_analyzed(self, analyzer):
        return analyzer.analyze_expr(self)

class Func:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'Func(%s)' % self.name

    def get_analyzed(self, analyzer):
        return analyzer.analyze_func(self)


class FuncCall(Expr):
    def __init__(self, args, func):
        self.args = args
        self.func = func

    def __repr__(self):
        return 'FuncCall(%s, %s)' % (self.args, self.func)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_func_call(self)


class Attribute:
    def __init__(self, attr, value):
        self.attr = attr
        self.value = value

    def __repr__(self):
        return 'Attribute(%s, %s)' % (self.attr, self.value)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_attribute(self)


class VarExpr(Expr):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'VarExpr(%s)' % self.name

    def get_analyzed(self, analyzer):
        return analyzer.analyze_var_expr(self)


class NumExpr(Expr):
    def __init__(self, n):
        self.n = n

    def __repr__(self):
        return 'NumExpr(%s)' % self.n

    def get_analyzed(self, analyzer):
        return analyzer.analyze_num_expr(self)


class StrExpr(Expr):
    def __init__(self, str):
        self.str = str

    def __repr__(self):
        return 'StrExpr(%s)' % self.str

    def get_analyzed(self, analyzer):
        return analyzer.analyze_str_expr(self)


class NameConstantExpr(Expr):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return 'NameConstantExpr(%s)' % self.value

    def get_analyzed(self, analyzer):
        return analyzer.analyze_name_constant_expr(self)


class BinOp(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __repr__(self):
        return 'BinOp(%s, %s)' % (self.left, self.right)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_bin_op(self)


class BoolOp(Expr):
    def __init__(self, left, comparator):
        self.left = left
        self.comparator = comparator

    def __repr__(self):
        return 'BoolOp(%s, %s)' % (self.left, self.comparator)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_bool_op(self)


class UnaryOp(Expr):
    def __init__(self, operand):
        self.operand = operand

    def __repr__(self):
        return 'UnaryOp(%s)' % self.operand

    def get_analyzed(self, analyzer):
        return analyzer.analyze_unary_op(self)


class Tuple(Expr):
    def __init__(self, el1, el2):
        self.el1 = el1
        self.el2 = el2

    def __repr__(self):
        return 'Tuple(%s, %s)' % (self.el1, self.el2)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_tuple(self)