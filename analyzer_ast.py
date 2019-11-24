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
        return 'If(%s, %s, %s)' % (self.body, self.orelse ,self.test)

    def get_analyzed(self, analyzer):
        return analyzer.analyze_if(self)


class While(BodyNode):
    def __init__(self, body, orelse, test):
        self.body = body
        self.orelse = orelse
        self.test = test

    def __repr__(self):
        return 'While(%s, %s, %s)' % (self.body, self.orelse ,self.test)

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


#class Attribute:


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
