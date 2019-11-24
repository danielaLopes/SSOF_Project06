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

    """def level(self, analyzer):
        if self.var.name not in analyzer.decl_vars:
            analyzer.decl_vars[self.var.name] = self.var.level(analyzer)
        else:
            if type(analyzer.decl_vars[self.var.name]) == type(list()):
                analyzer.decl_vars[self.var.name].append(self.expr.level(analyzer))
            else:
                analyzer.decl_vars[self.var.name] = [self.expr.level(analyzer)]
        return self.expr.level(analyzer)"""

    """def analyze(self, analyzer):
        label = {"kind": ast_type, "var": self.var, "explevel": self.expr.level()}
        analyzer.analyze_illegal_flows(label)"""

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
    pass
    """def __init__(self, value, sources):
        self.value = value # value['n']
        self.sources = sources

    def __repr__(self):
        return 'Expr(%s, %s)' % (self.type, self.value)

    def analyze(self, analyzer):
        label = {"kind": ast_type, "var": self.name, "explevel": self.exp.level()}
        analyzer.analyze_illegal_flows(label)"""

    def get_analyzed(self, analyzer):
        return analyzer.analyze_expr(self)

class Func:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'Func(%s)' % self.name

    """def kind(self, analyzer):
        for pattern in analyzer.patterns:
            if self.name in pattern.sources:
                return "SOURCE", pattern
            elif self.name in pattern.sanitizers:
                return "SANITIZER", pattern
            elif self.name in pattern.sinks:
                return "SINK", pattern
            else:
                return "NORMAL", pattern"""

    def get_analyzed(self, analyzer):
        return analyzer.analyze_func(self)

class FuncCall(Expr):
    def __init__(self, args, func):
        self.args = args
        self.func = func

    def __repr__(self):
        return 'FuncCall(%s, %s)' % (self.args, self.func)

    """def level(self, analyzer):
        kindTuple = self.func.kind(analyzer)
        kind = kindTuple[0]
        pattern = kindTuple[1]
        if kind == "SOURCE":
            return "TAINTED"

        elif kind == "SANITIZER":
            return self.func.name

        else:
            sanitizers = []
            funcLevel = ""
            for arg in self.args:
                level = arg.level(analyzer)
                if type(level) == type(list()):
                    sanitizers.extend(level)
                else:
                    if level == "TAINTED":
                        funcLevel = "TAINTED"

            if kind == "SINK":
                analyzer.vulnerabilities.append({"vulnerability": pattern.vulnerability,
                                                 "source": "",
                                                 "sink": self.func.name,
                                                 "sanitizer": sanitizers})

        if len(sanitizers) == 0:
            if funcLevel == "TAINTED":
                return "TAINTED"
            else:
                return "UNTAINTED"
        else:
            return sanitizers"""

    def get_analyzed(self, analyzer):
        return analyzer.analyze_func_call(self)


#class Attribute:


class VarExpr(Expr):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'VarExpr(%s)' % self.name

    """def level(self, analyzer):
        if self.name in analyzer.decl_vars:
            return analyzer.decl_vars[self.name]
        else:
            return "TAINTED"
            """

    def get_analyzed(self, analyzer):
        return analyzer.analyze_var_expr(self)


class NumExpr(Expr):
    def __init__(self, n):
        self.n = n

    def __repr__(self):
        return 'NumExpr(%s)' % self.n

    """def level(self, analyzer):
        return "UNTAINTED"
        """

    def get_analyzed(self, analyzer):
        return analyzer.analyze_num_expr(self)


class StrExpr(Expr):
    def __init__(self, str):
        self.str = str

    def __repr__(self):
        return 'StrExpr(%s)' % self.str

    """def level(self, analyzer):
        return "UNTAINTED"
        """

    def get_analyzed(self, analyzer):
        return analyzer.analyze_str_expr(self)
