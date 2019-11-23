from analyzer_ast import *

class Analyzer:

    def __init__(self, patterns):
        self.patterns = patterns
        self.decl_vars = {}
        self.state = []
        # output vulnerabilities are constructed during ast parsing with analyzer
        self.vulnerabilities = []

    #def analyze_illegal_flows(self, label):
    #    pass

    def analyze_ast(self, ast):
        self.analyze_body(ast.body)

    def analyze_body(self, body):
        for node in body.nodes:
            self.analyze_body_node(node)

    def analyze_body_node(self, node):
        if isinstance(node, Assign):
            self.analyze_assign(node)
        elif isinstance(node, If):
            self.analyze_if(node)
        elif isinstance(node, While):
            self.analyze_while(node)

    def analyze_assign(self, assign):
        if assign.var.name not in self.decl_vars:
            self.decl_vars[self.var.name] = self.analyze_var_expr(assign.var)
        else:
            if type(self.decl_vars[assign.var.name]) == type(list()):
                self.decl_vars[assign.var.name].append(self.analyze_var_expr(assign.expr))
            else:
                self.decl_vars[assign.var.name] = [self.analyze_var_expr(assign.expr)]
        return self.analyze_var_expr(assign.var)

    def analyze_if(self, if_stmnt):
        pass

    def analyze_while(self, while_stmnt):
        pass

    def analyze_expr(self, expr):
        if isinstance(node, NumExpr):
            self.analyze_num_expr(node)
        elif isinstance(node, VarExpr):
            self.analyze_var_expr(node)
        elif isinstance(node, StrExpr):
            self.analyze_str_expr(node)
        elif isinstance(node, FuncCall):
            self.analyze_func_call(node)

    def analyze_func(self, func):
        pass

    def analyze_func_call(self, func_call):
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
            return sanitizers

    def analyze_var_expr(self, expr):
        pass

    def analyze_num_expr(self, expr):
        pass

    def analyze_num_expr(self, expr):
        pass

    def analyze_str_expr(self, expr):
