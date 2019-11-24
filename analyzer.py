from analyzer_ast import *
from Levels import *


class Analyzer:

    def __init__(self, patterns):
        self.patterns = patterns
        self.decl_vars = {}
        self.state = []
        # output vulnerabilities are constructed during ast parsing with analyzer
        self.vulnerabilities = []

    def add_vulnerability(self, vulnerability, sources, sink):
        self.vulnerabilities.append({"vulnerability": vulnerability,
                                     "sources": sources,
                                     "sink": sink})

    def analyze_ast(self, ast):
        print("analyze_ast")
        ast.body.get_analyzed(self)
        #self.analyze_body(ast.body)

    def analyze_body(self, body):
        print("analyze_body: {}".format(body))
        for node in body.nodes:
            node.get_analyzed(self)

    def analyze_body_node(self, node):
        print("analyze_body_node: {}".format(node))
        node.get_analyzed(self)

    def analyze_assign(self, assign):
        print("analyze_assign: {}".format(assign))
        expr_level = assign.expr.get_analyzed(self)
        for var in assign.vars:
            if var.name in self.decl_vars:
                # variable only gets sanitized if it was tainted before
                if isinstance(expr_level, Sanitized):
                    expr_level.source = var.name
                    if isinstance(self.decl_vars[var.name], Tainted):
                        self.decl_vars[var.name] = expr_level
                    elif isinstance(self.decl_vars[var.name], Sanitized):
                        self.decl_vars[var.name].sanitizers.extend(expr_level.sanitizers)
            else:
                self.decl_vars[var.name] = expr_level
        return expr_level

    def analyze_if(self, if_stmnt):
        pass

    def analyze_while(self, while_stmnt):
        pass

    def analyze_expr(self, expr):
        print("analyze_expr: {}".format(expr))
        if isinstance(expr, NumExpr):
            self.analyze_num_expr(expr)
        elif isinstance(expr, VarExpr):
            self.analyze_var_expr(expr)
        elif isinstance(expr, StrExpr):
            self.analyze_str_expr(expr)
        elif isinstance(expr, FuncCall):
            self.analyze_func_call(expr)

    def analyze_func(self, func):
        print("analyze_func: {}".format(func))
        normal_kind = None
        for pattern in self.patterns:
            #print("pattern {}".format(pattern.sources))
            if func.name in pattern.sources:
                return "SOURCE", pattern
            elif func.name in pattern.sanitizers:
                print("sanitizer {}".format(func.name))
                return "SANITIZER", pattern
            elif func.name in pattern.sinks:
                return "SINK", pattern
            else:
                normal_kind = "NORMAL", None

        return normal_kind

    def analyze_func_call(self, func_call):
        print("analyze_func_call: {}".format(func_call))
        kindTuple = func_call.func.get_analyzed(self)
        print("kindTuple: {}".format(kindTuple))
        kind = kindTuple[0]
        pattern = kindTuple[1]
        if kind == "SOURCE":
            print("IS A SOURCE: {}".format(func_call.func.name))
            return Tainted(func_call.func.name)

        elif kind == "SANITIZER":
            print("IS A SANITIZER: {}".format(func_call.func.name))
            return Sanitized([{'vulnerability': pattern.vulnerability,\
                               'sanitizers': [func_call.func.name]}], None)

        else:
            print("IS ANOTHER KIND: {}".format(func_call.func.name))
            sanitizers = []
            sources = []
            is_tainted = None
            for arg in func_call.args:
                level = arg.get_analyzed(self)
                level_sanitizers = level.get_sanitizers(pattern.vulnerability)
                if not isinstance(level, Untainted):
                    if isinstance(level, Tainted):
                        is_tainted = level
                    if isinstance(arg, VarExpr):
                        sources.append({'name': arg.name, 'sanitizers': level_sanitizers})
                    elif isinstance(arg, FuncCall):
                        sources.append({'name': arg.func.name, 'sanitizers': level_sanitizers})
                    sanitizers.extend(level_sanitizers)

            if kind == "SINK":
                print("IS A SINK: {}".format(func_call.func.name))
                self.add_vulnerability(pattern.vulnerability, sources, func_call.func.name)

        if is_tainted:
            return is_tainted
        elif len(sources) > 0:
            return Sanitized(sanitizers, None)
        else:
            return Untainted()

    def analyze_var_expr(self, expr):
        print("analyze_var_expr: {}".format(expr))
        # check whether variable is declared
        if expr.name in self.decl_vars:
            return self.decl_vars[expr.name]
        else:
            return Tainted(expr.name)

    def analyze_num_expr(self, expr):
        print("analyze_num_expr: {}".format(expr))
        return Untainted()

    def analyze_str_expr(self, expr):
        print("analyze_str_expr: {}".format(expr))
        return Untainted()
