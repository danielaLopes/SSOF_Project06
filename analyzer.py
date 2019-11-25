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
        ast.body.get_analyzed(self)

    def analyze_body(self, body):
        for node in body.nodes:
            node.get_analyzed(self)

    def analyze_assign(self, assign):
        expr_level = assign.expr.get_analyzed(self)
        for var in assign.vars:
            if var.name in self.decl_vars:
                # variable only gets sanitized if it was tainted before
                if isinstance(expr_level, Sanitized):
                    expr_level.source = var.name
                    if isinstance(self.decl_vars[var.name], Tainted):
                        self.decl_vars[var.name] = expr_level
                    elif isinstance(self.decl_vars[var.name], Sanitized):
                        self.decl_vars[var.name].add_sanitizer(expr_level)
            else:
                self.decl_vars[var.name] = expr_level
        return expr_level

    def analyze_if(self, if_stmnt):
        for node in if_stmnt.body:
            node.get_analyzed(self)
        for node in if_stmnt.orelse:
            node.get_analyzed(self)
        for node in if_stmnt.test:
            node.get_analyzed(self)


    def analyze_while(self, while_stmnt):
        for node in while_stmnt.body:
            node.get_analyzed(self)
        for node in while_stmnt.orelse:
            node.get_analyzed(self)
        for node in while_stmnt.test:
            node.get_analyzed(self)

    def analyze_func(self, func):
        normal_kind = None
        for pattern in self.patterns:
            if func.name in pattern.sources:
                return "SOURCE", pattern
            elif func.name in pattern.sanitizers:
                return "SANITIZER", pattern
            elif func.name in pattern.sinks:
                return "SINK", pattern
            else:
                normal_kind = "NORMAL", None

        return normal_kind

    def analyze_func_call(self, func_call):
        kindTuple = func_call.func.get_analyzed(self)
        kind = kindTuple[0]
        pattern = kindTuple[1]
        if kind == "SOURCE":
            return Tainted(func_call.func.name)

        elif kind == "SANITIZER":
            return Sanitized({pattern.vulnerability: [func_call.func.name]}, None)

        else:
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
                self.add_vulnerability(pattern.vulnerability, sources, func_call.func.name)

        if is_tainted:
            return is_tainted
        elif len(sources) > 0:
            return Sanitized(sanitizers, None)
        else:
            return Untainted()

    def analyze_var_expr(self, expr):
        # check whether variable is declared
        if expr.name in self.decl_vars:
            return self.decl_vars[expr.name]
        else:
            return Tainted(expr.name)

    def analyze_num_expr(self, expr):
        return Untainted()

    def analyze_str_expr(self, expr):
        return Untainted()
