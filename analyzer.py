from analyzer_ast import *
from Levels import *


class Analyzer:

    def __init__(self, patterns):
        self.patterns = patterns
        self.decl_vars = {}
        self.state = []
        # output vulnerabilities are constructed during ast parsing with analyzer
        self.basic_vulnerabilities = []
        self.advanced_vulnerabilities = []

    def add_vulnerability_basic(self, vulnerability, sources, sink, sanitizers):
        self.basic_vulnerabilities.append({"vulnerability": vulnerability,
                                           "sources": sources,
                                           "sink": sink,
                                           "sanitizers": sanitizers})

    def add_vulnerability_advanced(self, vulnerability, sources, sink):
        self.advanced_vulnerabilities.append({"vulnerability": vulnerability,
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
        test_level = if_stmnt.test[0].get_analyzed(self)
        print('IF_BODY LEVEL: ',test_level)

        for node in if_stmnt.body:
            if isinstance(node,Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(self.decl_vars[var.name], Untainted):
                            self.decl_vars[var.name] = test_level
        for node in if_stmnt.orelse:
            if isinstance(node,Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(self.decl_vars[var.name], Untainted):
                            self.decl_vars[var.name] = test_level


    def analyze_while(self, while_stmnt):
        test_level = while_stmnt.test[0].get_analyzed(self)
        print('IF_BODY LEVEL: ',test_level)

        for node in while_stmnt.body:
            if isinstance(node,Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif sinstance(test_level, Sanitized) and isinstance(self.decl_vars[var.name], Untainted):
                            self.decl_vars[var.name] = test_level
        for node in while_stmnt.orelse:
            if isinstance(node,Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(self.decl_vars[var.name], Untainted):
                            self.decl_vars[var.name] = test_level

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
            sources_basic = []
            sources_advanced = []
            is_tainted = None
            for arg in func_call.args:
                level = arg.get_analyzed(self)
                level_sanitizers = level.get_sanitizers(pattern.vulnerability)
                if not isinstance(level, Untainted):
                    if isinstance(level, Tainted):
                        is_tainted = level
                    if isinstance(arg, VarExpr):
                        sources_basic.append(arg.name)
                        sources_advanced.append({'name': arg.name, 'sanitizers': level_sanitizers})
                    elif isinstance(arg, FuncCall):
                        sources_basic.append(arg.func.name)
                        sources_advanced.append({'name': arg.func.name, 'sanitizers': level_sanitizers})
                    sanitizers.extend(level_sanitizers)

            if kind == "SINK":
                self.add_vulnerability_basic(pattern.vulnerability, sources_basic, func_call.func.name, sanitizers)
                self.add_vulnerability_advanced(pattern.vulnerability, sources_advanced, func_call.func.name)

        if is_tainted:
            return is_tainted
        # sources_basic and sources_advanced are going to have the same size
        elif len(sources_basic) > 0:
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
