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

    def get_pattern_by_vuln(self, vulnerability):
        for pattern in self.patterns:
            if pattern.vulnerability == vulnerability:
                return pattern

    def get_sanitizers_per_vuln(self, vulnerability, sanitizers):
        sanitizers_per_vuln = []
        for sanitizer in sanitizers:
            if sanitizer in self.get_pattern_by_vuln(vulnerability).sanitizers:
                sanitizers_per_vuln.append(sanitizer)
        return sanitizers_per_vuln

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
            print("{} analyzed {}".format(node, node.get_analyzed(self)))

    def analyze_assign(self, assign):
        print("analyzing assign {}".format(assign))
        expr_level = assign.expr.get_analyzed(self)
        for var in assign.vars:
            if var.name in self.decl_vars:
                # variable only gets sanitized if it was tainted before
                if isinstance(expr_level, Sanitized):
                    expr_level.source = var.name
                    if isinstance(self.decl_vars[var.name], Tainted):
                        expr_level.source = self.decl_vars[var.name].source
                        self.decl_vars[var.name] = expr_level
                    elif isinstance(self.decl_vars[var.name], Sanitized):
                        self.decl_vars[var.name].sanitizers.extend(expr_level.sanitizers)
            else:
                self.decl_vars[var.name] = expr_level
        print("expr_level in assign {}".format(expr_level))
        return expr_level

    def analyze_if(self, if_stmnt):
        test_level = if_stmnt.test.get_analyzed(self)

        for node in if_stmnt.body:
            node_level = node.get_analyzed(self)
            if isinstance(node, Assign):
                print("node_level in if body {}".format(test_level))
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(node_level, Untainted):
                            self.decl_vars[var.name] = test_level
            elif isinstance(node, Attribute):
                pass
        for node in if_stmnt.orelse:
            node_level = node.get_analyzed(self)
            if isinstance(node, Assign):
                print("node_level in else body {}".format(test_level))
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(node_level, Untainted):
                            self.decl_vars[var.name] = test_level


    def analyze_while(self, while_stmnt):
        test_level = while_stmnt.test[0].get_analyzed(self)

        for node in while_stmnt.body:
            node_level = node.get_analyzed(self)
            if isinstance(node, Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(node_level, Untainted):
                            self.decl_vars[var.name] = test_level
        for node in while_stmnt.orelse:
            node_level = node.get_analyzed(self)
            if isinstance(node, Assign):
                for var in node.vars:
                    if var.name in self.decl_vars:
                        if isinstance(test_level, Tainted):
                            self.decl_vars[var.name] = test_level
                        elif isinstance(test_level, Sanitized) and isinstance(node_level, Untainted):
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
            return Sanitized([func_call.func.name], None)

        else:
            sanitizers = []
            sources_basic = []
            sources_advanced = []
            is_tainted = None

            for arg in func_call.args:
                arg_level = arg.get_analyzed(self)

                if kind == "SINK":
                    arg_sanitizers = self.get_sanitizers_per_vuln(pattern.vulnerability, arg_level.sanitizers)
                else:
                    arg_sanitizers = arg_level.sanitizers

                if not isinstance(arg_level, Untainted):
                    if isinstance(arg_level, Tainted):
                        is_tainted = arg_level
                    if isinstance(arg, VarExpr):
                        sources_basic.append(arg.name)
                        sources_advanced.append({'name': arg.name, 'sanitizers': arg_sanitizers})
                    elif isinstance(arg, FuncCall):
                        sources_basic.append(arg.func.name)
                        sources_advanced.append({'name': arg.func.name, 'sanitizers': arg_sanitizers})
                    sanitizers.extend(arg_sanitizers)

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

    def analyze_attribute(self, attribute):
        return attribute.value.get_analyzed(self)

    def analyze_var_expr(self, expr):
        print("analyzing var expr {}".format(expr))
        # check whether variable is declared
        if expr.name in self.decl_vars:
            return self.decl_vars[expr.name]
        else:
            return Tainted(expr.name)

    def analyze_num_expr(self, expr):
        return Untainted()

    def analyze_str_expr(self, expr):
        return Untainted()

    def analyze_bin_op(self, expr):
        left_level = expr.left.get_analyzed(self)
        right_level = expr.right.get_analyzed(self)
        return maxLevel(left_level, right_level)

    def analyze_bool_op(self, expr):
        left_level = expr.left.get_analyzed(self)
        comparator_level = expr.comparator.get_analyzed(self)
        return maxLevel(left_level, comparator_level)

    def analyze_unary_op(self, expr):
        return expr.operand.get_analyzed(self)
