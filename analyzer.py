from analyzer_ast import *
from Levels import *


class Analyzer:

    def __init__(self, patterns):
        self.patterns = patterns
        # saves a dictionary with declared variables and corresponding level
        self.decl_vars = {}
        # stack to keep levels in nested branches
        self.branch_levels = []
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
            node.get_analyzed(self)

    def analyze_assign(self, assign):
        #print("analyzing assign {}".format(assign))
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
        print("expr_level: {} in assign is: {}".format(assign.expr, expr_level))
        return expr_level

    def analyze_if(self, if_stmnt):
        test_level = if_stmnt.test.get_analyzed(self)

        self.branch_levels.append(test_level)

        # already updates values with worst level possible
        self.analyze_branch(test_level, if_stmnt.body)
        self.analyze_branch(test_level, if_stmnt.orelse)

        self.branch_levels.pop()


    def analyze_while(self, while_stmnt):
        test_level = while_stmnt.test.get_analyzed(self)

        self.branch_levels.append(test_level)

        # already updates values with worst level possible
        self.analyze_branch(test_level, while_stmnt.body)

        self.branch_levels.pop()

    # branch is not a node, but is useful to use this notion to not repeat code,
    # since logic is the same in if, else or while branches
    def analyze_branch(self, test_level, body_node):
        #print("BODY NODE {}".format(body_node))
        for node in body_node:
            node_level_if = node.get_analyzed(self)
            if isinstance(node, Assign):
                #print("node_level after assign in else body {}".format(test_level))
                for var in node.vars:
                    self.decl_vars[var.name] = maxLevel(test_level, node_level_if)

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

            # only signals vulnerability if the sink has arguments that may cause a vulnerability
            if kind == "SINK" and (is_tainted or len(sanitizers) > 0):
                self.add_vulnerability_basic(pattern.vulnerability, sources_basic, func_call.func.name, sanitizers)
                self.add_vulnerability_advanced(pattern.vulnerability, sources_advanced, func_call.func.name)

        if is_tainted:
            return is_tainted
        # sources_basic and sources_advanced are going to have the same size
        elif len(sources_basic) > 0:
            return Sanitized(sanitizers, None)
        else:
            return Untainted()

    # for simplicity, it is assumed only the assign node can change the values of a variable
    def analyze_attribute(self, attribute):
        attr_level = attribute.attr.get_analyzed(self)
        value_level = attribute.value.get_analyzed(self)
        return maxLevel(attr_level, value_level)

    def analyze_var_expr(self, expr):
        #print("analyzing var expr {}".format(expr))
        # check whether variable is declared
        #print("decl_vars {}".format(self.decl_vars))
        if expr.name in self.decl_vars:
            #print("VARIABLE IS DECLARED")
            return self.decl_vars[expr.name]
        else:
            return Tainted(expr.name)

    def analyze_num_expr(self, expr):
        return Untainted()

    def analyze_str_expr(self, expr):
        return Untainted()

    def analyze_name_constant_expr(self, expr):
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
        #print("analyzing unary node {}", expr)
        return expr.operand.get_analyzed(self)

    def analyze_tuple(self, expr):
        el1_level = expr.el1.get_analyzed(self)
        el2_level = expr.el2.get_analyzed(self)
        return maxLevel(el1_level, el2_level)
