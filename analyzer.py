from analyzer_ast import *
from Levels import *
from utils import *


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

    def get_max_nested_branch_levels(self, current_level):
        #print("BRANCH LEVELS: {}".format(self.branch_levels))
        combined_levels = current_level
        if len(self.branch_levels) > 1:
            for i in range(0, len(self.branch_levels)-1):
                #print("get_max_nested_branch_levels before: {}".format(self.decl_vars))
                combined_levels = maxLevel(self.branch_levels[i], self.branch_levels[i+1])
                #print("get_max_nested_branch_levels after: {}".format(self.decl_vars))
        return combined_levels

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
        if assign.var.name in self.decl_vars:
            # variable only gets sanitized if it was tainted before
            if isinstance(expr_level, Sanitized):
                var_previous_level = assign.var.get_analyzed(self)
                # maintains dependecies between several sanitizations with same source
                if expr_level.source == var_previous_level.source and\
                        isinstance(var_previous_level, Sanitized):
                    # extend returns None, so we need an auxiliary list to extend at the beginning
                    aux_sanitizers = create_copy_of_array(var_previous_level.sanitizers)
                    aux_sanitizers.extend(expr_level.sanitizers)
                    expr_level.sanitizers = aux_sanitizers

        #print("analyze_assign before: {}".format(self.decl_vars))
        self.decl_vars[assign.var.name] = expr_level
        #print("analyze_assign after: {}".format(self.decl_vars))
        #print("expr_level: {} in assign is: {}".format(assign.expr, expr_level))
        return expr_level

    def analyze_if(self, if_stmnt):
        # combine levels of all nested conditions
        test_level = if_stmnt.test.get_analyzed(self)
        self.branch_levels.append(test_level)
        combined_level = self.get_max_nested_branch_levels(test_level)

        # already updates values with worst level possible
        self.analyze_branch(combined_level, if_stmnt.body)
        self.analyze_branch(combined_level, if_stmnt.orelse)

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
            node_level= node.get_analyzed(self)
            if isinstance(node, Assign):
                #print("var {} level {} before if flow".format(node.var, self.decl_vars[node.var.name]))
                self.decl_vars[node.var.name] = maxLevel(test_level, node_level)
                #print("var {} level {} after if flow".format(node.var, self.decl_vars[node.var.name]))
        #print("AFTER EACH ANALYZE_BRANCH: {}".format(self.decl_vars))
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
        #print("FuncCall : {}".format(func_call))
        kindTuple = func_call.func.get_analyzed(self)
        kind = kindTuple[0]
        pattern = kindTuple[1]
        if kind == "SOURCE":
            return Tainted([func_call.func.name])

        elif kind == "SANITIZER":
            sanitize_sources = []
            for arg in func_call.args:
                arg_level = arg.get_analyzed(self)
                #print("SANITIZ function: {} arg: {}, level: {}".format(func_call, arg, arg_level))
                if isinstance(arg_level, Tainted) or isinstance(arg_level, Sanitized):
                    sanitize_sources.extend(arg_level.source)
                    #print("SANITIZED_SOURCES: {}".format(sanitize_sources))
            # if there was sanitiziation of atleast one not untainted argument
            if len(sanitize_sources) > 0:
                return Sanitized([func_call.func.name], sanitize_sources)
            # if there was nothing to sanitize, then it's untainted
            else:
                return Untainted()

        else:
            sanitizers = []
            sources_basic = []
            sources_advanced = []
            is_tainted = None
            is_sanitized = None

            for arg in func_call.args:
                arg_level = arg.get_analyzed(self)

                if kind == "SINK":
                    arg_sanitizers = self.get_sanitizers_per_vuln(pattern.vulnerability, arg_level.sanitizers)
                else:
                    arg_sanitizers = arg_level.sanitizers

                if not isinstance(arg_level, Untainted):
                    if isinstance(arg_level, Tainted):
                        is_tainted = arg_level
                    elif isinstance(arg_level, Sanitized):
                        is_sanitized = arg_level
                    if arg_level.source not in sources_basic:
                        sources_basic.append(arg_level.source)
                        sources_advanced.append({'source': arg_level.source, 'sanitizers': arg_sanitizers})
                    sanitizers.extend(arg_sanitizers)

            #print("is_tainted: {}, len(sanitizers): {}".format(is_tainted, len(sanitizers)))
            # only signals vulnerability if the sink has arguments that may cause a vulnerability
            if kind == "SINK" and (is_tainted or is_sanitized):
                self.add_vulnerability_basic(pattern.vulnerability, sources_basic, func_call.func.name, sanitizers)
                self.add_vulnerability_advanced(pattern.vulnerability, sources_advanced, func_call.func.name)

        if is_tainted:
            return is_tainted
        # if it's not tainted, then it can only be Sanitized or Untainted
        # but if it's Untainted it wouldn't have sources, so it's Sanitized
        elif len(sources_basic) > 0:
            return Sanitized(sanitizers, sources_basic)
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
            return self.decl_vars[expr.name]
        else:
            return Tainted([expr.name])

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
