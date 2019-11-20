class Assign():
    def __init__(self, name, expr):
        self.ast_type = "assign"
        self.name = name # targets[]['_type']
        self.expr = expr

    def __repr__(self):
        return 'Assign(%s, %s)' % (self.name, self.expr)

    def analyze(self, analyzer):
        label = {"kind": ast_type, "var": self.name, "explevel": self.expr.level()}
        analyzer.analyze_illegal_flows(label)

class Expr():
    def __init__(self, type, value, sources):
        self.type = type # value['_type'] e preciso guardar??
        self.value = value # value['n']
        self.sources = sources

    def __repr__(self):
        return 'Expr(%s, %s)' % (self.type, self.value)

    def level(self):


    def analyze(self, analyzer):
        label = {"kind": ast_type, "var": self.name, "explevel": self.exp.level()}
        analyzer.analyze_illegal_flows(label)

class VarExpr():
    def __init__(self, name):
        self.name = name

    def level(self, analyzer):
        if analyzer.decl_vars.contains(self.name):
            return "untainted"
