class Analyzer:

    def __init__(self, patterns):
        self.patterns = patterns
        self.decl_vars = {}
        self.state = []
        # output vulnerabilities are constructed during ast parsing with analyzer
        self.vulnerabilities = []

    def analyze_illegal_flows(self, label):
        pass

