class Analyzer:
    decl_vars = []
    state = []
    # output vulnerabilities are constructed during ast parsing with analyzer
    vulnerabilities = []

    def analyze_illegal_flows(self, label):

