class Sanitized:
    def __init__(self, sanitizers, source):
        self.sanitizers = sanitizers
        self.source = source

    def __repr__(self):
        return 'SANITIZED sanitizers: %s source %s',\
               self.sanitizers, self.source

    def get_sanitizers(self, vulnerability):
        for sanitizer in self.sanitizers:
            if sanitizer['vulnerability'] == vulnerability:
                return sanitizer['sanitizers']
        return []


class Tainted:
    def __init__(self, source):
        self.sanitizers = []
        self.source = source

    def __repr__(self):
        return 'TAINTED source %s', self.source

    def get_sanitizers(self, vulnerability):
        return self.sanitizers

class Untainted:
    def __repr__(self):
        return 'UNTAINTED'

    def get_sanitizers(self, vulnerability):
        return []
