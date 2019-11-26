#!/usr/bin/python3


class Sanitized:
    def __init__(self, sanitizers, source):
        # dictionary vulnerability->sanitizers_list
        self.sanitizers = sanitizers
        self.source = source

    def __repr__(self):
        return 'SANITIZED sanitizers %s source %s)' % (self.sanitizers, self.source)

    """def get_sanitizers(self, vulnerability):
        if vulnerability in self.sanitizers:
            return self.sanitizers[vulnerability]
        return []

    def add_sanitizer(self, other):
        vulnerabilities = list(other.sanitizers.keys())
        for vulnerability in vulnerabilities:
            if vulnerability in self.sanitizers:
                self.sanitizers[vulnerability].extend(other.sanitizers[vulnerability])
            else:
                self.sanitizers[vulnerability] = other.sanitizers[vulnerability]
    """

    def add_sanitizer(self, other):
        vulnerabilities = list(other.sanitizers.keys())
        for vulnerability in vulnerabilities:
            if vulnerability in self.sanitizers:
                self.sanitizers[vulnerability].extend(other.sanitizers[vulnerability])
            else:
                self.sanitizers[vulnerability] = other.sanitizers[vulnerability]


class Tainted:
    def __init__(self, source):
        self.sanitizers = []
        self.source = source

    def __repr__(self):
        return 'TAINTED source %s' % self.source

    def get_sanitizers(self, vulnerability):
        return self.sanitizers


class Untainted:
    def __init__(self):
        self.sanitizers = []

    def __repr__(self):
        return 'UNTAINTED'

    def get_sanitizers(self, vulnerability):
        return self.sanitizers


def maxLevel(level1, level2):
    # same levels that are not untainted
    if isinstance(level1, Tainted) and isinstance(level2, Tainted):
        if level1.source != level2.source:
            return Tainted([level1.source, level2.source])
        else:
            return Tainted([level1.source])

    elif isinstance(level1, Sanitized) and isinstance(level2, Sanitized):
        if level1.source != level2.source:
            source = [level1.source, level2.source]
        sanitizers = level1.sanitizers
        for sanitizer in sanitizers:
            if level2.sanitizers not in sanitizers:
                sanitizers.append(sanitizer)
        return Sanitized(source, sanitizers)

    # different level, but one is worse than the other
    elif isinstance(level1, Tainted) and isinstance(level2, Sanitized) or\
            isinstance(level1, Tainted) and isinstance(level2, Untainted):
        return level1
    elif isinstance(level1, Sanitized) and isinstance(level2, Tainted) or \
            isinstance(level1, Untainted) and isinstance(level2, Tainted):
        return level2

    #is untainted
    else:
        return Untainted()
