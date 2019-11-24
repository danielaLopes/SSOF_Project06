#!/usr/bin/python3


class Sanitized:
    def __init__(self, sanitizers, source):
        # dictionary vulnerability->sanitizers_list
        self.sanitizers = sanitizers
        self.source = source

    def __repr__(self):
        return 'SANITIZED sanitizers %s source %s)' % (self.sanitizers, self.source)

    def get_sanitizers(self, vulnerability):
        if vulnerability in self.sanitizers:
            return self.sanitizers[vulnerability]
        return {}

    def add_sanitizer(self, other):
        vulnerabilities = list(other.sanitizers.keys())
        for vulnerability in vulnerabilities:
            if vulnerability in self.sanitizers:
                self.sanitizers[vulnerability].extend(other.sanitizers[vulnerability])
            else:
                self.sanitizers[vulnerability] = other.sanitizers[vulnerability]


class Tainted:
    def __init__(self, source):
        self.sanitizers = {}
        self.source = source

    def __repr__(self):
        return 'TAINTED source %s' % self.source

    def get_sanitizers(self, vulnerability):
        return self.sanitizers

class Untainted:
    def __repr__(self):
        return 'UNTAINTED'

    def get_sanitizers(self, vulnerability):
        return {}
