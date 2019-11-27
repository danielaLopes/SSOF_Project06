#!/usr/bin/python3
from utils import *


class Sanitized:
    def __init__(self, sanitizers, source):
        # dictionary vulnerability->sanitizers_list
        self.sanitizers = sanitizers
        self.source = source

    def __repr__(self):
        return 'SANITIZED sanitizers %s source %s' % (self.sanitizers, self.source)

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
        new_sources = create_copy_of_array(level1.source)
        for source in level2.source:
            if source not in new_sources:
                new_sources.append(source)
        return Tainted(new_sources)

    elif isinstance(level1, Sanitized) and isinstance(level2, Sanitized):
        new_sources = create_copy_of_array(level1.source)
        for source in level2.source:
            if source not in new_sources:
                new_sources.append(source)
        sanitizers = create_copy_of_array(level1.sanitizers)
        for sanitizer in level2.sanitizers:
            if sanitizer not in sanitizers:
                sanitizers.append(sanitizer)
        return Sanitized(new_sources, sanitizers)

    # different level, but one is worse than the other
    elif isinstance(level1, Tainted) and isinstance(level2, Sanitized) or\
            isinstance(level1, Tainted) and isinstance(level2, Untainted) or\
            isinstance(level1, Sanitized) and isinstance(level2, Untainted):
        return level1
    elif isinstance(level1, Sanitized) and isinstance(level2, Tainted) or\
            isinstance(level1, Untainted) and isinstance(level2, Tainted) or\
            isinstance(level1, Untainted) and isinstance(level2, Sanitized):
        return level2

    #is untainted
    else:
        return Untainted()
