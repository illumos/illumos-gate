#!/usr/bin/env python3

import re
import sys

# group 0: The whole shebang
# group 1 or group 2: The page name (sans fonts, if any)
# group 3: The section
REFERENCE = re.compile(r'(?:\\fB([a-zA-Z0-9_.-]+)\\fR|([a-zA-Z0-9_.-]+))\(([0-9][A-Za-z]*)\)')
def match_section(match):
    return match.group(3).upper()

def match_page(match):
    return match.group(1) or match.group(2)

def sort_key(line):
    match = REFERENCE.match(line) # If this fails we're hosed
    assert(match)
    return [match_section(match), match_page(match)]


lines = [f.rstrip(',\n') for f in sys.stdin]
lines.sort(key=sort_key)
print(',\n'.join(lines))
