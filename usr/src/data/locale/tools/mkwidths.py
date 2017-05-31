#!/bin/python
"""

This file and its contents are supplied under the terms of the
Common Development and Distribution License ("CDDL"), version 1.0.
You may only use this file in accordance with the terms of version
1.0 of the CDDL.

A full copy of the text of the CDDL should have accompanied this
source.  A copy of the CDDL is also available via the Internet at
http://www.illumos.org/license/CDDL.

Copyright 2013 DEY Storage Systems, Inc.

Scratch script to produce the widths.cm content from the widths text
files.  It converts numeric unicode to symbolic forms.
"""

SYMBOLS = {}


def u8_str(val):
    """
    Convert a numeric value to a string representing the UTF-8 encoding
    of the numeric value, which should be a valid Unicode code point.
    """
    u8str = unichr(val).encode('utf-8')
    idx = 0
    out = ""
    while idx < len(u8str):
        out += "\\x%X" % ord(u8str[idx])
        idx += 1
    return out


def load_utf8():
    """
    This function loads the UTF-8 character map file, loading the symbols
    and the numeric values.  The result goes into the global SYMBOLS array.
    """
    lines = open("UTF-8.cm").readlines()
    for line in lines:
        items = line.split()
        if (len(items) != 2) or items[0].startswith("#"):
            continue
        (sym, val) = (items[0], items[1])
        SYMBOLS[val] = sym


def do_width_file(width, filename):
    """
    This function takes a file pairs of unicode values (hex), each of
    which is a range of unicode values, that all have the given width.
    """
    for line in open(filename).readlines():
        if line.startswith("#"):
            continue
        vals = line.split()
        while len(vals) > 1:
            start = int(vals[0], 16)
            end = int(vals[1], 16)
            val = start
            while val <= end:
                key = u8_str(val)
                val += 1
                sym = SYMBOLS.get(key, None)
                if sym == None:
                    continue
                print "%s\t%d" % (sym, width)
            vals = vals[2:]


if __name__ == "__main__":
    print "WIDTH"
    load_utf8()
    do_width_file(0, "widths-0.txt")
    do_width_file(2, "widths-2.txt")
    print "END WIDTH"
