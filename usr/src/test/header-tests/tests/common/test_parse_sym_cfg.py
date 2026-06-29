#!/usr/bin/python3
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Gordon W. Ross
#

"""
Unit tests for SymConfig._parse() - the symbols config file parser.

Tests use canned string input via io.StringIO so no external files are needed.
"""

import io
import unittest

from symbol_test import SymConfig, SymEntry

# ---------------------------------------------------------------------------
# Canned input: exercises all four directive types, continuation lines,
# multiple headers (;-separated), multiple arg types (;-separated),
# comments, and blank lines.
# ---------------------------------------------------------------------------

CANNED_SYM = """\
#
# Canned symbol test cfg for unit testing.
#

# A type test.
type | size_t | stddef.h | C11+

# A value test.
value | M_PI | double | math.h | C99+

# A define test with no expected value.
define | INFINITY | | math.h | C99+

# A define test with an expected value.
define | FLT_RADIX | 2 | float.h | C99+

# A simple func test (single arg, single header).
func | log | double | double | math.h | C99+

# A func test with continuation lines and multiple args.
func | hypot			|\
	double				|\
	double; double			|\
	math.h | C99+

# A func test with multiple headers (;-separated).
func | acosh			|\
	double				|\
	double				|\
	math.h; iso/math_c99.h | C99+
"""

# ---------------------------------------------------------------------------
# Expected results
# ---------------------------------------------------------------------------

EXPECTED = [
    dict(directive='type',   symbol='size_t',   rtype='size_t',
         atypes=[],                headers=['stddef.h'],              env_spec='C11+'),
    dict(directive='value',  symbol='M_PI',     rtype='double',
         atypes=[],                headers=['math.h'],                env_spec='C99+'),
    dict(directive='define', symbol='INFINITY',  rtype=None,
         atypes=[],                headers=['math.h'],   defval=None, env_spec='C99+'),
    dict(directive='define', symbol='FLT_RADIX', rtype=None,
         atypes=[],                headers=['float.h'],  defval='2',  env_spec='C99+'),
    dict(directive='func',   symbol='log',       rtype='double',
         atypes=['double'],        headers=['math.h'],                env_spec='C99+'),
    dict(directive='func',   symbol='hypot',     rtype='double',
         atypes=['double', 'double'], headers=['math.h'],             env_spec='C99+'),
    dict(directive='func',   symbol='acosh',     rtype='double',
         atypes=['double'],        headers=['math.h', 'iso/math_c99.h'], env_spec='C99+'),
]


class TestParseSymCfg(unittest.TestCase):

    def setUp(self):
        self.cfg = SymConfig()
        self.cfg._parse(io.StringIO(CANNED_SYM), filename='<test>')

    def test_entry_count(self):
        self.assertEqual(len(self.cfg.entries), len(EXPECTED))

    def test_entries(self):
        for i, exp in enumerate(EXPECTED):
            with self.subTest(i=i, symbol=exp['symbol']):
                e = self.cfg.entries[i]
                self.assertEqual(e.directive, exp['directive'])
                self.assertEqual(e.symbol,    exp['symbol'])
                self.assertEqual(e.env_spec,  exp['env_spec'])
                self.assertEqual(e.headers,   exp['headers'])
                self.assertEqual(e.atypes,    exp['atypes'])
                if exp['directive'] == 'define':
                    self.assertEqual(e.defval, exp.get('defval'))
                else:
                    self.assertEqual(e.rtype,  exp['rtype'])


if __name__ == '__main__':
    unittest.main()
