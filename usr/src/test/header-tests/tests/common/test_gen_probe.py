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
Unit tests for ProbeGen.gen_probe() - probe program source generation.

Expected outputs were captured from the previous implementation.
"""

import unittest

from symbol_test import ProbeGen, SymEntry


def make_entry(directive, symbol, headers, rtype=None, atypes=None, defval=None):
    return SymEntry(
        directive=directive,
        symbol=symbol,
        env_spec='',
        headers=headers,
        rtype=rtype,
        atypes=atypes or [],
        defval=defval,
    )


class TestGenProbeC(unittest.TestCase):
    """Probe generation for lang='c'."""

    def test_type(self):
        e = make_entry('type', 'size_t', ['stddef.h'], rtype='size_t')
        expected = (
            '#include <stddef.h>\n'
            'size_t test_type;\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_value(self):
        e = make_entry('value', 'M_PI', ['math.h'], rtype='double')
        expected = (
            '#include <math.h>\n'
            'double test_value;\n'
            'void\n'
            'test_func(void)\n'
            '{\n'
            '\ttest_value = M_PI;\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_define_no_value(self):
        e = make_entry('define', 'INFINITY', ['math.h'])
        expected = (
            '#include <math.h>\n'
            '#if !defined(INFINITY)\n'
            '#error INFINITY is not defined or has the wrong value\n'
            '#endif\n'
            '\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_define_with_value(self):
        e = make_entry('define', 'FLT_RADIX', ['float.h'], defval='2')
        expected = (
            '#include <float.h>\n'
            '#if !defined(FLT_RADIX) || FLT_RADIX != 2\n'
            '#error FLT_RADIX is not defined or has the wrong value\n'
            '#endif\n'
            '\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_func_single_arg(self):
        e = make_entry('func', 'log', ['math.h'], rtype='double', atypes=['double'])
        expected = (
            '#include <math.h>\n'
            'double \n'
            'test_func(double a0)\n'
            '{\n'
            '\treturn log(a0);\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_func_multi_arg(self):
        e = make_entry('func', 'hypot', ['math.h'], rtype='double',
                       atypes=['double', 'double'])
        expected = (
            '#include <math.h>\n'
            'double \n'
            'test_func(double a0, double a1)\n'
            '{\n'
            '\treturn hypot(a0, a1);\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)

    def test_func_void_return(self):
        e = make_entry('func', 'free', ['stdlib.h'], rtype='void',
                       atypes=['void *'])
        expected = (
            '#include <stdlib.h>\n'
            'void \n'
            'test_func(void * a0)\n'
            '{\n'
            '\tfree(a0);\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c'), expected)


class TestGenProbeCxx(unittest.TestCase):
    """Probe generation for lang='c++'."""

    def test_func_result_macro(self):
        """Non-void non-fnptr return: RESULT() macro must be emitted."""
        e = make_entry('func', 'log', ['cmath'], rtype='double', atypes=['double'])
        expected = (
            '#include <cmath>\n'
            '#if __cplusplus >= 201103L\n'
            '#define RESULT(v) result{v}\n'
            '#else\n'
            '#define RESULT(v) result = (v)\n'
            '#endif\n'
            'double \n'
            'test_func(double a0)\n'
            '{\n'
            '\tdouble RESULT(log(a0));\n'
            '\treturn result;\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c++'), expected)

    def test_func_void_return(self):
        """void return: no RESULT() macro; same form as C."""
        e = make_entry('func', 'free', ['cstdlib'], rtype='void',
                       atypes=['void *'])
        expected = (
            '#include <cstdlib>\n'
            'void \n'
            'test_func(void * a0)\n'
            '{\n'
            '\tfree(a0);\n'
            '}\n'
        )
        self.assertEqual(ProbeGen.gen_probe(e, 'c++'), expected)


if __name__ == '__main__':
    unittest.main()
