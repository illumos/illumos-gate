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
Unit tests for EnvConfig._parse() - the environment config file parser.

Tests use canned string input via io.StringIO so no external files are needed.
"""

import io
import unittest

from symbol_test import EnvConfig, CompileEnv

# ---------------------------------------------------------------------------
# Canned input: a realistic slice of cxx-symbols-env.cfg.
# Exercises: comment lines, blank lines, env with empty defs, env with defs,
# env_group referencing multiple envs.
# ---------------------------------------------------------------------------

CANNED_CXX = """\
#
# Compilation environments for C++ symbol visibility tests.
#

# Plain C++ standards - no extra defines.
env | CXX98\t\t| c++98 |
env | CXX11\t\t| c++11 |
env | CXX17\t\t| c++17 |

# _C99 variants add -D_STDC_C99.
env | CXX98_C99\t\t| c++98 | -D_STDC_C99
env | CXX11_C99\t\t| c++11 | -D_STDC_C99

env_group | CXX98+\t| CXX17 CXX11 CXX98
env_group | CXX_C99+\t| CXX11_C99 CXX98_C99
"""

# Expected envs: name → (lang, defs)
EXPECTED_ENVS = {
    'CXX98':     ('c++98', ''),
    'CXX11':     ('c++11', ''),
    'CXX17':     ('c++17', ''),
    'CXX98_C99': ('c++98', '-D_STDC_C99'),
    'CXX11_C99': ('c++11', '-D_STDC_C99'),
}

# Expected groups: name → frozenset of member env names
EXPECTED_GROUPS = {
    'CXX98+':   frozenset({'CXX17', 'CXX11', 'CXX98'}),
    'CXX_C99+': frozenset({'CXX11_C99', 'CXX98_C99'}),
}


class TestParseEnvCfg(unittest.TestCase):

    def setUp(self):
        self.cfg = EnvConfig('c++')
        self.cfg._parse(io.StringIO(CANNED_CXX), filename='<test>')

    def test_env_count(self):
        self.assertEqual(len(self.cfg.envs), len(EXPECTED_ENVS))

    def test_env_names(self):
        self.assertEqual(set(self.cfg.envs.keys()), set(EXPECTED_ENVS.keys()))

    def test_env_lang_and_defs(self):
        for name, (lang, defs) in EXPECTED_ENVS.items():
            with self.subTest(env=name):
                env = self.cfg.envs[name]
                self.assertEqual(env.lang, lang)
                self.assertEqual(env.defs, defs)

    def test_group_count(self):
        self.assertEqual(len(self.cfg.groups), len(EXPECTED_GROUPS))

    def test_group_names(self):
        self.assertEqual(set(self.cfg.groups.keys()),
                         set(EXPECTED_GROUPS.keys()))

    def test_group_members(self):
        for name, members in EXPECTED_GROUPS.items():
            with self.subTest(group=name):
                self.assertEqual(self.cfg.groups[name], members)

    def test_lang_mismatch_raises(self):
        """--lang=c should be rejected when env lines use c++ standards."""
        cfg = EnvConfig('c')
        with self.assertRaises(SystemExit):
            cfg._parse(io.StringIO(CANNED_CXX), filename='<test>')

    def test_group_undefined_member_raises(self):
        """A group referencing an undefined env name should raise."""
        bad = "env | FOO | c++11 |\nenv_group | BAR | FOO NOSUCHENV\n"
        cfg = EnvConfig('c++')
        with self.assertRaises(SystemExit):
            cfg._parse(io.StringIO(bad), filename='<test>')


if __name__ == '__main__':
    unittest.main()
