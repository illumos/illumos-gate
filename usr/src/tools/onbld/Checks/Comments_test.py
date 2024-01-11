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
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#

#
# Unit test for onbld comment checker
#
# To run this as a simple unit test:
#     python3 Comments_test.py
#
# To use this to measure coverage:
#     coverage3 erase
#     coverage3 run --branch Comments_test.py
#     coverage3 report -m --include Comments.py


import io
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(2, os.path.join(os.path.dirname(__file__), "../.."))

import onbld.Checks.Comments as Comments

class fake_bug_db:

    db = {
        '10': { 'cr_number': '10',
                'synopsis': 'this is a bug',
                'status': 'New'
               }
    }

    def lookup(self, buglist):
        return { bug: self.db[bug] for bug in buglist if bug in self.db }

class comchk_helper_test(unittest.TestCase):

    def test_isBug(self):
        self.assertTrue(Comments.isBug('10 this is a bug'))
        self.assertTrue(Comments.isBug('12345 this is a bug'))
        self.assertFalse(Comments.isBug('this is not a bug (no id)'))
        self.assertFalse(Comments.isBug('10000000 this is too big to be a bug'))

    def test_changeid_present(self):
        self.assertTrue(Comments.changeid_present(
            ['10 this is a bug',
             '',
             'Change-Id: Ideadbeef']))
        self.assertTrue(Comments.changeid_present(
            ['10 this is a bug',
             '20 this is another bug',
             '',
             'Change-Id: Ideadbeef']))

        self.assertFalse(Comments.changeid_present([]))
        self.assertFalse(Comments.changeid_present(['10 this is a bug']))
        self.assertFalse(Comments.changeid_present(
            ['10 this is a bug',
             '']))

        # Not a valid Change-Id
        self.assertFalse(Comments.changeid_present(
            ['10 this is a bug',
             '',
             'this is not a changeid']))
        self.assertFalse(Comments.changeid_present(
            ['10 this is a bug',
             '',
             'Change-Id: this is not a changeid']))

        # more than one Change-Id
        self.assertFalse(Comments.changeid_present(
            ['10 this is a bug',
             '',
             'Change-Id: Ideadbeef',
             'Change-Id: Ifeedface']))

class comchk_test(unittest.TestCase):

    def setUp(self):
        self.bugs = {}
        self.bugdb = fake_bug_db()

    def split_input(self, str):
        return [ line.strip() for line in str.splitlines() ]

    def expect_pass(self, input, *, check_db=False):

        with patch('onbld.Checks.Comments.BugDB') as mockdb:
            mockdb.configure_mock(return_value=self.bugdb)

            out = io.StringIO()
            self.assertEqual(0, Comments.comchk(self.split_input(input),
                                                check_db, out, bugs=self.bugs))
            self.assertEqual(out.getvalue(), '')

    def expect_fail(self, input, output, *, check_db=False):
        with patch('onbld.Checks.Comments.BugDB') as mockdb:
            mockdb.configure_mock(return_value=self.bugdb)

            out = io.StringIO()
            self.assertEqual(1, Comments.comchk(self.split_input(input),
                                                check_db, out, bugs=self.bugs))
            self.assertEqual(out.getvalue(), output)

    def test_comchk_newline(self):
        out = io.StringIO()
        with self.assertRaises(ValueError):
            Comments.comchk(['\n'], False, out)

    def test_comchk_basic(self):
        self.expect_pass('10 this is a bug\n')

    def test_comchk_reviewer(self):
        self.expect_pass('10 this is a bug\nReviewed by: alice\n')

    def test_comchk_approver(self):
        self.expect_pass('10 this is a bug\nReviewed by: alice\n'
                         'Approved by: bob\n')

    def test_comchk_changeid(self):
        self.expect_fail('10 this is a bug\n\nChange-Id: Ideadbeef',
                         'NOTE: Change-Id present in comment\n')

    def test_comchk_fail_spelling(self):

        self.expect_fail('10 this is the the bug\n',
                         'Spellcheck:\ncomment line 1 - '
                         'contains "the the", a common misspelling of "the"\n')

    def test_comchk_fail_not_bug(self):
        self.expect_fail('XX this is a bug\n',
                         'These comments are not valid bugs:\n'
                         '  XX this is a bug\n')

    def test_comchk_fail_blank_lines(self):
        self.expect_fail('10 this is a bug\n\n',
                         'WARNING: Blank line(s) in comments\n')

    def test_comchk_fail_bug_no_space(self):
        self.expect_fail('10this is a bug\n',
                         'These bugs are missing a single space '
                         'following the ID:\n'
                         '  10this is a bug\n')

    def test_comchk_fail_bug_dup(self):
        self.expect_fail('10 this is a bug\n10 this is another bug\n',
                         'These IDs appear more than once in your comments:\n'
                         '  10\n')

    def test_comchk_fail_bug_dup_no_space(self):
        self.expect_fail('10 this is a bug\n10this is another bug\n',
                         'These IDs appear more than once in your comments:\n'
                         '  10\n'
                         'These bugs are missing a single space '
                         'following the ID:\n'
                         '  10this is another bug\n')

    def test_comchk_multi_commit_dup(self):
        self.expect_pass('10 this is a bug\nReviewed-by: bob')
        self.expect_fail('10 this is a bug\nReviewed-by: bob',
                         'These IDs appear more than once in your comments:\n'
                         '  10\n')
        self.expect_pass('20 this is another bug\nReviewed-by: alice')

    def test_comchk_multi_changeid(self):
        self.expect_fail('10 this is a bug\n\nChange-Id: Ideadbeef',
                         'NOTE: Change-Id present in comment\n')
        self.expect_fail('20 this is a another bug\n\nChange-Id: Ifeedface',
                         'NOTE: Change-Id present in comment\n')

    def test_comchk_bugdb_pass(self):
        self.expect_pass('10 this is a bug\n', check_db=True)

    def test_comchk_bugdb_fail_synopsis(self):
        self.expect_fail('10 this is the wrong synopsis\n',
                         "These bug synopses don't match "
                         "the database entries:\n"
                         "Synopsis of 10 is wrong:\n"
                         "  should be: 'this is a bug'\n"
                         "         is: 'this is the wrong synopsis'\n",
                         check_db=True)

    def test_comchk_bugdb_wrong_bugid(self):
        self.expect_fail('20 this is the wrong bugid\n',
                         'These bugs were not found in the databases:\n'
                         '  20\n',
                         check_db=True)



if __name__ == '__main__':
    unittest.main()
