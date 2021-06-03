#!@PYTHON@
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
# Copyright 2022 Tintri by DDN, Inc. All rights reserved.
#

#
# Run tests provided by smbtorture.
#

import subprocess
import argparse
import re
import fnmatch

from enum import Enum
from datetime import datetime
from tempfile import TemporaryFile

def stripped_file(f):
    """Strips trailing whitespace from lines in f"""

    for line in f:
        yield line.strip()

def parse_tests(f):
    """Returns test names from f, skipping commented lines"""

    yield from (line for line in f
        if line and not line.startswith('#'))

def matched_suites(m):
    """Gets all smbtorture tests that match pattern m"""

    with TemporaryFile('w+') as tmp:
        subprocess.run(['smbtorture', '--list'], stdout=tmp,
            universal_newlines=True)
        tmp.seek(0)
        yield from (line for line in stripped_file(tmp)
                    if not line.startswith('smbtorture') and
                    m.match(line))

class TestResult(Enum):
    PASS = 0
    FAIL = 1
    UNKNOWN = 2
    SKIP = 3
    KILLED = 4
    TEST_ERR = 5

    def __str__(self):
        return self.name

    def __len__(self):
        return len(self.name)

class TestCase:
    """A particular instance of an smbtorture test"""

    __slots__ = 'name', 'result'

    def __init__(self, name):
        self.name = name
        self.result = TestResult.UNKNOWN

    def __str__(self):
        return f'{self.name} | {self.result}'

    def run(self, rfd, wfd, timeout, cmd):
        """Run cmd, setting the last element to the test name, and setting result
        based on rfd. Output is sent to wfd, and the test is killed based on timeout."""

        def finish(self, start, wfd):
            timediff = datetime.now() - start
            wfd.write(f'END   | {self} | {timediff}\n')
            return self.result

        starttime = datetime.now()
        wfd.write(f'START | {self.name} | {starttime.time()}\n')
        if self.result == TestResult.SKIP:
            return finish(self, starttime, wfd)

        cmd[-1] = self.name
        try:
            subprocess.run(cmd, universal_newlines=True, stdout=wfd,
                stderr=subprocess.STDOUT, timeout=timeout)
            for line in stripped_file(rfd):
                if self.result != TestResult.UNKNOWN:
                    continue
                elif line.startswith('failure:') or line.startswith('error:'):
                    self.result = TestResult.FAIL
                elif line.startswith('success:'):
                    self.result = TestResult.PASS
                elif line.startswith('skip:'):
                    self.result = TestResult.SKIP
                elif line.startswith('INTERNAL ERROR:'):
                    self.result = TestResult.TEST_ERR
        except subprocess.TimeoutExpired:
            self.result = TestResult.KILLED
            wfd.write('\nKilled due to timeout\n')
            rfd.read()

        return finish(self, starttime, wfd)

class TestSet:
    """Class to track state associated with the entire test set"""

    __slots__ = 'excluded', 'tests'

    def __init__(self, tests, skip_pat, verbose):
        self.excluded = 0

        def should_skip(self, test, pattern, verbose):
            """Returns whether test matches pattern, indicating it should be
            skipped."""

            if not pattern or not pattern.match(test):
                return False

            if verbose:
                print(f'{test} matches exception pattern; marking as skipped')

            self.excluded += 1
            return True

        self.tests = [TestCase(line) for line in tests
            if not should_skip(self, line, skip_pat, verbose)]


    def __iter__(self):
        return iter(self.tests)

    def __len__(self):
        return len(self.tests)

def fnm2regex(fnm_pat):
    """Maps an fnmatch(7) pattern to a regex pattern that will match against
    any suite that encapsulates the test name"""

    rpat = fnmatch.translate(fnm_pat)

    #
    # If the pattern doesn't end with '*', we also need it to match against
    # any sub-module; '*test' needs to also match 'smb2.test.first', but
    # not 'smb2.test-other.second'.
    #
    if not fnm_pat.endswith('*'):
        rpat += '|' + fnmatch.translate(fnm_pat + '.*')
    return rpat

def verbose_fnm2regex(fnm_pat):
    """fnm2regex(), but prints the input and output patterns"""
    ret_pat = fnm2regex(fnm_pat)
    print(f'fnmatch: {fnm_pat} regex: {ret_pat}')
    return ret_pat

def combine_patterns(iterable, verbose):
    """Combines patterns in an iterable into a single REGEX"""

    if verbose > 1:
        func = verbose_fnm2regex
    else:
        func = fnm2regex

    fnmatch_pat = '|'.join(map(func, iterable))

    if not fnmatch_pat:
        pat = None;
    else:
        pat = re.compile(fnmatch_pat, flags=re.DEBUG if verbose > 2 else 0)

    if verbose > 1:
        print(f'final pattern: {pat.pattern if pat else "<None>"}')
    return pat

class ArgumentFile(argparse.FileType):
    """argparse.FileType, but wrapped in stripped_file()"""

    def __call__(self, *args, **kwargs):
        return stripped_file(argparse.FileType.__call__(self, *args, **kwargs))


def main():
    parser = argparse.ArgumentParser(description=
        'Run a set of smbtorture tests, parsing the results.')

    parser.add_argument('server', help='The target server')
    parser.add_argument('share', help='The target share')
    parser.add_argument('user', help='Username for smbtorture')
    parser.add_argument('password', help='Password for user')

    parser.add_argument('--except', '-e',
        type=ArgumentFile('r'), metavar='EXCEPTIONS_FILE', dest='skip_list',
        help='A file containing fnmatch(7) patterns of tests to skip')
    parser.add_argument('--list', '-l',
        type=ArgumentFile('r'), metavar='LIST_FILE',
        help='A file containing the list of tests to run')
    parser.add_argument('--match', '-m',
        action='append', metavar='FNMATCH',
        help='An fnmatch(7) pattern to select tests from smbtorture --list')
    parser.add_argument('--output', '-o',
        default='/tmp/lastrun.log', metavar='LOG_FILE',
        help='Location to store full smbtorture output')
    parser.add_argument('--seed', '-s',
        type=int,
        help='Seed passed to smbtorture')
    parser.add_argument('--timeout', '-t',
        default=120, type=float,
        help='Timeout after which test is killed')
    parser.add_argument('--verbose', '-v',
        action='count', default=0,
        help='Verbose output')

    args = parser.parse_args()

    if (args.match == None) == (args.list == None):
        print('Must provide one of -l and -m')
        return

    server = args.server
    share = args.share
    user = args.user
    pswd = args.password
    fout = args.output

    if args.match != None:
        if args.verbose > 1:
            print('Patterns to match:')
            print(*args.match)

        testgen = matched_suites(combine_patterns(args.match, args.verbose))
    else:
        testgen = args.list

    if args.skip_list != None:
        skip_pat = combine_patterns(parse_tests(args.skip_list), args.verbose)
        if args.verbose > 1:
            exc_pat = skip_pat.pattern if skip_pat else '<NONE>'
            print(f'Exceptions pattern (in REGEX): {exc_pat}')
    else:
        skip_pat = None

    tests = TestSet(parse_tests(testgen), skip_pat, args.verbose)

    if args.verbose:
        print('Tests to run:')
        for test in tests:
            print(test.name)

    outw = open(fout, 'w', buffering=1)
    outr = open(fout, 'r')

    cmd = f'smbtorture //{server}/{share} -U{user}%{pswd}'.split()
    if args.seed != None:
        cmd.append(f'--seed={args.seed}')
    cmd.append('TEST_HERE')

    if args.verbose:
        print('Command to run:')
        print(*cmd)

    results = {res: 0 for res in TestResult}
    for test in tests:
        print(test.name, end=': ', flush=True)
        res = test.run(outr, outw, args.timeout, cmd)
        results[res] += 1
        print(res, flush=True)

    print('\n\nRESULTS:')
    print('=' * 22)
    for res in TestResult:
        print(f'{res}: {results[res]:>{20 - len(res)}}')
    print('=' * 22)
    print(f'Total: {len(tests):>15}')
    print(f'Excluded: {tests.excluded:>12}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Terminated by KeyboardInterrupt.')
