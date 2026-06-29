#!@TOOLS_PYTHON@ -Es
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

#
# Check test runfiles against installed test artifacts in proto.
#
# For each section in a runfile, verify that the test group path,
# the tests (if listed), and any pre/post auxiliary scripts exist
# in the proto area and are executable.  Auxiliary scripts are
# allowed to be outside the test group's own directory.
#
# Note that some tests might not run on the target system for which
# this workspace is building.  Some runfiles have test groups that
# specify an architecture like "arch=i86pc" and run only there.
# A runfile test group runs on the target if the "arch=" value is
# absent, or if the "arch" value matches the target architecture.
#
# For the build-time checks this runs, assume the build has all
# architectures for a given MACH (eg. i386/amd64 builds for all of
# i86pc i86xpv intel) and check for existence of test programs
# when the runfile arch matches any of the architectures that
# should exist in this build.

import argparse
import ast
import configparser
import io
import os
import posixpath
import re
import sys
import tokenize

SECTION_RE = re.compile(r'^\s*\[(.+?)\]\s*$')

# Maps MACH (build ISA) to the set of architecture names that may appear
# in runfile "arch=" properties for that build.  Derived from the
# *_ARCHITECTURES variables in usr/src/uts/Makefile.
MACH_ARCHITECTURES = {
    'i386':  {'i86pc', 'i86xpv', 'intel'},
    'sparc': {'sun4v', 'sun4u', 'sparc'},
}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Validate test runfiles against proto/root_i386 installs')
    parser.add_argument(
        '-R', dest='root', default=os.environ.get('ROOT'),
        help='proto root path (for example, .../proto/root_i386); '
             'default: $ROOT')
    parser.add_argument(
        '-T', dest='testroot', required=True,
        help='test root relative to proto root (for example, opt/os-tests)')
    parser.add_argument(
        '-m', '--mach', default=None,
        help='target CPU type (for example, i386 or sparc); used to determine '
             'which arch-constrained sections to check')
    parser.add_argument(
        'runfiles', nargs='+',
        help='runfile paths to check')

    args = parser.parse_args()
    if args.root is None:
        parser.error('missing proto root: set -R <root> or the ROOT '
                     'environment variable')
    return args


def find_runfiles(args):
    return list(args.runfiles)


def normalize_testroot(testroot):
    root = testroot.strip()
    if not root:
        return None
    if root.startswith('/'):
        return None
    root = posixpath.normpath(root)
    if root in ('.', '..') or root.startswith('../'):
        return None
    return root


def section_path(section, testroot):
    raw = section.split(':', 1)[0].strip()
    if raw.startswith('/'):
        return posixpath.normpath(raw)
    return posixpath.normpath(posixpath.join('/', testroot, raw))


def section_raw_path(section):
    return section.split(':', 1)[0].strip()


def is_test_file(path):
    return (os.path.isfile(path) and not os.path.islink(path) and
            os.access(path, os.X_OK))


def has_adjacent_string_literals(expr):
    try:
        toks = tokenize.generate_tokens(io.StringIO(expr).readline)
    except tokenize.TokenError:
        return False

    prev = None
    ignored = set([tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                   tokenize.DEDENT, tokenize.COMMENT, tokenize.ENDMARKER])
    for tok in toks:
        if tok.type in ignored:
            continue
        if tok.type == tokenize.STRING and prev == tokenize.STRING:
            return True
        prev = tok.type
    return False


def section_line_map(content):
    lines = {}
    for lineno, line in enumerate(content.splitlines(), 1):
        match = SECTION_RE.match(line)
        if match is None:
            continue
        section = match.group(1).strip()
        if section not in lines:
            lines[section] = lineno
    return lines


def format_error(runfile, lineno, test_group, detail):
    loc = '%s:%s' % (runfile, lineno)
    return 'In test group %s, %s: %s' % (test_group, loc, detail)


def emit_error(issues, runfile, lineno, test_group, detail):
    issues.append(format_error(runfile, lineno, test_group, detail))


def check_runfile(runfile, testroot, protoroot, archlist):
    issues = []
    config = configparser.RawConfigParser()
    content = None

    try:
        with open(runfile, encoding='utf-8') as f:
            content = f.read()
    except OSError as err:
        return ['%s: failed to read runfile: %s' % (runfile, err)]

    section_lines = section_line_map(content)

    try:
        config.read_string(content, source=runfile)
    except configparser.Error as err:
        return ['%s: parse error: %s' % (os.path.basename(runfile), err)]

    for sec in config.sections():
        lineno = section_lines.get(sec, '?')
        if section_raw_path(sec).upper() == 'DEFAULT':
            continue
        if config.has_option(sec, 'arch'):
            sec_arch = config.get(sec, 'arch').strip()
            if sec_arch not in archlist:
                continue
        # else arch not specified so do checks.

        secpath = section_path(sec, testroot)
        proto_path = os.path.join(protoroot, secpath.lstrip('/'))
        has_tests = config.has_option(sec, 'tests')
        has_autotests = config.has_option(sec, 'autotests')

        if has_tests or has_autotests:
            path_exists = os.path.exists(proto_path)
            path_is_dir = os.path.isdir(proto_path)
            path_is_file = os.path.isfile(proto_path)

            if not path_exists:
                emit_error(issues, runfile, lineno, secpath,
                           'test group path not found in proto area.')
            elif path_is_file:
                if has_tests:
                    emit_error(
                        issues, runfile, lineno, secpath,
                        'test group path is a file and should not have a '
                        'tests property.')
                else:
                    emit_error(
                        issues, runfile, lineno, secpath,
                        'test group path is a file and should not have an '
                        'autotests property.')

            if has_tests:
                tests_raw = config.get(sec, 'tests')
                if has_adjacent_string_literals(tests_raw):
                    emit_error(
                        issues, runfile, lineno, secpath,
                        'tests list contains adjacent string literals '
                        '(possible missing comma).')

                try:
                    tests = ast.literal_eval(tests_raw)
                except (SyntaxError, ValueError) as err:
                    emit_error(
                        issues, runfile, lineno, secpath,
                        'tests is not a valid Python list: %s' % err)
                    continue

                if not isinstance(tests, list):
                    emit_error(issues, runfile, lineno, secpath,
                               'tests must evaluate to a list.')
                    continue

                bad = [repr(x) for x in tests if not isinstance(x, str)]
                if bad:
                    emit_error(issues, runfile, lineno, secpath,
                               'tests must contain only strings: %s' %
                               ', '.join(bad))
                    continue

                if not path_is_dir:
                    continue

                for test in tests:
                    tpath = os.path.join(proto_path, test)
                    if not is_test_file(tpath):
                        emit_error(issues, runfile, lineno, secpath,
                                   'test %s not found in proto area.' % test)
        else:
            if not is_test_file(proto_path):
                emit_error(issues, runfile, lineno, secpath,
                           'single test path not found in proto area.')

        # Check pre/post auxiliary scripts. They are allowed to live in any
        # directory, so we only verify they exist in the proto area.
        aux_dir = secpath if (has_tests or has_autotests) \
            else posixpath.dirname(secpath)
        for prop in ('pre', 'post'):
            if not config.has_option(sec, prop):
                continue
            val = config.get(sec, prop).strip()
            if not val:
                continue
            if posixpath.isabs(val):
                apath = os.path.join(protoroot, val.lstrip('/'))
            else:
                apath = os.path.join(protoroot, aux_dir.lstrip('/'), val)
            if not is_test_file(apath):
                emit_error(issues, runfile, lineno, secpath,
                           '%s script not found in proto area: %s' %
                           (prop, val))

    return issues


def main():
    args = parse_args()
    protoroot = os.path.abspath(os.path.expanduser(args.root))
    testroot = normalize_testroot(args.testroot)

    if not os.path.isdir(protoroot):
        sys.stderr.write('error: proto root not found: %s\n' % protoroot)
        return 2

    if not os.path.isdir(os.path.join(protoroot, 'opt')):
        sys.stderr.write('error: invalid proto root (missing opt/): %s\n' %
                         protoroot)
        return 2

    if testroot is None:
        sys.stderr.write('error: invalid -T value (must be a relative path '
                         'under proto root): %s\n' % args.testroot)
        return 2

    testroot_path = os.path.join(protoroot, testroot)
    if not os.path.isdir(testroot_path):
        sys.stderr.write('error: test root not found under proto root: %s\n' %
                         testroot_path)
        return 2

    runfiles = find_runfiles(args)
    archlist = MACH_ARCHITECTURES.get(args.mach, set())
    issues = []
    for runfile in runfiles:
        issues.extend(check_runfile(runfile, testroot, protoroot, archlist))

    for issue in issues:
        sys.stderr.write('%s\n' % issue)

    return 1 if issues else 0


if __name__ == '__main__':
    sys.exit(main())
