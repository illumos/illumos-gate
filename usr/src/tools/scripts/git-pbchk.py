#!@TOOLS_PYTHON@ -Es
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2008, 2012 Richard Lowe
# Copyright 2019 Garrett D'Amore <garrett@damore.org>
# Copyright (c) 2015, 2016 by Delphix. All rights reserved.
# Copyright 2016 Nexenta Systems, Inc.
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2024 Bill Sommerfeld
#

from __future__ import print_function

import getopt
import io
import os
import re
import subprocess
import sys
import tempfile
import textwrap

if sys.version_info[0] < 3:
    from cStringIO import StringIO
else:
    from io import StringIO

#
# Adjust the load path based on our location and the version of python into
# which it is being loaded.  This assumes the normal onbld directory
# structure, where we are in bin/ and the modules are in
# lib/python(version)?/onbld/Scm/.  If that changes so too must this.
#
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "lib",
                                "python%d.%d" % sys.version_info[:2]))

#
# Add the relative path to usr/src/tools to the load path, such that when run
# from the source tree we use the modules also within the source tree.
#
sys.path.insert(2, os.path.join(os.path.dirname(__file__), ".."))

from onbld.Scm import Ignore
from onbld.Checks import Comments, Copyright, CStyle, HdrChk, WsCheck
from onbld.Checks import JStyle, Keywords, ManLint, Mapfile, SpellCheck
from onbld.Checks import ShellLint, PkgFmt

class GitError(Exception):
    pass

def git(command):
    """Run a command and return a stream containing its stdout (and write its
    stderr to its stdout)"""

    if type(command) != list:
        command = command.split()

    command = ["git"] + command

    try:
        tmpfile = tempfile.TemporaryFile(prefix="git-nits", mode="w+b")
    except EnvironmentError as e:
        raise GitError("Could not create temporary file: %s\n" % e)

    try:
        p = subprocess.Popen(command,
                             stdout=tmpfile,
                             stderr=subprocess.PIPE)
    except OSError as e:
        raise GitError("could not execute %s: %s\n" % (command, e))

    err = p.wait()
    if err != 0:
        raise GitError(p.stderr.read())

    tmpfile.seek(0)
    lines = []
    for l in tmpfile:
        lines.append(l.decode('utf-8', 'replace'))
    return lines

def git_root():
    """Return the root of the current git workspace"""

    p = git('rev-parse --show-toplevel')
    dir = p[0].strip()

    return os.path.abspath(dir)

def git_branch():
    """Return the current git branch"""

    p = git('branch')

    for elt in p:
        if elt[0] == '*':
            if elt.endswith('(no branch)'):
                return None
            return elt.split()[1]

def git_parent_branch(branch):
    """Return the parent of the current git branch.

    If this branch tracks a remote branch, return the remote branch which is
    tracked.  If not, default to origin/master."""

    if not branch:
        return None

    p = git(["for-each-ref", "--format=%(refname:short) %(upstream:short)",
            "refs/heads/"])

    if not p:
        sys.stderr.write("Failed finding git parent branch\n")
        sys.exit(1)

    for line in p:
        # Git 1.7 will leave a ' ' trailing any non-tracking branch
        if ' ' in line and not line.endswith(' \n'):
            local, remote = line.split()
            if local == branch:
                return remote
    return 'origin/master'

def slices(strlist, sep):
    """Yield start & end of each commit within the list of comments"""
    low = 0
    for i, v in enumerate(strlist):
        if v == sep:
            yield(low, i)
            low = i+1

    if low != len(strlist):
        yield(low, len(strlist))

def git_comments(parent):
    """Return the checkin comments for each commit on this git branch,
    structured as a list of lists of lines."""

    p = git('log --pretty=tformat:%%B:SEP: %s..' % parent)

    if not p:
        sys.stderr.write("No outgoing changesets found - missing -p option?\n");
        sys.exit(1)

    return [ [line.strip() for line in p[a:b]]
             for (a, b) in slices(p, ':SEP:\n')]

def git_file_list(parent, paths=None):
    """Return the set of files which have ever changed on this branch.

    NB: This includes files which no longer exist, or no longer actually
    differ."""

    p = git("log --name-only --pretty=format: %s.. %s" %
             (parent, ' '.join(paths)))

    if not p:
        sys.stderr.write("Failed building file-list from git\n")
        sys.exit(1)

    ret = set()
    for fname in p:
        fname = fname.strip()
        if fname and not fname.isspace():
            ret.add(fname)

    return sorted(ret)

def not_check(root, cmd):
    """Return a function which returns True if a file given as an argument
    should be excluded from the check named by 'cmd'"""

    ignorefiles = list(filter(os.path.exists,
                         [os.path.join(root, ".git/info", "%s.NOT" % cmd),
                          os.path.join(root, "exception_lists", cmd)]))
    return Ignore.ignore(root, ignorefiles)

def gen_files(root, parent, paths, exclude, filter=None):
    """Return a function producing file names, relative to the current
    directory, of any file changed on this branch (limited to 'paths' if
    requested), and excluding files for which exclude returns a true value """

    if filter is None:
        filter = lambda x: os.path.isfile(x)

    def ret(select=None):
        if not select:
            select = lambda x: True

        for abspath in git_file_list(parent, paths):
            path = os.path.relpath(os.path.join(root, abspath), '.')
            try:
                res = git("diff %s HEAD %s" % (parent, path))
            except GitError as e:
                # This ignores all the errors that can be thrown. Usually, this
                # means that git returned non-zero because the file doesn't
                # exist, but it could also fail if git can't create a new file
                # or it can't be executed.  Such errors are 1) unlikely, and 2)
                # will be caught by other invocations of git().
                continue
            empty = not res
            if (filter(path) and not empty and
                select(path) and not exclude(abspath)):
                yield path
    return ret

def gen_links(root, parent, paths, exclude):
    """Return a function producing symbolic link names, relative to the current
    directory, of any file changed on this branch (limited to 'paths' if
    requested), and excluding files for which exclude returns a true value """

    return gen_files(root, parent, paths, exclude, lambda x: os.path.islink(x))

def gen_none(root, parent, paths, exclude):
    """ Return a function returning the empty list """
    return lambda x: []

# The list of possible checks.   Each is recorded as two-function pair; the
# first is the actual checker, and the second is the generator which creates
# the list of things that the checker works on.

checks = {}
nits_checks = []
all_checks = []

def add_check(fn, gen):
    """ Define a checker and add it to the appropriate lists """
    name = fn.__name__
    if fn.__doc__ is None:
        raise ValueError('Check function lacks a documentation string',
                         name)
    checks[name] = (fn, gen)
    all_checks.append(name)
    if gen != gen_none:
        nits_checks.append(name)
    return fn

def filechecker(fn):
    """ Decorator which identifies a function as being a file-checker """
    return add_check(fn, gen_files)

def linkchecker(fn):
    """ Decorator which identifies a function as being a symlink-checker """
    return add_check(fn, gen_links)

def wschecker(fn):
    """ Decorator which identifies a function as being a workspace checker """
    return add_check(fn, gen_none)

@wschecker
def comchk(root, parent, flist, output):
    "Check that putback comments follow the prescribed format"
    output.write("Comments:\n")

    comments = git_comments(parent)
    multi = len(comments) > 1
    state = {}

    ret = 0
    for commit in comments:

        s = StringIO()

        result = Comments.comchk(commit, check_db=True,
                                 output=s, bugs=state)
        ret |= result

        if result != 0:
            if multi:
                output.write('\n%s\n' % commit[0])
            output.write(s.getvalue())

    return ret

@filechecker
def copyright(root, parent, flist, output):
    """Check that each source file contains a copyright notice for the current
year. You don't need to fix this if you, the potential new copyright holder,
chooses not to."""
    ret = 0
    output.write("Copyrights:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Copyright.copyright(fh, output=output)
    return ret

@filechecker
def cstyle(root, parent, flist, output):
    "Check that C source files conform to the illumos C style rules"
    ret = 0
    output.write("C style:\n")
    for f in flist(lambda x: x.endswith('.c') or x.endswith('.h')):
        with io.open(f, mode='rb') as fh:
            ret |= CStyle.cstyle(fh, output=output, picky=True,
                             check_posix_types=True,
                             check_continuation=True)
    return ret

@filechecker
def hdrchk(root, parent, flist, output):
    "Check that C header files conform to the illumos header style rules"
    ret = 0
    output.write("Header format:\n")
    for f in flist(lambda x: x.endswith('.h')):
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= HdrChk.hdrchk(fh, lenient=True, output=output)
    return ret

@filechecker
def jstyle(root, parent, flist, output):
    """Check that Java source files conform to the illumos Java style rules
(which differ from the traditionally recommended Java style)"""

    ret = 0
    output.write("Java style:\n")
    for f in flist(lambda x: x.endswith('.java')):
        with io.open(f, mode='rb') as fh:
            ret |= JStyle.jstyle(fh, output=output, picky=True)
    return ret

@filechecker
def keywords(root, parent, flist, output):
    """Check that no source files contain unexpanded SCCS keywords.
It is possible that this check may false positive on certain inputs.
It is generally obvious when this is the case.

This check does not check for expanded SCCS keywords, though the common
'ident'-style lines should be removed regardless of whether they are
expanded."""

    ret = 0
    output.write("SCCS Keywords:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Keywords.keywords(fh, output=output)
    return ret

@filechecker
def manlint(root, parent, flist, output):
    "Check for problems with man pages."

    ret = 0
    output.write("Man page format/spelling:\n")
    ManfileRE = re.compile(r'.*\.[0-9][a-z]*$', re.IGNORECASE)
    for f in flist(lambda x: ManfileRE.match(x)):
        with io.open(f, mode='rb') as fh:
            ret |= ManLint.manlint(fh, output=output, picky=True)
            ret |= SpellCheck.spellcheck(fh, output=output)
    return ret

@filechecker
def mapfilechk(root, parent, flist, output):
    """Check that linker mapfiles contain a comment directing anyone
editing to read the directions in usr/lib/README.mapfiles."""

    ret = 0
    # We are interested in examining any file that has the following
    # in its final path segment:
    #    - Contains the word 'mapfile'
    #    - Begins with 'map.'
    #    - Ends with '.map'
    # We don't want to match unless these things occur in final path segment
    # because directory names with these strings don't indicate a mapfile.
    # We also ignore files with suffixes that tell us that the files
    # are not mapfiles.
    MapfileRE = re.compile(r'.*((mapfile[^/]*)|(/map\.+[^/]*)|(\.map))$',
        re.IGNORECASE)
    NotMapSuffixRE = re.compile(r'.*\.[ch]$', re.IGNORECASE)

    output.write("Mapfile comments:\n")

    for f in flist(lambda x: MapfileRE.match(x) and not
                   NotMapSuffixRE.match(x)):
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Mapfile.mapfilechk(fh, output=output)
    return ret

@filechecker
def shelllint(root, parent, flist, output):
    """Check shell scripts for common errors."""
    ret = 0
    output.write("Shell lint:\n")

    def isshell(x):
        (_, ext) = os.path.splitext(x)
        if ext in ['.sh', '.ksh']:
            return True
        if ext == '':
            with io.open(x, mode='r', errors='ignore') as fh:
                if re.match(r'^#.*\bk?sh\b', fh.readline()):
                    return True
        return False

    for f in flist(isshell):
        with io.open(f, mode='rb') as fh:
            ret |= ShellLint.lint(fh, output=output)

    return ret

@filechecker
def pkgfmt(root, parent, flist, output):
    """Check package manifests for common errors."""
    ret = 0
    output.write("Package manifests:\n")

    for f in flist(lambda x: x.endswith('.p5m')):
        with io.open(f, mode='rb') as fh:
            ret |= PkgFmt.check(fh, output=output)

    return ret

def iswinreserved(name):
    reserved = [
        'con', 'prn', 'aux', 'nul',
        'com1', 'com2', 'com3', 'com4', 'com5',
        'com6', 'com7', 'com8', 'com9', 'com0',
        'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5',
        'lpt6', 'lpt7', 'lpt8', 'lpt9', 'lpt0' ]
    l = name.lower()
    for r in reserved:
        if l == r or l.startswith(r+"."):
            return True
    return False

def haswinspecial(name):
    specials = '<>:"\\|?*'
    for c in name:
        if c in specials:
            return True
    return False

@filechecker
def winnames(root, parent, flist, output):
    "Check for filenames which can't be used in a Windows filesystem."
    ret = 0
    output.write("Illegal filenames (Windows):\n")
    for f in flist():
        if haswinspecial(f):
            output.write("  "+f+": invalid character in name\n")
            ret |= 1
            continue

        parts = f.split('/')
        for p in parts:
            if iswinreserved(p):
                output.write("  "+f+": reserved file name\n")
                ret |= 1
                break

    return ret

@filechecker
def wscheck(root, parent, flist, output):
    "Check for whitespace issues such as mixed tabs/spaces in source files."
    ret = 0
    output.write("white space nits:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= WsCheck.wscheck(fh, output=output)
    return ret

@linkchecker
def symlinks(root, parent, flist, output):
    "Check for committed symlinks (there shouldn't be any)."
    ret = 0
    output.write("Symbolic links:\n")
    for f in flist():
        output.write("  "+f+"\n")
        ret |= 1
    return ret

def run_checks(root, parent, checklist, paths=''):
    """Run the checks named in 'checklist',
    and report results for any which fail.

    Return failure if any of them did.

    NB: the check names also name the NOT
    file which excepts files from them."""

    ret = 0

    for check in checklist:
        (cmd, gen) = checks[check]

        s = StringIO()

        exclude = not_check(root, check)
        result = cmd(root, parent, gen(root, parent, paths, exclude),
                     output=s)
        ret |= result

        if result != 0:
            print(s.getvalue())

    return ret

def print_checks():

    for c in all_checks:
        print(textwrap.fill(
            "%-11s %s" % (c, checks[c][0].__doc__),
            width=78,
            subsequent_indent=' '*12), '\n')

def main(cmd, args):
    parent_branch = None

    checklist = []

    try:
        opts, args = getopt.getopt(args, 'lb:c:p:')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        sys.stderr.write("Usage: %s [-l] [-c check] [-p branch] [path...]\n"
                         % cmd)
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-l':
            print_checks()
            sys.exit(0)
        # We accept "-b" as an alias of "-p" for backwards compatibility.
        elif opt == '-p' or opt == '-b':
            parent_branch = arg
        elif opt == '-c':
            if arg not in checks:
                sys.stderr.write("Unknown check '%s'\n" % arg)
                sys.exit(1)
            checklist.append(arg)

    if not parent_branch:
        parent_branch = git_parent_branch(git_branch())

    if len(checklist) == 0:
        if cmd == 'git-pbchk':
            if args:
                sys.stderr.write("only complete workspaces may be pbchk'd\n");
                sys.exit(1)
            checklist = all_checks
        else:
            checklist = nits_checks

    run_checks(git_root(), parent_branch, checklist, args)

if __name__ == '__main__':
    try:
        main(os.path.basename(sys.argv[0]), sys.argv[1:])
    except GitError as e:
        sys.stderr.write("failed to run git:\n %s\n" % str(e))
        sys.exit(1)
