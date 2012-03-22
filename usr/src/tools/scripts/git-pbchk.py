#!/usr/bin/python2.4
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
<<<<<<< HEAD
# Copyright 2008, 2011 Richard Lowe
=======
# Copyright 2008, 2012 Richard Lowe
>>>>>>> 8bcea97... 1960 developer tools should support git
#

import getopt
import os
import re
import subprocess
import sys

from cStringIO import StringIO

# This is necessary because, in a fit of pique, we used hg-format ignore lists
# for NOT files.
from mercurial import ignore

<<<<<<< HEAD
sys.path.insert(1, os.path.join('/opt/onbld/lib',
                                "python%d.%d" % sys.version_info[:2]))

from onbld.Checks import Comments, Copyright, CStyle, HdrChk
from onbld.Checks import JStyle, Keywords, Mapfile

def run(command):
    if type(command) != list:
        command = command.split()

=======
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

from onbld.Checks import Comments, Copyright, CStyle, HdrChk
from onbld.Checks import JStyle, Keywords, Mapfile


class GitError(Exception):
    pass

def git(command):
    """Run a command and return a stream containing its stdout (and write its
    stderr to its stdout)"""

    if type(command) != list:
        command = command.split()

    command = ["git"] + command

>>>>>>> 8bcea97... 1960 developer tools should support git
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    err = p.wait()
<<<<<<< HEAD
    return err != 0 and None or p.stdout

def git_root():
    p = run('git rev-parse --git-dir')
=======
    if err != 0:
        raise GitError(p.stdout.read())

    return p.stdout


def git_root():
    """Return the root of the current git workspace"""

    p = git('rev-parse --git-dir')
>>>>>>> 8bcea97... 1960 developer tools should support git

    if not p:
        sys.stderr.write("Failed finding git workspace\n")
        sys.exit(err)

    return os.path.abspath(os.path.join(p.readlines()[0],
                                        os.path.pardir))

<<<<<<< HEAD
def git_branch():
    p = run('git branch')
=======

def git_branch():
    """Return the current git branch"""

    p = git('branch')
>>>>>>> 8bcea97... 1960 developer tools should support git

    if not p:
        sys.stderr.write("Failed finding git branch\n")
        sys.exit(err)

    for elt in p:
        if elt[0] == '*':
<<<<<<< HEAD
            return elt.split()[1]

def git_parent_branch(branch):
    p = run(["git", "for-each-ref",
             "--format=%(refname:short) %(upstream:short)",
             "refs/heads/"])
=======
            if elt.endswith('(no branch)'):
                return None
            return elt.split()[1]


def git_parent_branch(branch):
    """Return the parent of the current git branch.

    If this branch tracks a remote branch, return the remote branch which is
    tracked.  If not, default to origin/master."""

    if not branch:
        return None

    p = git("for-each-ref --format=%(refname:short) %(upstream:short) " +
            "refs/heads/")
>>>>>>> 8bcea97... 1960 developer tools should support git

    if not p:
        sys.stderr.write("Failed finding git parent branch\n")
        sys.exit(err)

    for line in p:
        # Git 1.7 will leave a ' ' trailing any non-tracking branch
        if ' ' in line and not line.endswith(' \n'):
            local, remote = line.split()
            if local == branch:
                return remote
    return 'origin/master'

<<<<<<< HEAD
def git_comments(branch):
    p = run('git log --pretty=format:%%B %s..' % branch)
=======

def git_comments(parent):
    """Return a list of any checkin comments on this git branch"""

    p = git('log --pretty=format:%%B %s..' % parent)
>>>>>>> 8bcea97... 1960 developer tools should support git

    if not p:
        sys.stderr.write("Failed getting git comments\n")
        sys.exit(err)

    return map(lambda x: x.strip(), p.readlines())


<<<<<<< HEAD
def git_file_list(branch, paths=''):
    '''Set of files which have ever changed between BRANCH and here'''
    p = run("git log --name-only --pretty=format: %s.. %s" %
             (branch, paths))
=======
def git_file_list(parent, paths=None):
    """Return the set of files which have ever changed on this branch.

    NB: This includes files which no longer exist, or no longer actually
    differ."""

    p = git("log --name-only --pretty=format: %s.. %s" %
             (parent, ' '.join(paths)))
>>>>>>> 8bcea97... 1960 developer tools should support git

    if not p:
        sys.stderr.write("Failed building file-list from git\n")
        sys.exit(err)

    ret = set()
    for fname in p:
        if fname and not fname.isspace() and fname not in ret:
            ret.add(fname.strip())

    return ret


def not_check(root, cmd):
<<<<<<< HEAD
    '''Return a function to do NOT matching'''
=======
    """Return a function which returns True if a file given as an argument
    should be excluded from the check named by 'cmd'"""
>>>>>>> 8bcea97... 1960 developer tools should support git

    ignorefiles = filter(os.path.exists,
                         [os.path.join(root, ".git", "%s.NOT" % cmd),
                          os.path.join(root, "exception_lists", cmd)])
    if len(ignorefiles) > 0:
        return ignore.ignore(root, ignorefiles, sys.stderr.write)
    else:
        return lambda x: False


<<<<<<< HEAD
def gen_files(root, branch, paths, exclude):
    # Taken entirely from 2.6's os.path.relpath which we would use if we
=======
def gen_files(root, parent, paths, exclude):
    """Return a function producing file names, relative to the current
    directory, of any file changed on this branch (limited to 'paths' if
    requested), and excluding files for which exclude returns a true value """

    # Taken entirely from Python 2.6's os.path.relpath which we would use if we
>>>>>>> 8bcea97... 1960 developer tools should support git
    # could.
    def relpath(path, here):
        c = os.path.abspath(os.path.join(root, path)).split(os.path.sep)
        s = os.path.abspath(here).split(os.path.sep)
        l = len(os.path.commonprefix((s, c)))
        return os.path.join(*[os.path.pardir] * (len(s)-l) + c[l:])

<<<<<<< HEAD
    def ret(select=lambda x: True):
        for f in git_file_list(branch, paths):
=======
    def ret(select=None):
        if not select:
            select = lambda x: True

        for f in git_file_list(parent, paths):
>>>>>>> 8bcea97... 1960 developer tools should support git
            f = relpath(f, '.')
            if (os.path.exists(f) and select(f) and not exclude(f)):
                yield f
    return ret

<<<<<<< HEAD
def comchk(root, branch, flist, output):
    output.write("Comments:\n")

    return Comments.comchk(git_comments(branch), check_db=True,
                           output=output)

def mapfilechk(root, branch, flist, output):
=======

def comchk(root, parent, flist, output):
    output.write("Comments:\n")

    return Comments.comchk(git_comments(parent), check_db=True,
                           output=output)


def mapfilechk(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
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
        fh = open(f, 'r')
        ret |= Mapfile.mapfilechk(fh, output=output)
        fh.close()
    return ret


<<<<<<< HEAD
def copyright(root, branch, flist, output):
=======
def copyright(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0
    output.write("Copyrights:\n")
    for f in flist():
        fh = open(f, 'r')
        ret |= Copyright.copyright(fh, output=output)
        fh.close()
    return ret


<<<<<<< HEAD
def hdrchk(root, branch, flist, output):
=======
def hdrchk(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0
    output.write("Header format:\n")
    for f in flist(lambda x: x.endswith('.h')):
        fh = open(f, 'r')
        ret |= HdrChk.hdrchk(fh, lenient=True, output=output)
        fh.close()
    return ret


<<<<<<< HEAD
def cstyle(root, branch, flist, output):
=======
def cstyle(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0
    output.write("C style:\n")
    for f in flist(lambda x: x.endswith('.c') or x.endswith('.h')):
        fh = open(f, 'r')
        ret |= CStyle.cstyle(fh, output=output, picky=True,
                             check_posix_types=True,
                             check_continuation=True)
        fh.close()
    return ret


<<<<<<< HEAD
def jstyle(root, branch, flist, output):
=======
def jstyle(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0
    output.write("Java style:\n")
    for f in flist(lambda x: x.endswith('.java')):
        fh = open(f, 'r')
        ret |= JStyle.jstyle(fh, output=output, picky=True)
        fh.close()
    return ret


<<<<<<< HEAD
def keywords(root, branch, flist, output):
=======
def keywords(root, parent, flist, output):
>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0
    output.write("SCCS Keywords:\n")
    for f in flist():
        fh = open(f, 'r')
        ret |= Keywords.keywords(fh, output=output)
        fh.close()
    return ret


<<<<<<< HEAD
def run_checks(root, branch, cmds, paths='', opts={}):
=======
def run_checks(root, parent, cmds, paths='', opts={}):
    """Run the checks given in 'cmds', expected to have well-known signatures,
    and report results for any which fail.

    Return failure if any of them did.

    NB: the function name of the commands passed in is used to name the NOT
    file which excepts files from them."""

>>>>>>> 8bcea97... 1960 developer tools should support git
    ret = 0

    for cmd in cmds:
        s = StringIO()

        exclude = not_check(root, cmd.func_name)
<<<<<<< HEAD
        result = cmd(root, branch, gen_files(root, branch, paths, exclude),
=======
        result = cmd(root, parent, gen_files(root, parent, paths, exclude),
>>>>>>> 8bcea97... 1960 developer tools should support git
                     output=s)
        ret |= result

        if result != 0:
            print s.getvalue()

    return ret


<<<<<<< HEAD
def nits(root, branch, paths=''):
=======
def nits(root, parent, paths):
>>>>>>> 8bcea97... 1960 developer tools should support git
    cmds = [copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            mapfilechk]
<<<<<<< HEAD
    run_checks(root, branch, cmds, paths='')

def pbchk(root, branch):
=======
    run_checks(root, parent, cmds, paths)


def pbchk(root, parent, paths):
>>>>>>> 8bcea97... 1960 developer tools should support git
    cmds = [comchk,
            copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            mapfilechk]
<<<<<<< HEAD
    run_checks(root, branch, cmds)

if __name__ == '__main__':
    branch = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'b:')
    except getopt.GetoptError, e:
        sys.stderr.write(str(e))
        sys.stderr.write("Usage: git-nits [-b branch] [path...]\n")
=======
    run_checks(root, parent, cmds)


def main(cmd, args):
    parent_branch = None

    try:
        opts, args = getopt.getopt(args, 'b:')
    except getopt.GetoptError, e:
        sys.stderr.write(str(e) + '\n')
        sys.stderr.write("Usage: %s [-b branch] [path...]\n" % cmd)
>>>>>>> 8bcea97... 1960 developer tools should support git
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-b':
<<<<<<< HEAD
            branch = arg

    if not branch:
        branch = git_parent_branch(git_branch())

    func = nits
    if sys.argv[0].endswith('/git-pbchk'):
        func = pbchk

    func(git_root(), branch)
=======
            parent_branch = arg

    if not parent_branch:
        parent_branch = git_parent_branch(git_branch())

    func = nits
    if cmd == 'git-pbchk':
        func = pbchk
        if args:
            sys.stderr.write("only complete workspaces may be pbchk'd\n");
            sys.exit(1)

    func(git_root(), parent_branch, args)

if __name__ == '__main__':
    try:
        main(os.path.basename(sys.argv[0]), sys.argv[1:])
    except GitError, e:
        sys.stderr.write("failed to run git:\n %s\n" % str(e))
        sys.exit(1)
>>>>>>> 8bcea97... 1960 developer tools should support git
