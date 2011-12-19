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
# Copyright 2008, 2011 Richard Lowe
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

sys.path.insert(1, os.path.join('/opt/onbld/lib',
                                "python%d.%d" % sys.version_info[:2]))

from onbld.Checks import Comments, Copyright, CStyle, HdrChk
from onbld.Checks import JStyle, Keywords, Mapfile

def run(command):
    if type(command) != list:
        command = command.split()

    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    err = p.wait()
    return err != 0 and None or p.stdout

def git_root():
    p = run('git rev-parse --git-dir')

    if not p:
        sys.stderr.write("Failed finding git workspace\n")
        sys.exit(err)

    return os.path.abspath(os.path.join(p.readlines()[0],
                                        os.path.pardir))

def git_branch():
    p = run('git branch')

    if not p:
        sys.stderr.write("Failed finding git branch\n")
        sys.exit(err)

    for elt in p:
        if elt[0] == '*':
            return elt.split()[1]

def git_parent_branch(branch):
    p = run(["git", "for-each-ref",
             "--format=%(refname:short) %(upstream:short)",
             "refs/heads/"])

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

def git_comments(branch):
    p = run('git log --pretty=format:%%B %s..' % branch)

    if not p:
        sys.stderr.write("Failed getting git comments\n")
        sys.exit(err)

    return map(lambda x: x.strip(), p.readlines())


def git_file_list(branch, paths=''):
    '''Set of files which have ever changed between BRANCH and here'''
    p = run("git log --name-only --pretty=format: %s.. %s" %
             (branch, paths))

    if not p:
        sys.stderr.write("Failed building file-list from git\n")
        sys.exit(err)

    ret = set()
    for fname in p:
        if fname and not fname.isspace() and fname not in ret:
            ret.add(fname.strip())

    return ret


def not_check(root, cmd):
    '''Return a function to do NOT matching'''

    ignorefiles = filter(os.path.exists,
                         [os.path.join(root, ".git", "%s.NOT" % cmd),
                          os.path.join(root, "exception_lists", cmd)])
    if len(ignorefiles) > 0:
        return ignore.ignore(root, ignorefiles, sys.stderr.write)
    else:
        return lambda x: False


def gen_files(root, branch, paths, exclude):
    # Taken entirely from 2.6's os.path.relpath which we would use if we
    # could.
    def relpath(path, here):
        c = os.path.abspath(os.path.join(root, path)).split(os.path.sep)
        s = os.path.abspath(here).split(os.path.sep)
        l = len(os.path.commonprefix((s, c)))
        return os.path.join(*[os.path.pardir] * (len(s)-l) + c[l:])

    def ret(select=lambda x: True):
        for f in git_file_list(branch, paths):
            f = relpath(f, '.')
            if (os.path.exists(f) and select(f) and not exclude(f)):
                yield f
    return ret

def comchk(root, branch, flist, output):
    output.write("Comments:\n")

    return Comments.comchk(git_comments(branch), check_db=True,
                           output=output)

def mapfilechk(root, branch, flist, output):
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


def copyright(root, branch, flist, output):
    ret = 0
    output.write("Copyrights:\n")
    for f in flist():
        fh = open(f, 'r')
        ret |= Copyright.copyright(fh, output=output)
        fh.close()
    return ret


def hdrchk(root, branch, flist, output):
    ret = 0
    output.write("Header format:\n")
    for f in flist(lambda x: x.endswith('.h')):
        fh = open(f, 'r')
        ret |= HdrChk.hdrchk(fh, lenient=True, output=output)
        fh.close()
    return ret


def cstyle(root, branch, flist, output):
    ret = 0
    output.write("C style:\n")
    for f in flist(lambda x: x.endswith('.c') or x.endswith('.h')):
        fh = open(f, 'r')
        ret |= CStyle.cstyle(fh, output=output, picky=True,
                             check_posix_types=True,
                             check_continuation=True)
        fh.close()
    return ret


def jstyle(root, branch, flist, output):
    ret = 0
    output.write("Java style:\n")
    for f in flist(lambda x: x.endswith('.java')):
        fh = open(f, 'r')
        ret |= JStyle.jstyle(fh, output=output, picky=True)
        fh.close()
    return ret


def keywords(root, branch, flist, output):
    ret = 0
    output.write("SCCS Keywords:\n")
    for f in flist():
        fh = open(f, 'r')
        ret |= Keywords.keywords(fh, output=output)
        fh.close()
    return ret


def run_checks(root, branch, cmds, paths='', opts={}):
    ret = 0

    for cmd in cmds:
        s = StringIO()

        exclude = not_check(root, cmd.func_name)
        result = cmd(root, branch, gen_files(root, branch, paths, exclude),
                     output=s)
        ret |= result

        if result != 0:
            print s.getvalue()

    return ret


def nits(root, branch, paths=''):
    cmds = [copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            mapfilechk]
    run_checks(root, branch, cmds, paths='')

def pbchk(root, branch):
    cmds = [comchk,
            copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            mapfilechk]
    run_checks(root, branch, cmds)

if __name__ == '__main__':
    branch = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'b:')
    except getopt.GetoptError, e:
        sys.stderr.write(str(e))
        sys.stderr.write("Usage: git-nits [-b branch] [path...]\n")
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-b':
            branch = arg

    if not branch:
        branch = git_parent_branch(git_branch())

    func = nits
    if sys.argv[0].endswith('/git-pbchk'):
        func = pbchk

    func(git_root(), branch)
