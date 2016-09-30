#!@PYTHON@
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
#

'''
Create a wx-style active list on stdout based on a Mercurial
workspace in support of webrev's Mercurial support.
'''

#
# NB: This assumes the normal onbld directory structure
#
import sys, os

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "lib",
                                "python%d.%d" % sys.version_info[:2]))

# Allow running from the source tree, using the modules in the source tree
sys.path.insert(2, os.path.join(os.path.dirname(__file__), ".."))

from onbld.Scm import Version

try:
    Version.check_version()
except Version.VersionMismatch, versionerror:
    sys.stderr.write("Error: %s\n" % versionerror)
    sys.exit(1)


import getopt, binascii
from mercurial import error, hg, ui, util
from onbld.Scm.WorkSpace import WorkSpace


def usage():
    sys.stderr.write("usage: %s [-p parent] -w workspace\n" %
                     os.path.basename(__file__))
    sys.exit(2)


def main(argv):
    try:
        opts = getopt.getopt(argv, 'w:o:p:')[0]
    except getopt.GetoptError, e:
        sys.stderr.write(str(e) + '\n')
        usage()

    parentpath = None
    wspath = None
    outputfile = None

    for opt, arg in opts:
        if opt == '-w':
            wspath = arg
        elif opt == '-o':
            outputfile = arg
        elif opt == '-p':
            parentpath = arg

    if not wspath:
        usage()

    try:
        repository = hg.repository(ui.ui(), wspath)
    except error.RepoError, e:
        sys.stderr.write("failed to open repository: %s\n" % e)
        sys.exit(1)

    ws = WorkSpace(repository)
    act = ws.active(parentpath)

    node = act.parenttip.node()
    parenttip = binascii.hexlify(node)

    fh = None
    if outputfile:
        try:
            fh = open(outputfile, 'w')
        except EnvironmentError, e:
            sys.stderr.write("could not open output file: %s\n" % e)
            sys.exit(1)
    else:
        fh = sys.stdout

    fh.write("HG_PARENT=%s\n" % parenttip)

    entries = [i for i in act]
    entries.sort()

    for entry in entries:
        if entry.is_renamed() or entry.is_copied():
            fh.write("%s %s\n" % (entry.name, entry.parentname))
        else:
            fh.write("%s\n" % entry.name)

        # Strip blank lines.
        comments = filter(lambda x: x and not x.isspace(),
                          entry.comments)

        fh.write('\n')
        if comments:
            fh.write('%s\n' % '\n'.join(comments))
        else:
            fh.write("*** NO COMMENTS ***\n")
        fh.write('\n')

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(1)
    except util.Abort, msg:
        sys.stderr.write("Abort: %s\n" % msg)
        sys.exit(1)
