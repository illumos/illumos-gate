#! /usr/bin/python
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

'''
Create a wx-style active list on stdout based on a Mercurial
workspace in support of webrev's Mercurial support.
'''

#
# NB: This assumes the normal onbld directory structure
#
import sys, os
sys.path.insert(1, "%s/../lib/python" % os.path.dirname(__file__))
sys.path.insert(1, "%s/.." % os.path.dirname(__file__))

from onbld.Scm import Version

try:
    Version.check_version()
except Version.VersionMismatch, e:
    sys.stderr.write("Error: %s\n" % e)
    sys.exit(1)

import getopt, binascii
from mercurial import hg, repo
from onbld.Scm.WorkSpace import WorkSpace

def usage():
    sys.stderr.write("usage: %s [-p parent] -w workspace\n" %
                     os.path.basename(__file__))
    sys.exit(2)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'w:p:')
    except getopt.GetoptError, e:
        sys.stderr.write(str(e) + '\n')
        usage()

    parentpath = None
    wspath = None

    for opt, arg in opts:
        if opt == '-w':
            wspath = arg
        elif opt == '-p':
            parentpath = arg

    if not wspath:
        usage()

    try:
        repository = hg.repository(None, wspath)
    except repo.RepoError, e:
        sys.stderr.write("failed to open repository: %s\n" % e)
        sys.exit(1)

    ws = WorkSpace(repository)
    act = ws.active(parentpath)

    node = act.parenttip.node()
    parenttip = binascii.hexlify(node)
    print "HG_PARENT=" + parenttip

    entries = [i for i in act]
    entries.sort()

    for entry in entries:
        if entry.is_renamed():
            print "%s %s" % (entry.name, entry.parentname)
        else:
            print entry.name

        # Strip blank lines.
        comments = filter(lambda x: x and not x.isspace(),
                          entry.comments)

        print
        if comments:
            print '\n'.join(comments)
        else:
            print "*** NO COMMENTS ***"
        print

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(1)
