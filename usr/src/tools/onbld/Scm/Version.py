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

'''
Minimal amount of code to check the version of Mercurial in use
against our expectations.
'''

#
# It is important that this rely on as little of Mercurial as is possible.
#

from mercurial import version


class VersionMismatch(Exception):
    "Exception used to indicate a mis-match between Scm tools and Mercurial"
    pass

#
# List of versions that are explicitly acceptable to us
#
GOOD_VERSIONS = ['1.0', '1.0.1', '1.0.2']


def check_version():
    '''Check that we're running on a suitable version of Mercurial'''

    def versionstring(versions):
        '''return the list, versions, as a vaguely grammatical string'''
        if len(versions) > 1:
            return "%s or %s" % (', '.join(versions[0:-1]), versions[-1])
        else:
            return versions[0]

    if version.get_version() not in GOOD_VERSIONS:
        raise VersionMismatch("Scm expects Mercurial version %s, "
                              "actual version is %s" %
                              (versionstring(GOOD_VERSIONS),
                               version.get_version()))
