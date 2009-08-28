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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

'''
Deal with Mercurial versioning.

At a basic level, code to verify that the version of Mercurial in use
is suitable for use with Cadmium, and compare that version for the
sake of adapting to Mercurial API changes.
'''

#
# It is important that this module rely on as little of Mercurial as
# is possible.
#

#
# Mercurial >= 1.2 has util.version(), prior versions
# version.get_version() We discover which to use this way, rather than
# via ImportError to account for mercurial.demandimport delaying the
# ImportError exception.
#
from mercurial import util
if hasattr(util, 'version'):
    hg_version = util.version
else:
    from mercurial import version
    hg_version = version.get_version


class VersionMismatch(Exception):
    "Exception used to indicate a mismatch between SCM tools and Mercurial"
    pass

#
# List of versions that are explicitly acceptable to us
#
GOOD_VERSIONS = ['1.1.2', '1.3.1']


def check_version():
    '''Check that we're running on a suitable version of Mercurial'''

    def versionstring(versions):
        '''return the list, versions, as a vaguely grammatical string'''
        if len(versions) > 1:
            return "%s or %s" % (', '.join(versions[0:-1]), versions[-1])
        else:
            return versions[0]

    if hg_version() not in GOOD_VERSIONS:
        raise VersionMismatch("Scm expects Mercurial version %s, "
                              "actual version is %s." %
                              (versionstring(GOOD_VERSIONS),
                               hg_version()))


def _split_version(ver):
    '''Return the Mercurial version as a list [MAJOR, MINOR, MICRO],
    if this is not a released Mercurial return None.'''

    try:
        l = map(int, ver.split('.'))
        # If there's only one element, it's not really a tagged version
        if len(l) <= 1:
            return None
        else:
            return l
    except ValueError:
        return None


def at_least(desired):
    '''Return boolean indicating if the running version is greater
    than or equal to, the version specified by major, minor, micro'''

    hgver = _split_version(hg_version())
    desired = map(int, desired.split('.'))

    #
    # If _split_version() returns None, we're running on a Mercurial that
    # has not been tagged as a release.  We assume this to be newer
    # than any released version.
    #
    if hgver == None:
        return True

    # Pad our versions to the same overall length, appending 0's
    while len(hgver) < len(desired):
        hgver.append(0)
    while len(desired) < len(hgver):
        desired.append(0)

    for real, req in zip(hgver, desired):
        if real != req:
            return real > req

    return True
