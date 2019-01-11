#!ON_PYTHON
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.

#
# Mercurial (lack of) keyword checks
#

import re, sys

# A general 'ident'-style decleration, to allow for leniency.
ident = re.compile(r'((\%Z\%(\%M\%)\s+\%I\%|\%W\%)\s+\%E\% SMI)')

#
# Absolutely anything that appears to be an SCCS keyword.
# It's impossible to programatically differentiate between these
# and other, legitimate, uses of matching strings.
#
anykword = re.compile(r'%[A-ILMP-UWYZ]%')

def keywords(fh, filename=None, lenient=False, verbose=False,
             output=sys.stderr):
    '''Search FH for SCCS keywords, which should not be present when
    Mercurial is in use.

    If LENIENT, accept #ident-style declarations, for the purposes of
    migration'''

    if not filename:
        filename = fh.name

    ret = 0
    lineno = 0

    for line in fh:
        line = line.rstrip('\r\n')
        lineno += 1

        if lenient and ident.search(line):
            continue

        match = anykword.findall(line)
        if match:
            ret = 1
            output.write('%s: %d: contains SCCS keywords "%s"\n' %
                         (filename, lineno, ', '.join(match)))
            if verbose:
                output.write("   %s\n" % line)

    return ret
