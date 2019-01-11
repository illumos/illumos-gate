#!ON_PYTHON

CDDL = '''
CDDL HEADER START

The contents of this file are subject to the terms of the
Common Development and Distribution License (the "License").
You may not use this file except in compliance with the License.

You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
or http://www.opensolaris.org/os/licensing.
See the License for the specific language governing permissions
and limitations under the License.

When distributing Covered Code, include this CDDL HEADER in each
file and include the License file at usr/src/OPENSOLARIS.LICENSE.
If applicable, add the following below this CDDL HEADER, with the
fields enclosed by brackets "[]" replaced with your own identifying
information: Portions Copyright [yyyy] [name of copyright owner]

CDDL HEADER END
'''

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.

#
# Check that source files contain a valid CDDL block
#

import sys
from onbld.Checks import CmtBlk

# scmtest has a test for cddlchk that depends on the variable
# Cddl.CmntChrs. However, that variable has been refactored into
# CmtBlk. The following line preserves the original interface
# from the Cddl module, and allows existing programs that assume
# Cddl.CmntChrs exists to continue working.
#
CmntChrs = CmtBlk.CmntChrs

# The CDDL string above contains the block guards so that the text will
# be tested by cddlchk. However, we don't want to include the initial
# \n or the block guards in the text passed in.
#
CDDL = CDDL.splitlines()[3:-2]

def cddlchk(fh, filename=None, lenient=False, verbose=False, output=sys.stderr):
	return CmtBlk.cmtblkchk(fh, 'CDDL', CDDL, filename=filename,
				lenient=lenient, verbose=verbose, output=output)
