#! /usr/bin/python
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Check that link-editor mapfiles contain a valid mapfile header block
#

MAPFILE = '''
WARNING:  STOP NOW.  DO NOT MODIFY THIS FILE.
Object versioning must comply with the rules detailed in

	usr/src/lib/README.mapfiles

You should not be making modifications here until you've read the most current
copy of that file. If you need help, contact a gatekeeper for guidance.
'''

import sys, CmtBlk

MAPFILE = MAPFILE.splitlines()[1:]		# Don't include initial \n

def mapfilechk(fh, filename=None, verbose=False, output=sys.stderr):
	return CmtBlk.cmtblkchk(fh, 'MAPFILE', MAPFILE, filename=filename,
				verbose=verbose, output=output)
