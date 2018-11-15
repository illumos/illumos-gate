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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
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

import re, sys
from onbld.Checks import CmtBlk

MAPFILE = MAPFILE.splitlines()[1:]		# Don't include initial \n

def mapfilechk(fh, filename=None, verbose=False, output=sys.stderr):
	if filename:
		name = filename
	else:
		name = fh.name

	# Verify that the mapfile is using version 2 syntax. Read and discard
	# comment and empty lines until the first non-empty line is seen.
	# This line must be '$mapfile_version 2'.
	CmtRE = re.compile(r'#.*$')
	LeadingWSRE = re.compile(r'^\s+')
	VersionRE = re.compile(r'^\$mapfile_version\s+2\s*$')
	for line in fh:
		line = CmtRE.sub(r'', line)
		line = LeadingWSRE.sub(r'', line)
		if line == '' :
			continue

		# First non=empty line must be version declaration
		if not VersionRE.match(line):
			output.write("Warning: mapfile version 2 syntax"
				" expected in file %s\n" % name)
			return 1

		# We have verified version 2 syntax. Exit the loop
		break

	# If the mapfile contains a SYMBOL_VERSION directive, the file
	# must include a copy of the MAPFILE warning comment above. The
	# comment is specific to symbol versioning, so we don't harrass
	# the authors of mapfiles used exclusively for other purposes.
	SymVerRE = re.compile(r'^\s*symbol_version\s+', re.IGNORECASE)
	for line in fh:
		# If we find a SYMBOL_VERSION, then verify that the comment
		# is present. The comment usually precedes the mapfile_version
		# comment and any mapfile directives (including SYMBOL_VERSION),
		# so we need to rewind the file. This is more efficient than it
		# might seem: All of these items are near the top of the file,
		# so not not many lines are read, and file contents are
		# bufferred.
		if SymVerRE.match(line):
			fh.seek(0);
			return CmtBlk.cmtblkchk(fh, 'MAPFILE', MAPFILE,
				filename=filename, verbose=verbose,
				output=output)

	# Comment is not required.
	return 0
