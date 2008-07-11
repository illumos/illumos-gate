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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Make sure there is a correctly formed copyright message containing
# the current year.
#
# We treat extant but incorrect copyrights of known format as present
# for the purposes of the "no copyright found" messages to avoid
# treating every otherwise incorrect copyright as also not present
# 

import time, re, sys

def err(stream, msg, fname, line=None):
	if line:
		stream.write("%s: %d: %s\n" % (fname, line, msg))
	else:
		stream.write("%s: %s\n" % (fname, msg))

# pre-2002 copyright with '(c)'
oldcopyright = re.compile(r'Copyright \(c\) .* Sun Microsystems, Inc\.')

# pre-2002 copyright with 'by'
oldcopyright1 = re.compile(r'Copyright .* by Sun Microsystems, Inc\.')

# Valid, current copyright
goodcopyright = re.compile(r'Copyright ([\d, -]+) Sun Microsystems, Inc\.' +
			   r'(\s+)(All rights reserved\.)?')

licterms = 'Use is subject to license terms.'

def copyright(fh, filename=None, output=sys.stderr):
	ret = lineno = rights = 0
	# Are we expecting the license terms message on this line?
	expecting_license = False

	if not filename:
		filename = fh.name

	for line in fh:
		lineno += 1

		if expecting_license:
			expecting_license = False

			if licterms not in line:
				err(output, "'%s' message missing" % licterms,
				    filename, lineno)
				ret = 1
				continue
			elif rights > 0 and ret == 0:
				return 0
			continue

		if oldcopyright.search(line):
			err(output, "old copyright with '(c)'", filename,
			    lineno)
			rights += 1
			ret = 1
		elif oldcopyright1.search(line):
			err(output, "old copyright with 'by'", filename, lineno)
			rights += 1
			ret = 1

		#
		# group 1 = year
		# group 2 = spacing
		# group 3 = All rights reserved message.
		#
		match = goodcopyright.search(line)
		if match:
			expecting_license = True
			rights += 1

			year = time.strftime('%Y')
			if match.group(1) != year:
				err(output, "wrong copyright year %s, should "
				    "be %s" %
				    (match.group(1), year), filename, lineno)
				ret = 1

			if not match.group(3):
				err(output, "'All rights reserved.' message "
				    "missing",
				    filename, lineno)
				ret = 1
			elif match.group(2) != '  ':
				err(output, "need two spaces between copyright "
				    "and all rights reserved phrases",
				    filename, lineno)
				ret = 1
	#
	# If the last line left us expecting the license message,
	# we're pretty sure it isn't going to be there.
	#
	if expecting_license:
		err(output, "'Use is subject to license terms.' message "
		    "missing", filename, lineno)
		ret = 1

	if rights == 0:
		err(output, "no copyright message found", filename)
		ret = 1

	return ret
