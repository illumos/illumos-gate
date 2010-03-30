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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

# last valid Sun copyright
suncopyright = re.compile(r'Copyright ([\d, -]+) Sun Microsystems, Inc\.' +
			  r'(\s+)(All rights reserved\.)?')

# old, check to make sure no longer present
licterms = 'Use is subject to license terms.'

# initial Oracle copyright
goodcopyright = re.compile(r'Copyright \(c\) (\d\d\d\d, )?(\d\d\d\d)(,)? ' +
			   r'Oracle and/or its affiliates\.(\s+)' +
			   r'All rights reserved\.')

def copyright(fh, filename=None, output=sys.stderr):
	ret = lineno = rights = 0
	check_license = False

	if not filename:
		filename = fh.name

	for line in fh:
		lineno += 1

		if check_license:
			check_license = False
			if licterms in line:
				err(output, "old '%s' message found" % licterms,
				    filename, lineno)
				ret = 1
				continue

		if oldcopyright.search(line):
			err(output, "ancient Sun copyright", filename,
			    lineno)
			rights += 1
			ret = 1
			check_license = True
			continue
		elif oldcopyright1.search(line):
			err(output, "pre-2002 Sun copyright", filename, lineno)
			rights += 1
			ret = 1
			check_license = True
			continue
		elif suncopyright.search(line):
			err(output, "old Sun copyright", filename, lineno)
			rights += 1
			ret = 1
			check_license = True
			continue

		#
		# group 1 = optional initial year
		# group 2 = current year
		# group 3 = comma after current year
		# group 4 = spacing between phrases
		#
		match = goodcopyright.search(line)
		if match:
			# only check for the old license message on the line
			# following a copyright match
			check_license = True
			rights += 1

			year = time.strftime('%Y')
			if match.group(2) != year:
				err(output, "wrong copyright year %s, should "
				    "be %s" %
				    (match.group(2), year), filename, lineno)
				ret = 1

			if match.group(3) != ',':
				err(output, "need comma after current year",
				    filename, lineno)
				ret = 1

			if match.group(4) != ' ':
				err(output, "need one space between copyright "
				    "and all rights reserved phrases",
				    filename, lineno)
				ret = 1

	if rights == 0:
		err(output, "no copyright message found", filename)
		ret = 1

	return ret
