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
# Check header files conform to ON standards.
#

import sys, os, getopt

sys.path.append(os.path.join(os.path.dirname(__file__), '../lib/python'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from onbld.Checks.HdrChk import hdrchk

def usage():
	progname = os.path.split(sys.argv[0])[1]
	msg =  ['Usage: %s [-a] file [file...]\n' % progname,
		'  -a\tApply (more lenient) application header rules\n']
	sys.stderr.writelines(msg)


try:
	opts, args = getopt.getopt(sys.argv[1:], 'a')
except getopt.GetoptError:
	usage()
	sys.exit(2) 

lenient = False
for opt, arg in opts:
	if opt == '-a':
		lenient = True

ret = 0
for filename in args:
	try:
		fh = open(filename, 'r')
	except IOError, e:
		sys.stderr.write("failed to open '%s': %s\n" %
				 (e.filename, e.strerror))
	else:
		ret |= hdrchk(fh, lenient=lenient, output=sys.stderr)
		fh.close()
sys.exit(ret)
