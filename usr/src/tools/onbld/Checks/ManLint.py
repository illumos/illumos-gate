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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#

#
# ManLint, wrap the mandoc lint tool in a pythonic API
#

import sys
from onbld.Checks.ProcessCheck import processcheck

def manlint(fh, filename=None, output=sys.stderr, **opts):
	opttrans = { 'picky': None }

	for x in filter(lambda x: x not in opttrans, opts):
		raise TypeError('mandoc() got an unexpected keyword '
				'argument %s' % x)

	options = [opttrans[x] for x in opts if opts[x] and opttrans[x]]
	options.append('-Tlint')

	if not filename:
		filename = fh.name

	ret, tmpfile = processcheck('mandoc', options, fh, output)

	if tmpfile:
		for line in tmpfile:
			line = line.replace('<stdin>', filename)
			output.write(line)

		tmpfile.close()
	return ret
