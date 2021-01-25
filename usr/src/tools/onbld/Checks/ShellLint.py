#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

#
# ShellLint, wrap the 'shcomp -n' tool in a python API
#

import sys
from onbld.Checks.ProcessCheck import processcheck

def lint(fh, filename=None, output=sys.stderr, **opts):
	if not filename:
		filename = fh.name

	options = ['-n', '/dev/stdin', '/dev/null']

	ret, tmpfile = processcheck('shcomp', options, fh, output)

	if tmpfile:
		for line in tmpfile:
			if '`...` obsolete' in line:
				continue
			ret = 1

			line = line.replace('/dev/stdin', filename)
			line = line.replace('warning: ', '')
			output.write(line)

		tmpfile.close()
	return ret
