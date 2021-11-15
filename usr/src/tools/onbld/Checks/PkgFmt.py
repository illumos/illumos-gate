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
# Package manifest check
#

import sys
from onbld.Checks.ProcessCheck import processcheck

def check(fh, filename=None, output=sys.stderr, **opts):
	if not filename:
		filename = fh.name

	options = ['-c', '-f', 'v2']
	ret, tmpfile = processcheck('pkgfmt', options, fh, output)
	tmpfile.close()
	if ret == 0:
		# Manifest passes validation
		return 0

	output.write('{} is not in pkgfmt v2 form;\n'.format(filename))
	output.write('run `pkgfmt -f v2` on the file to re-format ' +
	    'the manifest in-place\n')

	return 1

