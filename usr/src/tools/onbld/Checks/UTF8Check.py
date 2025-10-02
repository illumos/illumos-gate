#! /usr/bin/python
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2025 Richard Lowe
#

#
# Check that source files contain only valid UTF-8
#

import io
import sys

def utf8check(path, output=sys.stderr):
        # When a file is opened as binary Python specifies a b'\n'
        # line-ending.  Because all valid multi-byte utf-8 characters have the
        # high bit set and this does not, it is safe for us to split a file
        # line-wise _before_ we decode it, we will never split in the middle
        # of a valid character, but may report an invalid character as if it
        # were on two separate lines.
	ret = 0
	with io.open(path, 'rb') as fh:
		errs = 0
		for (lineno, line) in enumerate(fh):
			try:
				line.decode("utf-8")
			except UnicodeDecodeError as e:
				errs += 1
				if errs < 10:
					output.write(f"{path}: {lineno + 1}: {e}\n")
				elif errs == 10:
					output.write(f"{path}: ... and more ...\n")
				ret = 1
	return ret
