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
# Copyright 2018 Gordon Ross <gordon.w.ross@gmail.com>
#

#
# Check file for whitespace issues
# (space tab, trailing space)
#


import time, re, sys

stMsg = 'space tab sequences'
twsMsg = 'has trailing spaces'

def err(stream, fname, lineno, msg):
	stream.write("%s:%d: %s\n" % (fname, lineno, msg))

def wscheck(fh, output=sys.stderr):
	lineno = 1
	ret = 0

	fname = fh.name

	for line in fh:
		if re.search(r' \t', line):
			err(output, fname, lineno, stMsg);
			ret = 1
		if re.search(r'[ \t]$', line):
			err(output, fname, lineno, twsMsg);
			ret = 1
		lineno += 1

	return ret
