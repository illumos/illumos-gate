#! /usr/bin/python

CDDL = '''
CDDL HEADER START

The contents of this file are subject to the terms of the
Common Development and Distribution License (the "License").
You may not use this file except in compliance with the License.

You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
or http://www.opensolaris.org/os/licensing.
See the License for the specific language governing permissions
and limitations under the License.

When distributing Covered Code, include this CDDL HEADER in each
file and include the License file at usr/src/OPENSOLARIS.LICENSE.
If applicable, add the following below this CDDL HEADER, with the
fields enclosed by brackets "[]" replaced with your own identifying
information: Portions Copyright [yyyy] [name of copyright owner]

CDDL HEADER END
'''

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Check source files contain a valid CDDL block
#

import re, sys

CDDL = CDDL.splitlines()[1:]		# Don't include initial \n

CmntChrs = r'#*!/\\";. '
CDDLStartRE = re.compile(r'^[%s ]*CDDL HEADER START' % CmntChrs)
CDDLEndRE = re.compile(r'^[%s ]*CDDL HEADER END' % CmntChrs)

class CddlError(Exception):
	def __init__(self, lineno, seen, shouldbe):
		Exception.__init__(self)
		self.lineno = lineno
		self.seen = seen
		self.shouldbe = shouldbe

def checkblock(block):
	line = block['start']
	lictxt = block['block']

	for actual, valid in map(lambda x, y: (x and x.lstrip(CmntChrs), y),
			       lictxt, CDDL):
		if actual != valid:
			raise CddlError(line, actual, valid)
		line += 1

def cddlchk(fh, filename=None, lenient=False, verbose=False, output=sys.stderr):
	ret = 0
	blocks = []
	lic = []
	in_cddl = False
	start = 0
	lineno = 0

	if not filename:
		filename = fh.name

	for line in fh:
		line = line.rstrip('\r\n')
		lineno += 1
		
		if CDDLStartRE.search(line):
			in_cddl = True
			lic.append(line)
			start = lineno
		elif in_cddl and CDDLEndRE.search(line):
			in_cddl = False
			lic.append(line)
			blocks.append({'start':start, 'block':lic})
			start = 0
			lic = []
		elif in_cddl:
			lic.append(line)

	if in_cddl:
		output.write('Error: Incomplete CDDL block in file %s\n'
			     '    at line %s\n''' % (filename, start))

	# Check for no CDDL, warn if we're not being lenient
	if not len(blocks) and not lenient:
		if not ret:
			ret = 2
		output.write("Warning: No CDDL block in file %s\n" % filename)

	# Check for multiple CDDL blocks
	if len(blocks) > 1:
		ret = 1
		output.write('Error: Multiple CDDL blocks in file %s\n'
			     '    at lines %s\n''' %
			     (filename, ', '.join([str(x['start'])
						   for x in blocks])))

	# Validate each CDDL block
	for b in blocks:
		try:
			checkblock(b)
		except CddlError, e:
			ret = 1
			output.write(
				"Error: Invalid line in CDDL block in file %s\n"
				"    at line %d, should be\n"
				"    '%s'\n"
				"    is\n"
				"    '%s'\n" % (filename, e.lineno,
						e.shouldbe, e.seen))
			break
		
	if verbose and not ret:
		output.write("Message: Valid CDDL block in file %s\n" %
			     filename)

	return ret
