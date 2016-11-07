#!@PYTHON@
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
# Check for valid CDDL blocks in source files.
#

import sys, os, getopt, fnmatch

sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "lib",
                                "python%d.%d" % sys.version_info[:2]))

# Allow running from the source tree, using the modules in the source tree
sys.path.insert(2, os.path.join(os.path.dirname(__file__), '..'))

from onbld.Checks.Cddl import cddlchk

class ExceptionList(object):
	def __init__(self):
		self.dirs = []
		self.files = []
		self.extensions = []

	def load(self, exfile):
		fh = None
		try:
			fh = open(exfile, 'r')
		except IOError, e:
			sys.stderr.write('Failed to open exception list: '
					 '%s: %s\n' % (e.filename, e.strerror))
			sys.exit(2)

		for line in fh:
			line = line.strip()

			if line.strip().endswith('/'):
				self.dirs.append(line[0:-1])
			elif line.startswith('*.'):
				self.extensions.append(line)
			else:
				self.files.append(line)

		fh.close()

	def match(self, filename):
		if os.path.isdir(filename):
			return filename in self.dirs
		else:
			if filename in self.files:
				return True

			for pat in self.extensions:
				if fnmatch.fnmatch(filename, pat):
					return True

	def __contains__(self, elt):
		return self.match(elt)

def usage():
	progname = os.path.split(sys.argv[0])[1]
	sys.stderr.write('''Usage: %s [-av] [-x exceptions] paths...
        -a		check that all the specified files have a CDDL block.
        -v		report on all files, not just those with errors.
        -x exceptions	load an exceptions file
''' % progname)
	sys.exit(2)


def check(filename, opts):
	try:
		fh = open(filename, 'r')
	except IOError, e:
		sys.stderr.write("failed to open '%s': %s\n" %
				 (e.filename, e.strerror))
		return 1
	else:
		return cddlchk(fh, verbose=opts['verbose'],
			       lenient=opts['lenient'],
			       output=sys.stdout)

def walker(opts, dirname, fnames):
	for f in fnames:
		path = os.path.join(dirname, f)

		if not os.path.isdir(path):
			if not path in opts['exclude']:
				opts['status'] |= check(path, opts)
		else:
			if path in opts['exclude']:
				fnames.remove(f)

def walkpath(path, opts):
	if os.path.isdir(path):
		os.path.walk(path, walker, opts)
	else:
		if not path in opts['exclude']:
			opts['status'] |= check(path, opts)

def main(args):
	options = {
		'status': 0,
		'lenient': True,
		'verbose': False,
		'exclude': ExceptionList()
	}

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'avx:')
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-a':
			options['lenient'] = False
		elif opt == '-v':
			options['verbose'] = True
		elif opt == '-x':
			options['exclude'].load(arg)

	for path in args:
		walkpath(path, options)

	return options['status']

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
