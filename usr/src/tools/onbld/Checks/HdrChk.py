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
# Check that header files conform to our standards
#
# Standards for all header files (lenient):
#
#       1) Begin with a comment containing a copyright message
#
#       2) Enclosed in a guard of the form:
#
#          #ifndef GUARD
#          #define GUARD
#          #endif /* [!]GUARD */
#
#          The preferred form is without the bang character, but either is
#          acceptable.
#
#       3) Has a valid ident declaration
#
# Additional standards for system header files:
#
#       1) The file guard must take the form '_FILENAME_H[_]', where FILENAME
#          matches the basename of the file.  If it is installed in a
#          subdirectory, it must be of the form _DIR_FILENAME_H.  The form
#          without the trailing underscore is preferred.
#
#       2) All #include directives must use the <> form.
#
#       3) If the header file contains anything besides comments and
#          preprocessor directives, then it must be enclosed in a C++ guard of
#          the form:
#
#          #ifdef __cplusplus
#          extern "C" {
#          #endif
#
#          #ifdef __cplusplus
#          }
#          #endif
#

import re, os, sys

class HeaderFile(object):
	def __init__(self, fh, filename=None, lenient=False):
		self.file = fh
		self.lenient = lenient
		self.lineno = 0
		self.has_copyright = False
		self.eof = False

		if filename:
			self.filename = filename
		else:
			self.filename = fh.name

	def getline(self):
		for line in self.file:
			self.lineno += 1
			if not line or line.isspace():
				continue
			else:
				line = line.rstrip('\r\n')

				# Recursively join continuation lines
				if line.endswith('\\'):
					line = line[0:-1] + self.getline()

				return line
		else:
			self.eof = True
			return ''

	#
	# Optionally take a line to start skipping/processing with
	#
	def skipcomments(self, curline=None):
		line = curline or self.getline()
		while line:
			# When lenient, allow C++ comments
			if self.lenient and re.search(r'^\s*//', line):
				line = self.getline()
				continue

			if not re.search(r'^\s*/\*', line):
				return line

			while not re.search(r'\*/', line):
				#
				# We explicitly exclude the form used in the
				# CDDL header rather than attempting to craft
				# a match for every possibly valid copyright
				# notice
				#
				if re.search(r'Copyright (?!\[yyyy\])', line):
					self.has_copyright = True
				line = self.getline()

			if re.search(r'Copyright (?!\[yyyy\])', line):
				self.has_copyright = True
			line = self.getline()

		return line


def err(stream, msg, hdr):
	if not hdr.eof:
		stream.write("%s: line %d: %s\n" %
			     (hdr.filename, hdr.lineno, msg))
	else:
		stream.write("%s: %s\n" % (hdr.filename, msg))


#
# Keyword strings (both expanded and literal) for the various SCMs
# Be certain to wrap each full expression in parens.
#
idents = [
	# SCCS
	r'((\%Z\%(\%M\%)\t\%I\%|\%W\%)\t\%E\% SMI)',
	r'(@\(#\)(\w[-\.\w]+\.h)\t\d+\.\d+(\.\d+\.\d+)?\t\d\d/\d\d/\d\d SMI)',
]

IDENT = re.compile(r'(%s)' % '|'.join(idents))


def hdrchk(fh, filename=None, lenient=False, output=sys.stderr):
	found_ident = False
	guard = None
	ret = 0

	hdr = HeaderFile(fh, filename=filename, lenient=lenient)

	#
	# Step 1:
	#
	# Headers must begin with a comment containing a copyright notice.  We
	# don't validate the contents of the copyright, only that it exists
	#
	line = hdr.skipcomments()

	if not hdr.has_copyright:
		err(output, "Missing copyright in opening comment", hdr)
		ret = 1
	
	#
	# Step 2:
	#
	# For application header files only, allow the ident string to appear
	# before the header guard.
	if lenient and line.startswith("#pragma ident") and IDENT.search(line):
		found_ident = 1
		line = hdr.skipcomments()

	#
	# Step 3: Header guards
	#
	match = re.search(r'^#ifndef\s([a-zA-Z0-9_]+)$', line)
	if not match:
		err(output, "Invalid or missing header guard", hdr)
		ret = 1
	else:
		guard = match.group(1)

		if not lenient:
			guardname = os.path.basename(hdr.filename)

			#
			# If we aren't being lenient, validate the name of the
			# guard
			#

			guardname = guardname.upper()
			guardname = guardname.replace('.', '_').replace('-','_')
			guardname = guardname.replace('+', "_PLUS")

			if not re.search(r'^_.*%s[_]?$' % guardname, guard):
				err(output, "Header guard does not match "
				    "suggested style (_FILEPATH_H_)", hdr)
				ret = 1

		line = hdr.getline()
		if not re.search(r'#define\s%s$' % guard, line):
			err(output, "Invalid header guard", hdr)
			ret = 1
			if not line:
				line = hdr.skipcomments()
		else:
			line = hdr.skipcomments()


	#
	# Step 4: ident string
	#
	# We allow both the keyword and extracted versions
	#
	if (not found_ident and line.startswith("#pragma ident") and
	    not IDENT.search(line)):
		err(output, "Invalid #pragma ident", hdr)
		ret = 1
	else:
		line = hdr.skipcomments(line)

	#
	# Main processing loop
	#
	in_cplusplus = False
	found_endguard = False
	found_cplusplus = False
	found_code = False

	while line:
		if not (line.startswith('#') or line.startswith('using')):
			found_code = True
			line = hdr.getline()
			continue

		match = re.search(r'^#include(.*)$', line)
		if match:
			#
			# For system files, make sure #includes are of the form:
			# '#include <file>'
			#
			if not lenient and not re.search(r'\s<.*>',
							 match.group(1)):
				err(output, "Bad include", hdr)
				ret = 1
		elif not in_cplusplus and re.search(r'^#ifdef\s__cplusplus$',
						    line):
			#
			# Start of C++ header guard.
			# Make sure it is of the form:
			#
			# #ifdef __cplusplus
			# extern "C" {
			# #endif
			#
			line = hdr.getline()
			if line == 'extern "C" {':
				line = hdr.getline()
				if line != '#endif':
					err(output, "Bad __cplusplus clause",
					    hdr)
					ret = 1
				else:
					in_cplusplus = True
					found_cplusplus = True
			else:
				continue
		elif in_cplusplus and re.search(r'^#ifdef\s__cplusplus$', line):
			#
			# End of C++ header guard.  Make sure it is of the form:
			#
			# #ifdef __cplusplus
			# }
			# #endif
			#
			line = hdr.getline()
			if line == '}':
				line = hdr.getline()
				if line != '#endif':
					err(output, "Bad __cplusplus clause",
					    hdr)
					ret = 1
				else:
					in_cplusplus = False
			else:
				continue
		elif re.search(r'^#endif\s/\* [!]?%s \*/$' % guard, line):
			#
			# Ending header guard
			#
			found_endguard = True

		line = hdr.skipcomments()

	#
	# Check for missing end clauses
	#
	if (not lenient) and (not found_cplusplus) and found_code:
		err(output, "Missing __cplusplus guard", hdr)
		ret = 1

	if in_cplusplus:
		err(output, "Missing closing #ifdef __cplusplus", hdr)
		ret = 1

	if not found_endguard:
		err(output, "Missing or invalid ending header guard", hdr)
		ret = 1

	return ret
