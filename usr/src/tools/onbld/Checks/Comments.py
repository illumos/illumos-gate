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
# Check delta comments:
# 	- Have the correct form.
# 	- Have a synopsis matching that of the CR or ARC case.
# 	- Appear only once.
#

import re, sys
from onbld.Checks.DbLookups import BugDB, ARC

arcre = re.compile(r'^([A-Z][A-Z]*ARC[/ \t][12]\d{3}/\d{3}) (.*)$')
bugre = re.compile(r'^(\d{7}) (.*)$')
def isARC(comment):
	return arcre.match(comment)

def isBug(comment):
	return bugre.match(comment)

#
# Translate any acceptable case number format into "<ARC> <YEAR>/<NUM>"
# format.
#
def normalize_arc(caseid):
	return re.sub(r'^([A-Z][A-Z]*ARC)[/ \t]', '\\1 ', caseid)

def comchk(comments, check_db=True, output=sys.stderr):
	bugnospcre = re.compile(r'^(\d{7})([^ ].*)')
	ignorere = re.compile(r'^(Contributed by .*|backout \d{7})')

	errors = { 'bugnospc': [],
		   'mutant': [],
		   'dup': [],
		   'nomatch': [],
		   'nonexistent': [] }
	bugs = {}
	arcs = {}
	ret = blanks = 0

	for com in comments:
		# Ignore valid comments we can't check
		if ignorere.search(com):
			continue

		if not com or com.isspace():
			blanks += 1
			continue

		match = bugre.search(com)
		if match:
			if match.group(1) not in bugs:
				bugs[match.group(1)] = []
			bugs[match.group(1)].append(match.group(2))
			continue

		#
		# Bugs missing a space after the ID are still bugs
		# for the purposes of the duplicate ID and synopsis
		# checks.
		#
		match = bugnospcre.search(com)
		if match:
			if match.group(1) not in bugs:
				bugs[match.group(1)] = []
			bugs[match.group(1)].append(match.group(2))
			errors['bugnospc'].append(com)
			continue

		# ARC case
		match = arcre.search(com)
		if match:
			case = normalize_arc(match.group(1))
			if case not in arcs: arcs[case] = []
			arcs[case].append(match.group(2))
			continue

		# Anything else is bogus
		errors['mutant'].append(com)

	if len(bugs) > 0 and check_db:
		bugdb = BugDB()
		results = bugdb.lookup(bugs.keys())

	for crid, insts in bugs.iteritems():
		if len(insts) > 1:
			errors['dup'].append(crid)

		if not check_db:
			continue

		if crid not in results:
			errors['nonexistent'].append(crid)
			continue

		for entered in insts:
			synopsis = results[crid]["synopsis"]
			if not re.search(re.escape(synopsis) +
					 r'( \([^)]+\))?$', entered):
				errors['nomatch'].append([crid, synopsis,
							  entered])

	for case, insts in arcs.iteritems():
		if len(insts) > 1:
			errors['dup'].append(case)

		if not check_db:
			continue

		com, id = case.split(' ')
		arc = ARC(com, id)

		if not arc.valid():
			errors['nonexistent'].append(case)
			continue

		#
		# The opensolaris.org ARC interfaces only give us the
		# first 40 characters of the case name, so we must limit
		# our checking similarly.
		#
		# We first try a direct match between the actual case name
		# and the entered comment.  If that fails we remove a possible
		# trailing (fix nit)-type comment, and re-try.
		#
		for entered in insts:
			if entered[0:40] == arc.name():
				continue
			else:
				dbcom = re.sub(r' \([^)]+\)$', '', entered)
				if dbcom[0:40] != arc.name():
					errors['nomatch'].append([case,
								  arc.name(),
								  entered])

	if blanks:
		output.write("WARNING: Blank line(s) in comments\n")
		ret = 1

	if errors['dup']:
		ret = 1
		output.write("These IDs appear more than once in your "
			     "comments:\n")
		for err in errors['dup']:
			output.write("  %s\n" % err)

	if errors['bugnospc']:
		ret = 1
		output.write("These bugs are missing a single space following "
			     "the ID:\n")
		for com in errors['bugnospc']:
			output.write("  %s\n" % com)

	if errors['mutant']:
		ret = 1
		output.write("These comments are neither bug nor ARC case:\n")
		for com in errors['mutant']:
			output.write("  %s\n" % com)

	if errors['nonexistent']:
		ret = 1
		output.write("These bugs/ARC cases were not found in the "
			     "databases:\n")
		for id in errors['nonexistent']:
			output.write("  %s\n" % id)

	if errors['nomatch']:
		ret = 1
		output.write("These bugs/ARC case synopsis/names don't match "
			     "the database entries:\n")
		for err in errors['nomatch']:
			output.write("Synopsis/name of %s is wrong:\n" % err[0])
			output.write("  should be: '%s'\n" % err[1])
			output.write("         is: '%s'\n" % err[2])

	return ret
