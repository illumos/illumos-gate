#!/bin/ksh
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Create dummy functions for each of the functions in the module API.  We can
# then link a module against an object file created from the output of this
# script to determine whether or not that module restricts itself to the API.
# If the module uses functions outside of the module API, then it cannot be
# used as a kmdb module.
#
nawk '
	/^[ 	]*global:[ 	]*$/ {
		printing = 1;
		next;
	}

	/^[	]*local:[ 	]*$/ {
		printing = 0;
		next;
	}

	# Skip blank lines and comments
	/^$/ { next; }
	/^[ 	]*#/ { next;}

	# Print globals only
	printing == 0 { next; }

	# Symbols beginning with "kmdb_" are not in the module API - they are
	# private to kmdb.
	$1 ~ /^kmdb_/ { next; }

	# Symbols which have the token "variable" are seen as an int
	$3 ~ /variable/ {
		if (seen[$1]) {
			next;
		}

		seen[$1] = 1;

		printf("int %s = 0;\n", substr($1, 1, length($1) - 1));
		next;
	}

	$1 !~ /;$/ { next; }

	# Print everything else that we have not already seen as a function
	# definition so we can create our filter.
	{
		if (seen[$1]) {
			next;
		}

		seen[$1] = 1;

		printf("void %s(void) {}\n", substr($1, 1, length($1) - 1));
	}
'

#
# kmdb modules cannot have their own _init, _fini, or _info routines.  By
# creating dummies for them here, a link against an object file created from
# the output of this script will fail if the module defines one of them.
#
echo "void _init(void) {}"
echo "void _info(void) {}"
echo "void _fini(void) {}"
#
# The SunStudio compiler may generate calls to _memcpy and so we
# need to make sure that the correct symbol exists for these calls.
#
echo "void _memcpy(void) {}"
