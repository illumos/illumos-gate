#! /bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#ident	"%Z%%M%	%I%	%E% SMI"

# Stub library for programmer's interface to libsys.  Used to satisfy ld(1)
# processing, and serves as a precedence place-holder at execution-time.

awk '
/.*/ {
	if ($2 == "1") {
		printf("#pragma weak %s = _%s\n", $3, $3);
		flag = "_";
	} else
		flag = "";
	if ($1 == "f") {
		printf("void *\n%s%s()\n{\n", flag, $3);
		printf("\t/*NOTREACHED*/\n\treturn (0);\n}\n\n");
	} else {
		if ($4 == "1")
			printf("%s %s%s %s %s\n\n", $5, flag, $3, $6, $7);
		else if ($4 == "2")
			printf("%s %s %s%s %s %s\n\n", $5, $6, flag, $3, $7, $8);
		else if ($4 == "3")
			printf("%s %s %s%s%s %s %s    %s\n\n", $5, $6, flag, $3, $7, $8, $9, $10);
	}
}
' libsys.list	>	libsys.c
