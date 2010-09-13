#!/usr/bin/sh
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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#! /usr/bin/sh

#     Portions Copyright(c) 1988, Sun Microsystems, Inc.
#     All Rights Reserved

#     Makefile for echo

#ident	"%Z%%M%	%I%	%E% SMI"        /* SVr4.0 1.2  */

PATH=/usr/bin
if test -z "$3" -o "$3" = "$1" -o "$3" = "$2"; then
	echo `gettext TEXT_DOMAIN "usage: diffmk name1 name2 name3 -- name3 must be different"`
	exit 1
fi
diff -e $1 $2 | (sed -n -e '
/[ac]$/{
	p
	a\
.mc |
: loop
	n
	/^\.$/b done1
	p
	b loop
: done1
	a\
.mc\
.
	b
}

/d$/{
	s/d/c/p
	a\
.mc *\
.mc\
.
	b
}'; echo '1,$p') | ed - $1| sed -e '
/^\.TS/,/.*\. *$/b pos
/^\.T&/,/.*\. *$/b pos
p
d
:pos
/^\.mc/d
' > $3
