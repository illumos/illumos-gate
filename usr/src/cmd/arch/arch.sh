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


#       Copyright(c) 1988, Sun Microsystems, Inc.
#       All Rights Reserved

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

# On sparc systems, arch returns sun4 (historical artifact)
# while arch -k returns `uname -m`. On all other systems,
# arch == arch -k == uname -m.

USAGE="Usage: $0 [ -k | archname ]"
UNAME=/usr/bin/uname
ECHO=/usr/bin/echo

case $# in
0)	OP=major;;
1)	case $1 in
	-k)		OP=minor;;
	-?)		$ECHO $USAGE;
			exit 1;;
	*)		OP=compat;;
	esac;;
*)	$ECHO $USAGE;
	exit 1;;
esac

MINOR=`$UNAME -m`

case `$UNAME -p` in
sparc)  MAJOR=sun4;;
*)	MAJOR=$MINOR;;
esac

case $OP in
major)	$ECHO $MAJOR;;
minor)	$ECHO $MINOR;;
compat) [ $1 = $MAJOR ] ; exit ;;
esac

exit 0
