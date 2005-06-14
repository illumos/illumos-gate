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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
if [ $# -gt 2 ]
then
	echo >&2 "Usage:  basename [ path [ suffix-pattern ] ]"
	exit 1
fi
#	If no first argument or first argument is null, make first argument
#	"."  Add beginning slash, then remove trailing slashes, then remove 
#	everything up through last slash, then remove suffix pattern if 
#	second argument is present.
#	If nothing is left, first argument must be of form //*, in which
# 	case the basename is /.
exec /usr/bin/expr \
	"/${1:-.}" : '\(.*[^/]\)/*$' : '.*/\(..*\)' : "\\(.*\\)$2\$"  \|  \
	"/${1:-.}" : '\(.*[^/]\)/*$' : '.*/\(..*\)'    \|  \
	"/${1:-.}" : '.*/\(..*\)' 
