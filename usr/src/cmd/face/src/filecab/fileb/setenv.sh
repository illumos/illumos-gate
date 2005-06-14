#!/sbin/sh
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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/
#

# usage: setenv [-f file] [-r variable] [variable=value] ...
# sets variables in files

file=$HOME/pref/.environ
var=
while [ "$#" -gt 0 ]
do
	case "$1" in
	-f)
		file="$2"
		shift
		;;
	-f*)
		file="`expr \"$1\" : '-f\(.*\)'`"
		;;
	-r)
		var="$2"
		echo "`grep \"^$var=\" \"$file\" 2>/dev/null`" | sed -e "s/^$var=//"
		shift
		;;
	-r*)
		var="`expr \"$1\" : '-r\(.*\)'`"
		echo "`grep \"^$var=\" \"$file\" 2>/dev/null`" | sed -e "s/^$var=//"
		;;
	*)
		var="`expr \"$1\" : '\([^=]*\)=.*'`"
		(expr "$1" : '\(.*\)' | sed -e 's/\\[ncrbft0]/\\&/g' -e 's/$/\\n/' | tr -d '\012'; echo) | sed -e 's/\\n$//' > /tmp/setenv$$
		grep -v "^$var=" "$file" >> /tmp/setenv$$ 2>/dev/null
		cp /tmp/setenv$$ "$file"
		rm -f /tmp/setenv$$
		;;
	esac
	shift
done
