#ident	"%Z%%M%	%I%	%E% SMI"	SVr4.0 1.4
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
#	From:	SVr4.0	terminfo:Doc.sed	1.4

#
#	This script is used to strip info from the terminfo
#	source files.
#
sed -n '
	/^# \{1,\}Manufacturer:[ 	]*\(.*\)/s//.M \1/p
	/^# \{1,\}Class:[ 	]*\(.*\)/s//.C \1/p
	/^# \{1,\}Author:[ 	]*\(.*\)/s//.A \1/p
	/^# \{1,\}Info:[ 	]*/,/^[^#][^	]/ {
		s/^# *Info:/.I/p
		/^#[	 ]\{1,\}/ {
			s/#//p
		}
		/^#$/ i\
.IE
	}
	/^\([^#	 ][^ 	]*\)|\([^|,]*\),[ 	]*$/ {
		s//Terminal:\
	"\2"\
		\1/
		s/|/, /g
		p
	}
' $*
