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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/
grep -n "^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]" $* > /tmp/$$
ex - /tmp/$$ <<\!
v/(.*)$/d
g/STATIC/d
g/\<static\>/d
g/\<long\>/d
g/\<short\>/d
g/\<line\>/d
g/\<switch\>/d
g/\<unsigned\>/d
g/\<return\>/d
g/\<break\>/d
g/\<bool\>/d
g/\<boolean\>/d
g/\<case\>/d
g/\<struct\>/d
g/\<int\>/d
g/\<char\>/d
g/\<extern\>/d
g/:$/d
g/\\/d
1,$s/\(.*:\)\(.*\)/\2|\1/
1,$s/|/                                                 /
1,$s/^\(................................................\) */\1/
w
q
!
sort /tmp/$$
rm /tmp/$$
