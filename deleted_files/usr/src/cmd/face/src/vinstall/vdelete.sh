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
ferror()
{
	echo $1 ; exit 1
}
set -a

LOGINID=${1}

VMSYS=`sed -n -e '/^vmsys:/s/^.*:\([^:][^:]*\):[^:]*$/\1/p' /etc/passwd`
if [ ! -d "${VMSYS}" ]
then
	echo "The value for VMSYS is not set."
	exit 1
fi

UHOME=`grep -s "^$LOGINID:" /etc/passwd | cut -f6 -d:`
if [ -z "${UHOME}" ]
then
	echo "\n${LOGNID}'s home directory has not been retrieved correctly."
	exit 1
fi

$VMSYS/bin/chkperm -d -u ${LOGINID} 2>&1 || ferror "You must be super-user to remove $LOGINID as a FACE user."

if grep '^\. \$HOME/\.faceprofile$' ${UHOME}/.profile > /dev/null
then
	grep -v '^\. \$HOME/\.faceprofile$' ${UHOME}/.profile > /tmp/f.del.$$
	cp /tmp/f.del.$$ ${UHOME}/.profile
fi

exit 0
