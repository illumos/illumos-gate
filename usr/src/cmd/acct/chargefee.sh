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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
#	"chargefee login-name number"
#	"emits tacct.h/ascii record to charge name $number"
cd /var/adm
PATH=/usr/lib/acct:/usr/bin:/usr/sbin
if test $# -lt 2; then
	echo "usage: chargefee name number" >&2
	exit 1
fi
_entry="`getent passwd $1`"
if test -z "${_entry}"; then
	echo "can't find login name $1" >&2
	exit 2
fi
case "$2"  in
-[0-9]*|[0-9]*);;
*)
	echo "charge invalid: $2" >&2
	exit 3
esac

if test ! -r fee; then
	nulladm fee
fi
_userid=`echo "${_entry}" | cut -d: -f3`  # get the UID
echo  "${_userid} $1 0 0 0 0 0 0 0 0 0 0 $2"  >>fee
