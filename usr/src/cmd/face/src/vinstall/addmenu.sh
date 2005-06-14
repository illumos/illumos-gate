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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

trap 'rm -f $VMSYS/OBJECTS/.Lserve ; exit 0' 1 2 15

error ()
{
	echo "$1"; rm -f ${VMSYS}/OBJECTS/.Lserve; exit 1
}
# set VMSYS so that Menu.programs file can be updated if installed.
VMSYS=`sed -n -e '/^vmsys:/s/^.*:\([^:][^:]*\):[^:]*$/\1/p' /etc/passwd`
export VMSYS

if [ ! -d "${VMSYS}" ]
then
	error "Can't find home directory for vmsys"
fi

if [ ! -f ${VMSYS}/OBJECTS/.Lserve ]
then
	>${VMSYS}/OBJECTS/.Lserve
else
	error "Can't update ${VMSYS}/lib/services file because it is LOCKED!!!"
fi

echo "\`echo 'name=\"${1}\"';echo 'action=OPEN ${2}'\`" >> $VMSYS/lib/services || error "Can't access $VMSYS/lib/services"
sort $VMSYS/lib/services > /tmp/f.sv.$$
cp /tmp/f.sv.$$ $VMSYS/lib/services || error "Can't access $VMSYS/lib/services"
rm -f /tmp/f.sv.$$

rm -f ${VMSYS}/OBJECTS/.Lserve
exit 0
