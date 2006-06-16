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


#ident	"%Z%%M%	%I%	%E% SMI"

#
#	Determine the fs identifier of a file system.
#
#!	chmod +x ${file}
USAGE=`gettext TEXT_DOMAIN "Usage: fstyp [-v] special"`
NARGS=`echo $#`

if [ $NARGS -eq 0 ]
then
	echo "$USAGE" >&2
	exit 2
fi
while getopts v? c
do
	case $c in
	 v) VFLAG="-"$c;;
	\?) echo "$USAGE" >&2
	    exit 2;;
	esac
done
shift `expr $OPTIND - 1`

if [ "$VFLAG" ]
then
	if [ $NARGS -gt 2 ]
	then
		echo "$USAGE" >&2
		exit 2
	fi
else
	if [ $NARGS -gt 1 ]
	then
		echo "$USAGE" >&2
		exit 2
	fi
fi
	


SPEC=$1
if [ "$SPEC" = "" ]
then
	echo "$USAGE" >&2
	exit 2
fi
if [ ! -r $SPEC ]
then
	gettext TEXT_DOMAIN "fstyp: cannot stat or open <$SPEC>\n"
	exit 1
fi

if [ \( ! -b $SPEC \) -a \( ! -c $SPEC \) ]
then
	gettext TEXT_DOMAIN "fstyp: <$SPEC> not block or character special device\n"
	exit 1
fi

#
#	Execute all heuristic functions /etc/fs/*/fstype 
#	or /usr/lib/fs/*/fstyp and
#	return the fs identifier of the specified file system.
#

CNT=0 

if [ -d /usr/lib/fs ]
then
	DIR=/usr/lib/fs
else
	DIR=/etc
fi

for f in $DIR/*/fstyp
do
	$f $VFLAG $SPEC >&1
	if [ $? -eq 0 ]
	then
		CNT=`expr ${CNT} + 1`
	fi
done

if [ ${CNT} -gt 1 ]
then
	echo `gettext TEXT_DOMAIN "Unknown_fstyp (multiple matches)"` >&2
	exit 2
elif	[ ${CNT} -eq 0 ]
then
	echo `gettext TEXT_DOMAIN "Unknown_fstyp (no matches)"` >&2
	exit 1
else
	exit 0
fi
