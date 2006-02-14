#!/bin/sh
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
#
# Copyright 1990, 1991 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

# create_cklist - creates a snapshot of the contents of the directories
#		  designated by env variable CKLISTPATH.
#		  Return error if the checklist file is already created.

cklistfile=$1
tmpckfile=${ASETDIR}/tmp/tmpcklist.$$

if [ -s $cklistfile ]
then
	echo
	echo create_cklist: the file already exists - $cklistfile
	exit 3
fi

if [ "${CKLISTPATH}" = "" ]
then
	echo
	echo Env variable CKLISTPATH undefined.
	echo Check ${ASETDIR}/asetenv file.
	echo $QUIT
	exit 3
fi
gooddir=false
OLDIFS=$IFS
IFS=":"
for i in ${CKLISTPATH}
do
	if [ ! -d $i ]
	then
		echo
		echo "create_cklist: Directory $i does not exist."
		echo "Check env variable \c"
		echo "$CKLISTPATH\c"
		echo " in ${ASETDIR}/asetenv file."
		continue
	else
		gooddir=true
		/usr/aset/util/nls -ldaC $i/* | $ADDCKSUM >> $tmpckfile
	fi
done

$CAT $tmpckfile | $SED "/cklist.${ASETSECLEVEL}/d" > $cklistfile
$RM $tmpckfile

IFS=$OLDIFS
if [ "$gooddir" = "false" ]
then
	# none of the directories were good
	echo
	echo Bad env variable $CKLISTPATH
	echo Check ${ASETDIR}/asetenv file.
	echo $QUIT
	exit 3
fi
