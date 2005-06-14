#!/bin/ksh
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
# Copyright (c) 1998 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
# gsscred_db clean up script
#
# This file is used to remove duplicate entries from
# the gsscred_db file. It is activated as a root cron
# job once a day. It only performs cleanup when
# the gsscred_db file has changed since last operation.

FILE_TO_CLEAN=/etc/gss/gsscred_db
CLEAN_TIME=/etc/gss/.gsscred_clean
TMP_FILE=/etc/gss/gsscred_clean$$

trap "rm -f $TMP_FILE; exit" 0 1 2 3 13 15


if [ -s $FILE_TO_CLEAN ] && [ $FILE_TO_CLEAN -nt $CLEAN_TIME ]
then

#
#	The file being sorted has the following format:
#		name	uid	comment
#
#	We are trying to remove duplicate entries for the name
#	which may have different uids. Entries lower in the file
#	are newer since addition performs an append. We use cat -n
#	in order to preserve the order of the duplicate entries and
#	only keep the latest. We then sort on the name, and line
#	number (line number in reverse). The line numbers are then
#	removed and duplicate entries are cut out.
#
	cat -n $FILE_TO_CLEAN | sort -k 2,2 -k 1,1nr 2> /dev/null \
		| cut -f2- | \
		awk ' (NR > 1 && $1 != key) || NR == 1 { 
				key = $1;
				print $0;
			}
		' > $TMP_FILE

	if [ $? -eq 0 ] && mv $TMP_FILE $FILE_TO_CLEAN; then
#
#		update time stamp for this sort
#
		touch -r $FILE_TO_CLEAN $CLEAN_TIME
	else
		rm -f $TMP_FILE
	fi
fi
