#! /bin/sh
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
# sccsid = @(#) addcksum 1.2 1/2/91 14:49:04
#

# This script takes a checklist file from standard input and adds a checksum
# to each *file* entry. If the entry is not a file (e.g. directory
# or symbolic link), nothing is added. The result is written to standard
# output.

while read perm links user group size month date time year filename junk
do
	firstchar=`echo $perm | $SED "s/^\(.\).*/\1/"`
	if test "$firstchar" = "-"
	then
		cksum=`$SUM $filename | $SED "s/^\([0-9]* [0-9]*\) .*/\1/"`
		echo "$perm $links $user $group $size $month $date $time\c"
		echo " $year $filename $junk $cksum"
	else
		echo "$perm $links $user $group $size $month $date $time\c"
		echo " $year $filename $junk"
	fi
done
