#! /usr/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

DASHES="============================================================"

MACH=	`uname -p`

if [ $MACH = "sparc" ]
then
	MACH64="sparcv9"
elif [ $MACH = "i386" ]
then
	MACH64="amd64"
else
	MACH64="unknown"
fi

LOG=lint.$MACH.log

#
# Keep the first run as a backup, so that subsequent runs can diff against it.
#
if [ -f $LOG ]
then
	if [ ! -f $LOG.bak ]
	then
		mv $LOG $LOG.bak
	else
		rm -f $LOG
	fi
fi

#
# Grab the lint.out from all of our directories.
#
for ii in $*
do
	if [ $ii = ".WAIT" ]
	then
		continue
	fi

	# Concatinate the lint.out to our log file.
#	echo $ii/$MACH >> $LOG
	echo $DASHES >> $LOG
	cat $ii/$MACH/lint.out >> $LOG
	echo "\n" >> $LOG

	# If there is a 64-bit directory, tack that on as well.
	if [ -f $ii/$MACH64/lint.out ]
	then
#		echo $ii/$MACH64 >> $LOG
		echo $DASHES >> $LOG
		cat $ii/$MACH64/lint.out >> $LOG
		echo "\n" >> $LOG
	fi
done

#
# If there is a backup log, diff the current one against it.
#
if [ -f $LOG.bak ]
then
	echo "Running diff on log file..."
	diff $LOG.bak $LOG
fi

exit 0
