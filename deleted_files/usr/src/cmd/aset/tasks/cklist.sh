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

# Checklist comparison on "static" system objects attributes
#
# This script compares the master copy of checklist, which
# lists the expected attributes of specified "static" system
# objects, with a current snapshot of these same objects and
# reports and differences found.
#
# If the master copy is not found, it will be reported, and
# the current snapshot will become the master copy -- no
# comparison can be done, of course.
#
# Since the creation of the checklist involves running the checksum
# program, sum(1), which requires read access on the system objects,
# superuser privilege is required for successful completion of this
# task.

# Create master copy, if not created already; else
# create temporary file and compare with master.
tmpcklist=/tmp/cklist.${ASETSECLEVEL}.$$
mastercklist=${ASETDIR}/masters/cklist.${ASETSECLEVEL}

echo
echo "*** Begin Checklist Task ***"

if [ "$UID" -ne 0 ]
then
	echo
	echo "You are not authorized for the creation and/or comparison"
	echo "of system checklist. Task skipped."
	exit 3
fi

if [ ! -s $mastercklist ]
then
	echo
	echo "No checklist master - comparison not performed."
	echo "... Checklist master is being created now. Wait ..."
	/bin/sh ${ASETDIR}/tasks/create_cklist $mastercklist
	echo "... Checklist master created."
else
	echo
	echo "... Checklist snapshot is being created. Wait ..."
	/bin/sh ${ASETDIR}/tasks/create_cklist $tmpcklist
	echo "... Checklist snapshot created."
	echo
	/bin/cmp -s $mastercklist $tmpcklist
	if [ $? -eq 0 ]
	then
		echo "No differences in the checklist."
	else
		echo "Here are the differences in the checklist."
		echo "< lines are from the master;"
		echo "> lines are from the current snapshot"
		echo
		$DIFF $mastercklist $tmpcklist
	fi
	$RM -f $tmpcklist
fi

echo
echo "*** End Checklist Task ***"
