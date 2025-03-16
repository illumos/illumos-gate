#!/bin/sh

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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This is a simple helper script for smtp-notify which looks for certain
# expansion macros, which we've committed and converts them to valid
# libfmd_msg macros which directly reference event payload members.
#
# This allows us to change event payload names or alter the libfmd_msg
# expansion macro syntax without breaking user-supplied message body
# templates.
#
# We use all-caps for the committed macro names to avoid colliding
# with an actual event payload member name.
#
# Usage: process_msg_template.sh <infile> <outfile> <code> <severity>
#

#
# Verify template exists, is readable and is an ascii text file
#
if [ ! -e $1 ] || [ ! -r $1 ]; then
	exit 1
fi

/usr/has/bin/file $1 | grep "ascii text" > /dev/null
if [ $? != 0 ]; then
	exit 1
fi

tmpfile1=$2;
tmpfile2=`/usr/bin/mktemp -p /var/tmp`

cat $1 | sed s/\%\<CODE\>/$3/g > $tmpfile1
cat $tmpfile1 | sed s/\%\<UUID\>/\%\<uuid\>/g > $tmpfile2
cat $tmpfile2 | sed s/\%\<CLASS\>/\%\<class\>/g > $tmpfile1
cat $tmpfile1 | sed s/\%\<SEVERITY\>/$4/g > $tmpfile2
cat $tmpfile2 | sed s/\%\<FMRI\>/svc\:\\/\%\<attr.svc.svc-name\>\:\%\<attr.svc.svc-instance\>/g > $tmpfile1
cat $tmpfile1 | sed s/\%\<FROM-STATE\>/\%\<attr.from-state\>/g > $tmpfile2
cat $tmpfile2 | sed s/\%\<TO-STATE\>/\%\<attr.to-state\>/g > $tmpfile1
cat $tmpfile1 | sed s/\%\<HOSTNAME\>/\%h/g > $tmpfile2
cat $tmpfile2 | sed s/\%\<URL\>/\%s/g > $tmpfile1
rm -f $tmpfile2
exit 0
