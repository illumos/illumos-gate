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
# sccsid = @(#) file_attr 1.1 1/2/91 14:40:37

# file_attr - takes as argument a pathname and
#              prints file attributes in the following format:
#
#              pathname mode owner group type
#

if [ $# -ne 1 ]
then
	echo
	exit
fi

lsline=`$LS -ld $1`

name=`echo $lsline | $AWK '{print $9}'`
mode=`echo $lsline | $AWK '{print $1}'`
owner=`echo $lsline | $AWK '{print $3}'`
group=`echo $lsline | $AWK '{print $4}'`

type=`echo $mode | $AWK '{ if (substr($0, 1, 1)=="d") { \
	                      print "directory"
                           } else if (substr($0, 1, 1)=="l") { \
	                      print "symlink"
                           } else {
	                      print "file"
	                   }
                         }'`

echo "$name `$STR_TO_MODE $mode` $owner $group $type"
