#!/sbin/sh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# zoneunshare  -- unshare zone resources

# Processes the specified sharetab file and unshare
# all entries shared by the specfied zone

USAGE="zoneunshare -z zonename [- | file]"
set -- `getopt z: $*`
if [ $? != 0 ]		# invalid options
	then
	echo $USAGE >&2
	exit 1
fi
for i in $*		# pick up the options
do
	case $i in
	-z)  zonename=$2; shift 2;;
	--)  shift; break;;
	esac
done

zoneattr=`/usr/sbin/zoneadm -z $zonename list -p 2> /dev/null`
if [ $? -ne 0 ]		# invalid zone
	then
	echo $USAGE >&2
	exit 1
fi

prefix=`echo $zoneattr | cut -d ":" -f4`
rootpath=$prefix/root

if [ $# -gt 1 ]		# accept only one argument
then
	echo $USAGE >&2
	exit 1
elif [ $# = 1 ]
then
	case $1 in
	-)	infile=;;	# use stdin
	*)	infile=$1;;	# use a given source file
	esac
else
	infile=/etc/dfs/sharetab	# default
fi

# Run unshare for each resource in its own shell

while read line				# get complete lines
do
	echo $line
done < $infile |
	`egrep "^$rootpath"|nawk '{ print "/usr/sbin/unshare " $1 ";" }'|/sbin/sh`
