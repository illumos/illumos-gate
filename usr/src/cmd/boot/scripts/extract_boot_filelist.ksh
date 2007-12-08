#!/bin/ksh -p
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
# ident	"%Z%%M%	%I%	%E% SMI"

#
# set path, but inherit /tmp/bfubin if it is sane
#
if [ "`echo $PATH | cut -f 1 -d :`" = /tmp/bfubin ] && \
    [ -O /tmp/bfubin ] ; then
	export PATH=/tmp/bfubin:/usr/sbin:/usr/bin:/sbin
else
	export PATH=/usr/sbin:/usr/bin:/sbin
fi

usage() {
	echo "Usage: ${0##*/}: [-R \<root\>] <filelist> ..."
	exit 2
}

altroot=""
filelists=
while getopts R FLAG
do
        case $FLAG in
        R)	shift
		if [ "$1" != "/" ]; then
			altroot="$1"
		fi
		;;
        *)      usage
		;;
        esac
	shift
done

if [ $# -eq 0 ]; then
	usage
fi

filelists=$*

filtering=no
if [ "$altroot" == "" ]; then
	case `uname -m` in
	i86pc)
		filtering=no
		;;
	sun4u)
		filtering=yes
		exclude_pattern="sun4v"
		;;
	sun4v)
		filtering=yes
		exclude_pattern="sun4u"
		;;
	esac
fi

for list in $filelists
do
	if [ -f $altroot/$list ]; then
		if [ $filtering = yes ]; then
			cat $altroot/$list | grep -v $exclude_pattern
		else
			cat $altroot/$list
		fi
	fi
done

exit 0
