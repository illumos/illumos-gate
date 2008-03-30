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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
	echo "This utility is a component of the bootadm(1M) implementation"
	echo "and it is not recommended for stand-alone use."
	echo "Please use bootadm(1M) instead."
	echo ""
	echo "Usage: ${0##*/}: [-R \<root\>] [-p \<platform\>] \<filelist\> ..."
	echo "where \<platform\> is one of i86pc, sun4u or sun4v"
	exit 2
}

# default platform is what we're running on
PLATFORM=`uname -m`

altroot=""
filelists=
platform_provided=no

OPTIND=1
while getopts R:p: FLAG
do
        case $FLAG in
        R)	if [ "$OPTARG" != "/" ]; then
			altroot="$OPTARG"
		fi
		;;
	p)	platform_provided=yes
		PLATFORM="$OPTARG"
		;;
        *)      usage
		;;
        esac
done

shift `expr $OPTIND - 1`
if [ $# -eq 0 ]; then
	usage
fi

filelists=$*

#
# If the target platform is provided, as is the case for diskless,
# or we're building an archive for this machine, we can build
# a smaller archive by not including unnecessary components.
#
filtering=no
if [ "$altroot" == "" ] || [ $platform_provided = yes ]; then
	case $PLATFORM in
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
	*)
		usage
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
