#!/sbin/sh
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

# Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

# Portions of this source code were derived from Berkeley 4.3 BSD
# under license from the Regents of the University of California.

#ident	"%Z%%M%	%I%	%E% SMI"

dev=aps
oflags= newargs=

for i
do
	case $i in
	-Tcat)	dev=cat ;;
	-Taps)	dev=aps ;;
	-T*)	echo invalid option $i;  exit 1 ;;
	-c*)	cm=`echo $i|sed -e s/c/m/`
		newargs="$newargs $cm"
		oflags=$oflags$i  ;;
	-b|-k*|-p*|-g|-w)	oflags=$i$oflags ;;
	*)	newargs="$newargs $i"  ;;
	esac
done

case $dev in

cat)
	exec otroff $*
	;;

aps)
	if [ "-b" = "$oflags" ]
	then
		echo '-b no longer supported'
		exit 1
	fi
	if [ -n "$oflags" ]
	then
		echo "options -c, -k, -b, -w, -g and -p are no longer supported"
	fi
	exec troff $newargs
	;;

esac
