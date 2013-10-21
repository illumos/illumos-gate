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
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


case "$MACH" in
  "i386" )
	echo "# /dev/console and /dev/contty autopush setup
#
#       major minor   lastminor       modules

	wc	-1	0	ldterm ttcompat
	asy	-1	0	ldterm ttcompat
	xencons	0	0	ldterm ttcompat
	ptsl	0	47	ldterm ttcompat
	usbsacm -1	0	ldterm ttcompat
	usbser_edge	-1	0	ldterm ttcompat
	usbsprl	-1	0	ldterm ttcompat
	usbsksp	-1	0	ldterm ttcompat
	usbftdi	-1	0	ldterm ttcompat
	ipsecesp -1	0	ipsecesp
	ipsecah	-1	0	ipsecah
" > iu.ap
	;;
  "sparc" )
	echo "# /dev/console and /dev/contty autopush setup
#
#      major   minor lastminor	modules

	wc	-1	0	ldterm ttcompat
	qcn	0	255	ldterm ttcompat
	sgcn	0	0	ldterm ttcompat
	zs	0	63	ldterm ttcompat
	zs	131072	131135	ldterm ttcompat
	ptsl	0	47	ldterm ttcompat
	cvc	0	0	ldterm ttcompat
	mcpzsa	0	127	ldterm ttcompat
	mcpzsa	256	383	ldterm ttcompat
	se	0	255	ldterm ttcompat
	se	131072	131327	ldterm ttcompat
	se	16384	0	ldterm ttcompat
	se	16392	0	ldterm ttcompat
	su	0	255	ldterm ttcompat
	su	16385	0	ldterm ttcompat
	su	131072	131073	ldterm ttcompat
	usbser_edge -1	0	ldterm ttcompat
	usbsacm -1	0	ldterm ttcompat
	usbsprl -1	0	ldterm ttcompat
	usbsksp -1	0	ldterm ttcompat
	usbftdi	-1	0	ldterm ttcompat
	ttymux	-1	0	ldterm ttcompat
	ipsecesp -1	0	ipsecesp
	ipsecah	-1	0	ipsecah
	oplmsu	0	0	ldterm ttcompat
" >iu.ap
	;;
  * )
	echo "Unknown architecture."
	exit 1
	;;
esac
