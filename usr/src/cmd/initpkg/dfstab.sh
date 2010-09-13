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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1.2.1	*/
case "$MACH" in
  "u3b2"|"sparc"|"i386"|"ppc" )
	echo "
# Do not modify this file directly.
# Use the sharemgr(1m) command for all share management
# This file is reconstructed and only maintained for backward
# compatibility. Configuration lines could be lost.
#
#	share [-F fstype] [ -o options] [-d \"<text>\"] <pathname> [resource]
#	.e.g,
#	share  -F nfs  -o rw=engineering  -d \"home dirs\"  /export/home2
" >dfstab
	;;
  * )
	echo "Unknown architecture."
	exit 1
	;;
esac
