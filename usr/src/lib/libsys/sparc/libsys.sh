#! /bin/sh
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1995 by Sun Microsystems, Inc.
# All rights reserved.
#
# Stub library for programmer's interface to libsys.  Used to satisfy ld(1)
# processing, and serves as a precedence place-holder at execution-time.

awk '
BEGIN {
	printf("\t.file\t\"libsyss.s\"\n\t.section\t\".text\"\n");
}
/.*/ {
	printf("\t.global\t%s\n%s:\n\tt 5\n\t.type\t%s,#function\n\t.size\t%s,.-%s\n", $0, $0, $0, $0, $0);
}
' libsyss.list	>	libsyss.s
