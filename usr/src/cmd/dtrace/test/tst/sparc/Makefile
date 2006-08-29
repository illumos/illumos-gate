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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../Makefile.com

ASFLAGS += -D_ASM -K PIC -P

clobber := DSRC += ustack/tst.helper_helper.d ustack/tst.annotated_helper.d

all:	ustack/tst.helper.exe ustack/tst.annotated.exe

ustack/tst.helper.exe: ustack/tst.helper.o ustack/tst.helper_helper.o
	$(CC) -o ustack/tst.helper.exe \
		 ustack/tst.helper.o ustack/tst.helper_helper.o
	$(STRIP) ustack/tst.helper.exe

ustack/tst.helper_helper.o: ustack/tst.helper_helper.d
	/usr/sbin/dtrace -G -o ustack/tst.helper_helper.o \
		-s ustack/tst.helper_helper.d

ustack/tst.annotated.exe: ustack/tst.annotated.o ustack/tst.annotated_helper.o
	$(CC) -o ustack/tst.annotated.exe \
		 ustack/tst.annotated.o ustack/tst.annotated_helper.o

ustack/tst.annotated_helper.o: ustack/tst.annotated_helper.d
	/usr/sbin/dtrace -G -o ustack/tst.annotated_helper.o \
		-s ustack/tst.annotated_helper.d
