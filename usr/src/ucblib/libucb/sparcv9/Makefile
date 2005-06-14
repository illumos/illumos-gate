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
# Copyright (c) 1997-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# ucblib/libucb/sparcv9/Makefile

SYSOBJS=	 	\
	setjmp.o	\
	signal.o

MAPDIR=	../spec/sparcv9

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

DYNFLAGS += $(DYNFLAGS64)
BUILD.SO= $(CC) $(CFLAGS) -o $@ -G $(DYNFLAGS) $(PICS) -L $(ROOT)/usr/lib/$(MACH64) $(LDLIBS)
BUILD.s=	$(AS) $(ASFLAGS) -xarch=v9 -D__sparcv9 $< -o $@

# sparcv9-specific rule
objs/%.o pics/%.o: ../sparc/sys/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: sys/%.s
	$(BUILD.s)
	$(POST_PROCESS_O)

.KEEP_STATE:

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)
