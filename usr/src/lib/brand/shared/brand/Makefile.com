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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

COBJS =		brand_util.o
ASOBJS =	crt.o handler.o runexe.o
OFFSETS_SRC =	../common/offsets.in
OFFSETS_H =	assym.h
OBJECTS =	$(COBJS) $(ASOBJS)
CLOBBERFILES +=	$(OFFSETS_H)

include $(SRC)/lib/Makefile.lib

SRCDIR =	../common
CSRCS =		$(COBJS:%o=../common/%c)
ASSRCS =	$(ASOBJS:%o=$(ISASRCDIR)/%s)
SRCS =		$(CSRCS) $(ASSRCS)

#
# Ugh, this is a gross hack.  Our assembly routines uses lots of defines
# to simplify variable access.  All these defines work fine for amd64
# compiles because when compiling for amd64 we use the GNU assembler,
# gas.  For 32-bit code we use the Sun assembler, as.  Unfortunatly
# as does not handle certian constructs that gas does.  So rather than
# make our code less readable, we'll just use gas to compile our 32-bit
# code as well.
#
i386_AS		= $(amd64_AS)

CPPFLAGS +=	-D_REENTRANT -U_ASM -I. -I../sys
CFLAGS +=	$(CCVERBOSE)
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM -I. -I../sys

.KEEP_STATE:

#
# build the offset header before trying to compile any files.  (it's included
# by brand_misc.h, so it's needed for all objects, not just assembly ones.)
#
# Note we have to build assym.h via its dependency on pics/% so that the
# target dependent assignment of CTF_FLAGS will be there, otherwise make
# will see two different commands to build it (endless rebuilds).
#
all: pics .WAIT $$(PICS)

lint: lintcheck

$(OBJECTS:%=pics/%): $(OFFSETS_H)

$(OFFSETS_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) < $(OFFSETS_SRC) >$@

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
