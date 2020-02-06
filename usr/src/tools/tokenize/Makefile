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

SHFILES=	tokenize
BINARIES=	forth_preload.so.1 forth tokenize.exe

LIBRARY = forth_preload.a
VERS = .1
OBJECTS = forth_preload.o asmsubr.o

CLOBBERFILES = $(SHFILES)

include $(SRC)/lib/Makefile.lib
include ../Makefile.tools

LIBS = $(DYNLIB)

MAPFILES =

DYNFLAGS += $(ZINTERPOSE)
LDLIBS = -lc
NATIVE_LIBS += libc.so

ASFLAGS += -P -D_ASM

.KEEP_STATE:

all:	$(SHFILES) $(BINARIES)

install: all .WAIT $(ROOTONBLDMACHSHFILES) $(ROOTONBLDMACHBINARIES)

include $(SRC)/lib/Makefile.targ

pics/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: %.s
	$(AS) $(ASFLAGS) -o $@ $<
	$(POST_PROCESS_O)
