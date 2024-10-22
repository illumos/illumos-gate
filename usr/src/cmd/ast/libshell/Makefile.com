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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

SHELL= /usr/bin/ksh93

LIBRARY= libshell.a
VERS= .1

include ../Makefile.defs

OBJECTS += $(LIBOBJS)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ast

MAPFILES= ../mapfile-vers

# Specify the MACH we currently use to build and test ksh
LIBSHELLMACH= $(TARGETMACH)
LIBSHELLBASE=..

LIBS= $(DYNLIB)
LDLIBS += -lcmd -ldll -last -lsocket -lm -lc

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
CPPFLAGS= \
	$(DTEXTDOM) $(DTS_ERRNO) \
	$(LIBSHELLCPPFLAGS) \
	-Iast -I.

CFLAGS += $(ASTCFLAGS)
CFLAGS64 += $(ASTCFLAGS64)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-char-subscripts

pics/bltins/print.o := CERRWARN += -_gcc14=-Wno-dangling-pointer

# smatch gets out of memory on common/sh/macro.c
SMATCH= off

.KEEP_STATE:

all: install_h mkpicdirs .WAIT $(LIBS)

mkpicdirs:
	@mkdir -p $(LOBJDIRS:%=pics/%)

include $(SRC)/lib/Makefile.targ

pics/%.o: $(ASTSRC)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

######################################################################
# Header file generation

$(HEADERSRC:%=ast/%): $(HEADERSRC:%=$(ASTSRC)/include/%)
	$(MKDIR) -p $(@D)
	$(CP) $(ASTSRC)/include/$(@F) $@

CLOBBERFILES += ast/*

install_h: $(HEADERSRC:%=ast/%)

_feature: FRC
	$(MAKE) -f Makefile.iffe generate

include ../../Makefile.astmsg

FRC:
