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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= librsm.a
VERS= .2

TEXT_DOMAIN=	SUNW_OST_OSLIB

OBJECTS = rsmlib.o rsmgen.o rsmloopback.o

# include library definitions, do not change order of include and DYNLIB
include ../../Makefile.lib

SRCDIR =	../common

LIBS = $(DYNLIB)

# The DEBUG flag is enabled for debug builds
DEBUG =
$(NOT_RELEASE_BUILD)DEBUG = -DDEBUG

# The COPTFLAG is used for optimization purposes.
# It is disabled for debug builds
$(NOT_RELEASE_BUILD)COPTFLAG =
$(NOT_RELEASE_BUILD)COPTFLAG64 =

CPPFLAGS = -I../inc -I../../common/inc $(CPPFLAGS.master) -D_REENTRANT $(DEBUG)

CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-parentheses

# not linted
SMATCH=off

LDLIBS += -lc

.KEEP_STATE:

all:  $(LIBS)

lint: lintcheck

# include library targets
include ../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
