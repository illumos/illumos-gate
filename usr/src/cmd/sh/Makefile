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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

PROG =		sh
USR_PROG =	$(PROG)

OBJS=	args.o blok.o cmd.o defs.o error.o fault.o hash.o hashserv.o \
	io.o msg.o print.o stak.o string.o word.o xec.o \
	ctype.o echo.o expand.o func.o macro.o pwd.o setbrk.o test.o \
	bltin.o jobs.o ulimit.o main.o name.o service.o
SRCS=	$(OBJS:%.o=%.c)

include ../Makefile.cmd

#
# for message cataloge
#
POFILE= sh.po
POFILES= $(SRCS:%.c=%.po)
XGETFLAGS += -a -x sh.xcl

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -DACCT
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-extra
CERRWARN += -_gcc=-Wno-unused-variable

# unknown type for func
SMATCH=off

MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS += $(MAPFILES:%=-M%)
LDLIBS += -lgen

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(ROOTHASBINPROG)

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT)     $(POFILES) > $@

install: all $(ROOTHASBINPROG)
	$(RM) $(ROOTHASBIN)/jsh
	$(SYMLINK) sh $(ROOTHASBIN)/jsh
	$(RM) $(ROOTHASLIB)/rsh
	$(SYMLINK) ../bin/sh $(ROOTHASLIB)/rsh

clean:	
	$(RM) $(OBJS)

lint: lint_SRCS

include ../Makefile.targ
