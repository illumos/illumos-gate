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
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG =		sh
ROOTFS_PROG =	$(PROG)

OBJS=	args.o blok.o cmd.o defs.o error.o fault.o hash.o hashserv.o \
	io.o msg.o print.o stak.o string.o word.o xec.o \
	ctype.o echo.o expand.o func.o macro.o pwd.o setbrk.o test.o \
	bltin.o jobs.o ulimit.o sh_policy.o main.o name.o service.o
SRCS=	$(OBJS:%.o=%.c)

include ../Makefile.cmd

# This flag is being added only for SCO (x86) compatibility  
CFLAGS += $(iBCS2FLAG)

#
# for message cataloge
#
POFILE= sh.po
POFILES= $(SRCS:%.c=%.po)
XGETFLAGS += -a -x sh.xcl

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -DACCT
MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS += $(MAPFILES:%=-M%)
LDLIBS += -lgen -lsecdb
GROUP =	root

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(ROOTFS_PROG)

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT)     $(POFILES) > $@

install: all $(ROOTSBINPROG)
	$(RM) $(ROOTSBIN)/jsh
	$(SYMLINK) sh $(ROOTSBIN)/jsh
	$(RM) $(ROOTSBIN)/pfsh
	$(SYMLINK) sh $(ROOTSBIN)/pfsh
	$(RM) $(ROOTBIN)/sh
	$(SYMLINK) ../../sbin/sh $(ROOTBIN)/sh
	$(RM) $(ROOTBIN)/jsh
	$(SYMLINK) ../../sbin/sh $(ROOTBIN)/jsh
	$(RM) $(ROOTBIN)/pfsh
	$(SYMLINK) ../../sbin/sh $(ROOTBIN)/pfsh
	$(RM) $(ROOTLIB)/rsh
	$(SYMLINK) ../../sbin/sh $(ROOTLIB)/rsh

clean:	
	$(RM) $(OBJS)

lint: lint_SRCS

include ../Makefile.targ
