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
# Copyright 2015 Joyent, Inc.
#

PROG =		lxinit

PROG_OBJS =	lxinit.o pipe_stream.o run_command.o
LIST_OBJS =	list.o

OBJS =		$(PROG_OBJS) \
		$(LIST_OBJS)
SRCS =		$(PROG_OBJS:%.o=%.c) \
		$(LIST_OBJS:%.o=$(SRC)/common/list/%.c)

all:		$(PROG)

include ../Makefile.lx
include $(SRC)/cmd/Makefile.cmd

# override the install directory
ROOTBIN =	$(ROOTBRANDDIR)
CLOBBERFILES =	$(OBJS) $(ROOTPROG)

UTSBASE =	$(SRC)/uts

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(UTSBASE)/common/brand/lx
LDLIBS +=	-lzonecfg -lipadm -lsocket -linetutil -lnsl -lcmdutils

.KEEP_STATE:

install: all $(ROOTPROG)

clean:
	$(RM) $(PROG) $(OBJS)

lint: lint_PROG lint_SRCS

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/list/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include $(SRC)/cmd/Makefile.targ
