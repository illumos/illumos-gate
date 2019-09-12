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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2019 Joyent, Inc.
#

PROG =		svcs
OBJS =		svcs.o explain.o
MYOBJS =	notify_params.o
SRCS =		$(OBJS:%.o=%.c) $(MYOBJS:%.o=../common/%.c)
POFILES =	$(OBJS:.o=.po)

include ../../Makefile.cmd
include ../../Makefile.ctf

POFILE =	$(PROG)_all.po
LDLIBS +=	-lcontract -lscf -luutil -lumem -lnvpair -lzonecfg -lsasl -lproc
CPPFLAGS += -I ../common

lint := LINTFLAGS = -mux
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses

.KEEP_STATE:

all: $(PROG)

%.o: ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

$(PROG): $(OBJS) $(MYOBJS)
	$(LINK.c) -o $@ $(OBJS) $(MYOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS) $(MYOBJS)

lint: lint_SRCS

include ../../Makefile.targ
