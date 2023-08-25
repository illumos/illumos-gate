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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#
#
# Makefile for auditconfig

PROG = auditconfig

include $(SRC)/cmd/Makefile.cmd

LIBBSM = $(SRC)/lib/libbsm/common

LDLIBS += -lnsl -lbsm -lsecdb

OBJS = auditconfig.o
SRCS = $(OBJS:%.o=%.c)

POFILE = $(PROG).po
MSGFILES = $(SRCS)

CPPFLAGS += -I$(LIBBSM)
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

$(PROG): $(SRCS) $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
