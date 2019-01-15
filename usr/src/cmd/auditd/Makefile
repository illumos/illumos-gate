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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

PROG = auditd

MANIFEST = auditd.xml
SVCMETHOD = svc-auditd

include $(SRC)/cmd/Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

LIBBSM = $(SRC)/lib/libbsm/common
AUDITD = $(SRC)/cmd/auditd

CPPFLAGS += -D_REENTRANT
CPPFLAGS += -I$(LIBBSM) -I$(AUDITD)

CERRWARN += -_gcc=-Wno-parentheses

SMOFF += macros

LDLIBS += -lbsm -lsecdb

OBJS = auditd.o doorway.o queue.o
SRCS = $(OBJS:%.o=%.c)

POFILE =	$(PROG).po
MSGFILES =	$(SRCS)

.KEEP_STATE:

all:		$(PROG)

install:	all $(ROOTUSRSBINPROG) \
		$(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(PROG):	$(SRCS) $(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

lint:		lint_SRCS

$(POFILE): $(MSGFILES)
		$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
		$(RM) $(OBJS)

check:		$(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
