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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
#
# Makefile for auditset

PROG = svc-auditset
SVCMETHOD = $(PROG)

MANIFEST = auditset.xml

include $(SRC)/cmd/Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

LIBBSM = $(SRC)/lib/libbsm/common

LDLIBS += -lbsm

OBJS = svc-auditset.o
SRCS = $(OBJS:%.o=%.c)

POFILE = $(PROG).po
MSGFILES = $(SRCS)

CPPFLAGS += -I$(LIBBSM)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(PROG): $(SRCS) $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

check:          $(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
