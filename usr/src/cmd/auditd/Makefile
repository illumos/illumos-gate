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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = auditd

MANIFEST = auditd.xml
SVCMETHOD = svc-auditd

include $(SRC)/cmd/Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

LIBBSM = $(SRC)/lib/libbsm/common
AUDITCONFIG = $(SRC)/cmd/auditconfig
AUDITD = $(SRC)/cmd/auditd

CPPFLAGS += -D_REENTRANT
CPPFLAGS += -I$(LIBBSM) -I$(AUDITCONFIG) -I$(AUDITD)

LDLIBS += -lbsm -lsecdb -lscf

OBJS = audit_scf_shared.o auditd.o doorway.o queue.o
SRCS = $(AUDITCONFIG)/audit_scf_shared.c auditd.c doorway.c queue.c

POFILE =	$(PROG).po
MSGFILES =	$(SRCS)

.KEEP_STATE:

all:		$(PROG)

install:	all $(ROOTUSRSBINPROG) \
		$(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(PROG):	$(SRCS) $(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

audit_scf%.o:
		$(COMPILE.c) $(AUDITCONFIG)/$(@:%.o=%.c)

lint:		lint_SRCS

$(POFILE): $(MSGFILES)
		$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
		$(RM) $(OBJS)

check:		$(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
