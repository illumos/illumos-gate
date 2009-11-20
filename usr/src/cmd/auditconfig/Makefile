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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# Makefile for auditconfig

PROG = auditconfig

include $(SRC)/cmd/Makefile.cmd

POFILE = auditconfig.po
MSGFILES = $(SRCS)

LIBBSM = $(SRC)/lib/libbsm/common
AUDITCONFIG = $(SRC)/cmd/auditconfig
AUDITD = $(SRC)/cmd/auditd

LDLIBS += -lnsl -lbsm -lscf

OBJS = audit_scf.o audit_scf_shared.o auditconfig.o 
SRCS = $(OBJS:%.o=%.c)

CPPFLAGS += -I$(LIBBSM) -I$(AUDITD) -I$(AUDITCONFIG) 

.KEEP_STATE:

install: all $(ROOTUSRSBINPROG)
all: $(PROG)

$(PROG): $(SRCS) $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)


$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

#_msg: $(MSGDOMAINPOFILE)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include $(SRC)/cmd/Makefile.targ
#include $(SRC)/Makefile.msg.targ
BUILDPO.msgfiles = \
	$(RM) messages.po $(TEXT_DOMAIN).po; \
	$(TOUCH) $(TEXT_DOMAIN).po; \
	$(XGETTEXT) $(XGETFLAGS) $(MSGFILES); \
	$(SED) -e '/^\# msgid/,/^\# msgstr/d' -e '/^domain/d' \
	-e '/^\#$$/d' -e '/^\#, /d' \
	messages.po $(TEXT_DOMAIN).po > $(POFILE); \
	$(RM) messages.po $(TEXT_DOMAIN).po
