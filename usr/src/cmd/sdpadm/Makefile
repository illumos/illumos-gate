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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

PROG = sdpadm

OBJS = sdpadm.o
SRCS = $(OBJS:.o=.c)
MSGFILES	= $(SRCS:%.c=%.i)
ETCFILES = sdp.conf
ROOTETC = $(ROOT)/etc

LINTFLAGS += -mx

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
POFILE = sdpadm_msg.po
XGETFLAGS = -a
FILEMODE = 0555
OWNER = root
GROUP = bin

ROOTETCFILES= $(ETCFILES:%=$(ROOTETC)/%)
$(ROOTETCFILES) := FILEMODE= 644

LINT_OBJS       = $(OBJS:%.o=%.ln)

.KEEP_STATE:

all: $(PROG) $(ETCFILES)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTETCFILES)

$(POFILE):	$(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(PROG) $(MSGFILES) $(POFILE)

lint:	$(LINT_OBJS) 
	$(LINT.c) $(LINTFLAGS) $(LDLIBS) $(LINT_OBJS)

include $(SRC)/Makefile.msg.targ
