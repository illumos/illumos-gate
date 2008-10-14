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
# cmd/mpathadm/Makefile

include ../Makefile.cmd

PROG= mpathadm

OBJS= cmdparse.o mpathadm.o mpathadm_text.o
SRCS= $(OBJS:%.o=%.c)
POFILE= mpathadm_all.po
POFILES=$(OBJS:%.o=%.po)

LDLIBS += -lMPAPI -ldevid

LINTFLAGS += -xerroff=E_BAD_FORMAT_STR2

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)


clean:
	$(RM) $(OBJS) $(POFILES) $(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

lint:	lint_SRCS

include ../Makefile.targ
