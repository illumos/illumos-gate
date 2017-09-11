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
# Copyright 2010 Nexenta Systems, Inc. All rights reserved.
#

PROG=		beadm
OBJS=		beadm.o
SRCS=		$(OBJS:%.o=%.c)
POFILE=		beadm.po

include ../Makefile.cmd

LDLIBS += -lnvpair -lbe -lcmdutils
CERRWARN += -_gcc=-Wno-parentheses

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

# Links from /usr/sbin to /sbin
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(PROG) $@

FRC:

include ../Makefile.targ
