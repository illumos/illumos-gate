#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# "general" is intended to be a generic way to invoke a filesystem-specific
# command, but at the moment, only /usr/sbin/unshare uses this facility.
# Until someone else needs this functionality, this will be turned off
# so that we don't wind up with a spurious /usr/sbin/general.  To use
# "general" more fully in future, remove the comments from the lines below.
#

PROG=	unshare
#PROG=	general

OBJS=	general.o
SRCS=	general.c

#ROOTLINK= $(ROOTUSRSBIN)/unshare

CFLAGS += -s

include ../../Makefile.cmd

CERRWARN += -_gcc=-Wno-parentheses

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTLINK)

#$(ROOTLINK): $(ROOTUSRSBINPROG)
#	$(RM) $@; $(LN) $(ROOTUSRSBINPROG) $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ

