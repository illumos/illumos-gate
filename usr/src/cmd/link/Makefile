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
# Copyright 2015 RackTop Systems.
#

PROG= link 
XPG4PROG= link
OBJS= link.o

include ../Makefile.cmd

clean $(XPG4) := OBJS += values-xpg4.o

FILEMODE= 0555

CERRWARN += -_gcc=-Wno-parentheses

.KEEP_STATE:

all: $(PROG) $(XPG4)

$(PROG) $(XPG4): $$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTXPG4PROG)
	-$(RM) $(ROOTETCPROG)
	-$(SYMLINK) ../usr/sbin/$(PROG) $(ROOTETCPROG)

values-xpg4.o: ../../lib/common/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/common/common/values-xpg4.c

clean:
	$(RM) $(OBJS)

lint:	lint_PROG

include ../Makefile.targ
