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

PROG= date
XPG4PROG= date
OBJS= date.o

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)

clean $(XPG4) := OBJS += values-xpg4.o
XGETFLAGS += -a -x $(PROG).xcl

.KEEP_STATE:

all: $(PROG) $(XPG4)

$(PROG) $(XPG4): $$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)


install: all $(ROOTPROG) $(ROOTXPG4PROG)

values-xpg4.o: ../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg4.c

clean:
	$(RM) $(OBJS)

# do not lint date.xpg4
lint:	lint_PROG

include ../Makefile.targ
