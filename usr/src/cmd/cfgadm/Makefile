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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= cfgadm

include ../Makefile.cmd

SED= sed
DCFILE= $(PROG).dc

XGETFLAGS += -a -x cfgadm.xcl

LDLIBS += -lcfgadm
LINTFLAGS += $(ENVLDFLAGS1) $(ENVLDFLAGS2) $(ENVLDFLAGS3) $(LDLIBS)

SMOFF += snprintf_overflow

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)
	-$(RM) $(ROOTETCPROG)
	$(SYMLINK) ../usr/sbin/$(PROG) $(ROOTETCPROG)

clean:

lint:	lint_PROG

$(DCFILE): $(PROG).c
	$(RM) $(DCFILE)
	$(COMPILE.cpp) $(PROG).c | \
	$(XGETTEXT) -t -
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ
