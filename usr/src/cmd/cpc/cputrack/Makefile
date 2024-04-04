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
# Copyright (c) 2018, Joyent, Inc.
#

include	../../Makefile.cmd
include	../../Makefile.cmd.64
include	../../Makefile.ctf

PROG =		cputrack
OBJS =		$(PROG).o caps.o time.o setgrp.o strtoset.o
LDLIBS +=	-lcpc -lpctx

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRC)/lib/libcpc/common

POFILES =	../common/$(PROG).po ../common/caps.po
POFILE =	$(PROG)_cmd.po

# not linted
SMATCH=off

ROOTLINK = $(PROG:%=$(ROOTBIN64)/%)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(ROOTLINK)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTLINK):
	$(RM) $@; $(SYMLINK) ../../bin/cputrack $@

clean:
	$(RM) $(OBJS)

%.o:	../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

include ../../Makefile.targ
