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

.KEEP_STATE:

PROG = prstat
OBJS = prstat.o prfile.o prtable.o prsort.o prutil.o

include ../Makefile.cmd
include ../Makefile.cmd.64

XGETFLAGS = -a -x prstat.xcl
POFILE = pprstat.po
POFILES = $(OBJS:.o=.po)

ROOTLINK = $(PROG:%=$(ROOTBIN64)/%)

CLOBBERFILES += $(POFILE) $(POFILES)

CSTD = $(CSTD_GNU99)
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
LDLIBS += -lcurses -lproject

FILEMODE = 0555

.KEEP_STATE:

.PARALLEL : $(OBJS)

all: $(PROG)

clean:
	$(RM) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

install: all $(ROOTPROG) $(ROOTLINK)

$(ROOTLINK):
	$(RM) $@; $(SYMLINK) ../../bin/$(@F) $@

include ../Makefile.targ
