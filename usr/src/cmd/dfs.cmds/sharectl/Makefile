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

include ../../Makefile.cmd
include ../../Makefile.ctf

PROG=		sharectl

CPPFLAGS += -I../sharemgr
LDLIBS += -lshare -lumem

OBJS = $(PROG:%=%.o) shareutil.o

CLOBBERFILES = $(POFILE) $(POFILES)

POFILES = $(OBJS:.o=.po)
POFILE  = sharectl_cmd.po

.KEEP_STATE:

all: $(PROG)

_msg: $(POFILE)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

%.o: ../sharemgr/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.po: ../sharemgr/%.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)
