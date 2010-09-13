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
# ident	"%Z%%M%	%I%	%E% SMI"

include $(SRC)/cmd/Makefile.cmd

.KEEP_STATE:

ROOTBIN = $(ROOT)/opt/SUNWdtrt/bin
ROOTBIN32 = $(ROOTBIN)/$(MACH32)
ROOTBIN64 = $(ROOTBIN)/$(MACH64)

PROG = chkargs
LDLIBS = $(LDLIBS.cmd)
LDLIBS += -ldtrace -lctf

ROOTISAEXEC = $(ROOTBIN)/$(PROG)
ROOTPROG32 = $(ROOTBIN32)/$(PROG)
ROOTPROG64 = $(ROOTBIN64)/$(PROG)

$(ROOTPROG32) := FILEMODE = 0555
$(ROOTPROG64) := FILEMODE = 0555

all: $(PROG)

clean lint:

clobber:
	$(RM) $(PROG) $(ROOTISAEXEC)

$(PROG): ../$(PROG).c
	$(LINK.c) -o $@ ../$(PROG).c $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

$(ROOTPROG32): $(ROOTBIN32) $(PROG)

$(ROOTPROG64): $(ROOTBIN64) $(PROG)

$(ROOTBIN32)/%: %
	$(INS.file)

$(ROOTBIN64)/%: %
	$(INS.file)

$(ROOTISAEXEC):
	$(RM) $@;
	$(CP) -p $(ISAEXEC) $@

$(ROOTBIN)/%: $(ROOTBIN)
	$(INS.dir)

$(ROOTBIN):
	$(INS.dir)
