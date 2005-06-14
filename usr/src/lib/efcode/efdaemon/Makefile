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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/efcode/efdaemon/Makefile

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64

EFCODEDIR = $(ROOT)/usr/lib/efcode
EFCODEDIR64 = $(EFCODEDIR)/$(MACH64)

CPPFLAGS += -DDEBUG -DFCODE_INTERNAL
CPPFLAGS += -I ../include -I $(ROOT)/usr/platform/sun4u/include

PROG	= efdaemon
EFTARGETS += $(EFCODEDIR64)/$(PROG)
EFTARGETS += $(EFCODEDIR)/efcode.sh

MFSTDIR = $(ROOT)/var/svc/manifest/platform/sun4u
MANIFEST = efdaemon.xml
EFTARGETS += $(MFSTDIR)/$(MANIFEST)

$(MFSTDIR)/$(MANIFEST) := FILEMODE = 0444

all:	$(PROG)

clean:
	-$(RM) $(PROG)

$(EFCODEDIR64)/%: %
	$(INS.file)

$(EFCODEDIR)/%.sh: %.sh
	$(INS.file)

$(MFSTDIR)/%: %
	$(INS.file)

install: all .WAIT $(EFTARGETS)

lint:	lint_PROG

.KEEP_STATE:

include $(SRC)/cmd/Makefile.targ
