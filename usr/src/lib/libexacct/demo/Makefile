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
# lib/libexacct/demo/Makefile
#

PROG = exdump

include ../../../cmd/Makefile.cmd

LDLIBS += -lexacct -lproject -lsocket -lnsl
CFLAGS += $(CCVERBOSE)

.KEEP_STATE:

DEMOFILES = \
	exdump.c \
	Makefile \
	README

ROOTDEMODIR = $(ROOT)/usr/demo/libexacct
ROOTDEMOFILES = $(DEMOFILES:%=$(ROOTDEMODIR)/%)

all: $(PROG)

install: all $(ROOTDEMOFILES)

clean:

lint: lint_PROG

$(ROOTDEMODIR):
	$(INS.dir)

$(ROOTDEMODIR)/%: %.demo
	$(INS.rename)

$(ROOTDEMODIR)/%: %
	$(INS.file)

$(ROOTDEMOFILES): $(ROOTDEMODIR)

$(ROOTDEMODIR) := OWNER = root
$(ROOTDEMODIR) := GROUP = bin
$(ROOTDEMODIR) := DIRMODE = 755

$(ROOTDEMOFILES) := OWNER = root
$(ROOTDEMOFILES) := GROUP = bin
$(ROOTDEMOFILES) := FILEMODE = 644

include ../../../cmd/Makefile.targ
