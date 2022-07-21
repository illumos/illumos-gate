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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2022 Garrett D'Amore
#

#
# Note that this Makefile is *not* the Makefile that is installed in the proto
# area's /usr/demo/mdb directory -- that file is Makefile.demo.  This Makefile
# copies Makefile.demo and the other files in this directory to /usr/demo/mdb.
#

include ../../Makefile.cmd

DEMOFILES = \
	common/example1.c \
	common/example2.c \
	Makefile \
	Makefile.common \
	Makefile.i386 \
	Makefile.amd64 \
	README

DEMOSUBDIRS = common i386 amd64

ROOTDEMODIR = $(ROOT)/usr/demo/mdb
ROOTDEMOFILES = $(DEMOFILES:%=$(ROOTDEMODIR)/%)
ROOTDEMOSUBDIRS = $(DEMOSUBDIRS:%=$(ROOTDEMODIR)/%)

all clean.lint clean clobber dmods install_h lint:

install: $(ROOTDEMOFILES)

$(ROOTDEMODIR):
	$(INS.dir)

$(ROOTDEMOSUBDIRS):
	$(INS.dir)

$(ROOTDEMODIR)/%: %.demo
	$(INS.rename)

$(ROOTDEMODIR)/%: %
	$(INS.file)

$(ROOTDEMOFILES): $(ROOTDEMOSUBDIRS)

$(ROOTDEMOSUBDIRS): $(ROOTDEMODIR)

$(ROOTDEMODIR) := DIRMODE = 755

$(ROOTDEMOSUBDIRS) := DIRMODE = 755

$(ROOTDEMOFILES) := FILEMODE = 644
