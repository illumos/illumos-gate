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

PROGS = adbgen1 adbgen3 adbgen4
OBJS = adbsub.o
SCRIPTS = adbgen

CLOBBERFILES = $(PROGS) $(OBJS) $(SCRIPTS)

.PARALLEL: $(PROGS) $(OBJS) $(SCRIPTS)
.KEEP_STATE:

include ../../Makefile.cmd

ROOTADBDIR32	= $(ROOT)/usr/lib/adb
ROOTADBDIR64	= $(ROOT)/usr/lib/adb/$(MACH64)
ROOTADBDIR	= $(ROOTADBDIR32)

ROOTPROGS	= $(PROGS:%=$(ROOTADBDIR)/%)
ROOTOBJS	= $(OBJS:%=$(ROOTADBDIR)/%)
ROOTSCRIPTS	= $(SCRIPTS:%=$(ROOTADBDIR)/%)

FILEMODE	= 0644
$(ROOTPROGS) $(ROOTSCRIPTS) := FILEMODE = 0755

all: $$(PROGS) $$(OBJS) $$(SCRIPTS)
install: $$(ROOTPROGS) $$(ROOTOBJS) $$(ROOTSCRIPTS)

clean:

adbgen%: ../common/adbgen%.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) -c -o $@ $<
	$(POST_PROCESS_O)

%: ../common/%.sh
	$(RM) $@
	cat $< >$@
	chmod +x $@

$(ROOTADBDIR32)/%: % $(ROOTADBDIR32)
	$(INS.file)

$(ROOTADBDIR64)/%: % $(ROOTADBDIR64)
	$(INS.file)

$(ROOTADBDIR32):
	$(INS.dir)

$(ROOTADBDIR64): $(ROOTADBDIR32)
	$(INS.dir)

include ../../Makefile.targ
