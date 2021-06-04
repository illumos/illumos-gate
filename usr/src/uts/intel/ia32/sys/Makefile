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
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# include global definitions
include ../../../../Makefile.master

HDRS=			\
	kdi_regs.h	\
	privmregs.h	\
	privregs.h

LINKS=			\
	asm_linkage.h	\
	machtypes.h	\
	psw.h		\
	pte.h		\
	reg.h		\
	stack.h		\
	trap.h		\
	traptrace.h

ROOTINCISA= $(ROOT)/usr/include/ia32
ROOTDIR= $(ROOTINCISA)/sys
ROOTDIRS= $(ROOTDIR)

ROOTHDRS= $(HDRS:%=$(ROOTDIR)/%)
ROOTLINKS= $(LINKS:%=$(ROOTDIR)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIR)/asm_linkage.h	:= LINK_TARGET = ../../sys/asm_linkage.h
$(ROOTDIR)/machtypes.h		:= LINK_TARGET = ../../sys/machtypes.h
$(ROOTDIR)/psw.h		:= LINK_TARGET = ../../sys/psw.h
$(ROOTDIR)/pte.h		:= LINK_TARGET = ../../sys/pte.h
$(ROOTDIR)/reg.h		:= LINK_TARGET = ../../sys/reg.h
$(ROOTDIR)/stack.h		:= LINK_TARGET = ../../sys/stack.h
$(ROOTDIR)/trap.h		:= LINK_TARGET = ../../sys/trap.h
$(ROOTDIR)/traptrace.h		:= LINK_TARGET = ../../sys/traptrace.h

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS) $(ROOTLINKS)

install_h: $(ROOTINCISA) .WAIT $(ROOTDIRS) .WAIT $(ROOTHDRS) $(ROOTLINKS)

$(ROOTINCISA):
	$(INS.dir)

$(ROOTDIRS):	$(ROOTINCISA)
	$(INS.dir)

$(ROOTLINKS):
	$(RM) $@; $(SYMLINK) $(LINK_TARGET) $@

check:	$(CHECKHDRS)
