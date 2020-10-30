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
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/Makefile.master
include		$(SRC)/cmd/sgs/Makefile.sub

MACHDEMOFILES= \
		i386/regs.c \
		i386/m_utils.c \
		i386/rdb_mach.h \
		i386/Makefile \
		amd64/regs.c \
		amd64/rdb_mach.h \
		amd64/Makefile \
		sparc/regs.c \
		sparc/m_utils.c \
		sparc/rdb_mach.h \
		sparc/Makefile \
		sparcv9/regs.c \
		sparcv9/m_utils.c \
		sparcv9/rdb_mach.h \
		sparcv9/Makefile

DEMOFILES= \
		00README \
		Makefile.com \
		Makefile.targ \
		common/bpt.c \
		common/dis.c \
		common/disasm.c \
		common/disasm.h \
		common/main.c \
		common/ps.c \
		common/gram.y \
		common/lex.l \
		common/globals.c \
		common/help.c \
		common/utils.c \
		common/maps.c \
		common/syms.c \
		common/callstack.c \
		common/rdb.h \
		common/rdb.man \
		tests/breaks \
		tests/loadmaps \
		tests/object_padding_maps \
		tests/plt_skip \
		tests/steps \
		tests/test-sparc-regs \
		tests/simp.c \
		tests/sub.c \
		$(MACHDEMOFILES)

ROOTDEMODIRBASE=	$(ROOT)/usr/demo/librtld_db

ROOTDEMODIRS=	$(ROOTDEMODIRBASE) \
		$(ROOTDEMODIRBASE)/common \
		$(ROOTDEMODIRBASE)/tests \
		$(ROOTDEMODIRBASE)/i386 \
		$(ROOTDEMODIRBASE)/amd64 \
		$(ROOTDEMODIRBASE)/sparc \
		$(ROOTDEMODIRBASE)/sparcv9

ROOTDEMOFILES=	$(DEMOFILES:%=$(ROOTDEMODIRBASE)/%)

$(ROOTDEMODIRS) :=	DIRMODE =	755

SED=		sed -e "/DEMO DELETE START/,/DEMO DELETE END/d"

CLEANFILES=	*.demo */*.demo

.KEEP_STATE:
.PARALLEL:	$(ROOTDEMOFILES)

all catalog chkmsg:

install:	$(ROOTDEMODIRS) .WAIT $(ROOTDEMOFILES)

clean clobber: FRC
		$(RM) $(CLEANFILES)

$(ROOTDEMODIRS):
		$(INS.dir)

$(ROOTDEMODIRBASE)/Makefile.%: Makefile.%.demo
		$(INS.rename)

$(ROOTDEMODIRBASE)/%/Makefile: %/Makefile.demo
		$(INS.rename)

Makefile.%.demo: Makefile.%
		$(SED) < $< > $@

%/Makefile.demo: %/Makefile
		$(SED) < $< > $@

$(ROOTDEMODIRBASE)/%: %
		$(INS.file)

$(ROOTDEMODIRBASE)/common/%:	common/%
		$(INS.file)

$(ROOTDEMODIRBASE)/tests/%:	tests/%
		$(INS.file)

$(ROOTDEMODIRBASE)/sparc/%:	sparc/%
		$(INS.file)

$(ROOTDEMODIRBASE)/sparcv9/%:	sparcv9/%
		$(INS.file)

$(ROOTDEMODIRBASE)/i386/%:	i386/%
		$(INS.file)

FRC:
