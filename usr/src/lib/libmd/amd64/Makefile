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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2013 Saso Kiselkov. All rights reserved.
#

LIBRARY =	libmd.a
VERS =		.1

OBJECTS =	edonr.o md4.o md5.o sha1.o sha2.o \
		skein.o skein_block.o skein_iv.o

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/lib/Makefile.rootfs
include		$(SRC)/lib/Makefile.lib.64
include		../Makefile.com

CAPFILES =	pics/sha1-ni.o \
		pics/sha256-ni.o

EXTPICS =	pics/md5_amd64.o \
		pics/sha512-x86_64.o \
		pics/sha256-x86_64.o \
		pics/sha1-x86_64.o \
		$(CAPFILES:%.o=%.o.symcap)

CLEANFILES +=	$(EXTPICS) \
		$(EXTPICS:pics/%.o=%.s) \
		$(CAPFILES) \
		$(CAPFILES:%.o=%.o.objcap) \
		$(CAPFILES:%.o=%.o.symcap)

pics/sha1-ni.o.objcap		:= CAPFILE = capabilities/sha.cap
pics/sha256-ni.o.objcap		:= CAPFILE = capabilities/sha.cap

# This prevents <sys/asm_linkage.h> from including C source:
AS_CPPFLAGS += -D_ASM

.KEPP_STATE:

all:		$(LIBS)

install:	all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTCOMPATLINKS64)

pics/%.o: %.s
		$(COMPILE.s) -o $@ ${@F:.o=.s}
		$(POST_PROCESS_O)

pics/%.o: $(SRC)/common/crypto/sha1/amd64/%.s
		$(COMPILE.s) -o $@ $<
		$(POST_PROCESS_O)

pics/%.o: $(SRC)/common/crypto/sha2/amd64/%.s
		$(COMPILE.s) -o $@ $<
		$(POST_PROCESS_O)

pics/%.o.objcap: pics/%.o
		$(LD) -r -o $@ -M$(CAPFILE) -Breduce $<
		$(POST_PROCESS_O)

pics/%.o.symcap: pics/%.o.objcap
		$(LD) -r -o $@ -z symbolcap $<

md5_amd64.s: $(COMDIR)/md5/amd64/md5_amd64.pl
		$(PERL) $? $@

sha1-x86_64.s: $(COMDIR)/sha1/amd64/sha1-x86_64.pl
		$(PERL) $? $@

sha512-x86_64.s: $(COMDIR)/sha2/amd64/sha512-x86_64.pl
		$(PERL) $? $@

sha256-x86_64.s: $(COMDIR)/sha2/amd64/sha512-x86_64.pl
		$(PERL) $? $@

include		../Makefile.targ
