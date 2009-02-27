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
# lib/pkcs11/libsoftcrypto/amd64/Makefile
#

LIBRARY=	libsoftcrypto.a
VERS= .1

AES_PSM_OBJS= aes_amd64.o aeskey.o
AES_PSM_SRC= $(AES_DIR)/$(MACH64)/aes_amd64.s $(AES_DIR)/$(MACH64)/aeskey.c

ARCFOUR_PSM_OBJS= arcfour-x86_64.o
ARCFOUR_PSM_SRC= arcfour-x86_64.s

BIGNUM_PSM_OBJS= bignum_amd64.o bignum_amd64_asm.o
BIGNUM_PSM_SRC= $(BIGNUM_DIR)/$(MACH64)/bignum_amd64.c \
		$(BIGNUM_DIR)/$(MACH64)/bignum_amd64_asm.s

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

CFLAGS		+= -xO4 -xcrossfile
BIGNUM_FLAGS	+= -DPSR_MUL
LINTFLAGS64	+= $(BIGNUM_FLAGS) $(AES_FLAGS)
CLEANFILES      += arcfour-x86_64.s

LDLIBS  += -lc
LIBS += $(LINTLIB)

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)

arcfour-x86_64.s:	$(ARCFOUR_DIR)/amd64/arcfour-x86_64.pl
	$(PERL) $? $@

pics/%.o:	$(AES_DIR)/$(MACH64)/%.c
	$(COMPILE.c) $(AES_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(AES_DIR)/$(MACH64)/%.s
	$(COMPILE.s) $(AES_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(BIGNUM_DIR)/$(MACH64)/%.c
	$(COMPILE.c) $(BIGNUM_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(BIGNUM_DIR)/$(MACH64)/%.s
	$(COMPILE64.s) $(BIGNUM_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	arcfour-x86_64.s
	$(COMPILE64.s) $(ARCFOUR_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

