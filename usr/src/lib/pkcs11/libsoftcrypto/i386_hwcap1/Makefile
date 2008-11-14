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
# lib/pkcs11/libsoftcrypto/i386_hwcap1/Makefile
#
LIBRARY=	libsoftcrypto_hwcap1.a
VERS= .1

MODULE= libsoftcrypto_hwcap1.so.1

BIGNUM_PSM_OBJS= bignum_i386.o bignum_i386_asm.o
BIGNUM_PSM_SRC=	$(BIGNUM_DIR)/i386/bignum_i386_asm.s \
		$(BIGNUM_DIR)/i386/bignum_i386.c

include ../Makefile.com

BIGNUM_FLAGS += -DMMX_MANAGE -DHWCAP -DPSR_MUL
LINTFLAGS += $(BIGNUM_FLAGS)
LDLIBS  += -lc

$(ROOTHWCAPDIR)/% := FILEMODE= 755

install:  all $(ROOTHWCAPDIR)/$(MODULE)

pics/bignum_i386.o:	$(BIGNUM_DIR)/i386/bignum_i386.c
	$(COMPILE.c) $(BIGNUM_FLAGS) -o $@ $(BIGNUM_DIR)/i386/bignum_i386.c
	$(POST_PROCESS_O)

pics/bignum_i386_asm.o:	$(BIGNUM_DIR)/i386/bignum_i386_asm.s
	$(COMPILE.s) -o $@ $(BIGNUM_DIR)/i386/bignum_i386_asm.s
	$(POST_PROCESS_O)

$(ROOTHWCAPDIR): $(ROOTLIBDIR)
	$(INS.dir)

$(ROOTHWCAPDIR)/%: $(ROOTHWCAPDIR) %
	$(INS.file)
