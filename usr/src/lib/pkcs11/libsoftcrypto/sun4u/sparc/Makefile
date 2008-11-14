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
# lib/pkcs11/libsoftcrypto/sun4u/sparc/Makefile
#

CLASS = 32

include ../Makefile.com

ASFLAGS +=   -xarch=v8plus
LINTFLAGS += -D$(PLATFORM)

install:  all $(SOFT_PSR_LINKS) $(USR_PSM_LIBS)

include $(SRC)/Makefile.psm.targ

pics/mont_mulf_asm.o: $(BIGNUM_DIR)/sun4u/mont_mulf_v8plus.s
	$(COMPILE.s) -o $@ $(BIGNUM_DIR)/sun4u/mont_mulf_v8plus.s
	$(POST_PROCESS_O)
