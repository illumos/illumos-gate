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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/pkcs11/pkcs11_softtoken/sparc/Makefile

AES_PSR_OBJECTS = aes_crypt_sparc.o
ARCFOUR_PSR_OBJECTS = arcfour_crypt_sparc.o
DES_PSR_OBJECTS = des_crypt_sparc.o
RSA_PSR_OBJECTS = 
BIGNUM_PSR_OBJECTS = mont_mulf_sparc.o
BIGNUM_CFG = -DUSE_FLOATING_POINT

include ../Makefile.com
CFLAGS		+=	-Dsun4u
CPPFLAGS	+=	-DMP_USE_UINT_DIGIT

install: all $(ROOTLIBS) $(ROOTLINKS)


pics/aes_crypt_sparc.o: $(AESDIR)/sun4u/aes_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -P -DPIC -xarch=v8plus -o $@ \
		$(AESDIR)/sun4u/aes_crypt_asm.s
	$(POST_PROCESS_O)

pics/arcfour_crypt_sparc.o: $(ARCFOURDIR)/sun4u/arcfour_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -P -DPIC -xarch=v8plus -o $@ \
		$(ARCFOURDIR)/sun4u/arcfour_crypt_asm.s
	$(POST_PROCESS_O)

pics/des_crypt_sparc.o: $(DESDIR)/sun4u/des_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -P -DPIC -xarch=v8plus -o $@ \
		$(DESDIR)/sun4u/des_crypt_asm.s
	$(POST_PROCESS_O)

pics/mont_mulf_sparc.o: $(BIGNUMDIR)/sun4u/mont_mulf_v8plus.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -xarch=v8plus -o $@ \
		$(BIGNUMDIR)/sun4u/mont_mulf_v8plus.s
	$(POST_PROCESS_O)
