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
# lib/pkcs11/libsoftcrypto/sun4u/Makefile.com
#

LIBRARY = libsoftcrypto_psr.a
VERS= .1
PLATFORM = sun4u
MODULE = libsoftcrypto_psr.so.1

include $(SRC)/Makefile.psm
include ../Makefile.links
include ../../Makefile.com

# Platform-specific settings
AES_PSM_OBJS= aes_crypt_asm.o
ARCFOUR_PSM_OBJS= arcfour_crypt_asm.o
DES_PSM_OBJS= des_crypt_asm.o
BIGNUM_PSM_OBJS= mont_mulf_asm.o
BIGNUM_FLAGS += -DUSE_FLOATING_POINT

MAPFILES = ../mapfile-vers
OBJECTS = $(AES_OBJS) $(ARCFOUR_OBJS) $(DES_OBJS) $(BIGNUM_PSM_OBJS) \
	$(MODES_OBJS)

# Compiler settings
LDLIBS  += -lc
CFLAGS += -D$(PLATFORM)
CFLAGS64 += -D$(PLATFORM)
ASFLAGS += -DPIC

$(USR_PSM_LIB_DIR)/% := FILEMODE = 755

pics/aes_crypt_asm.o: $(AES_DIR)/sun4u/aes_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -o $@ $(AES_DIR)/sun4u/aes_crypt_asm.s
	$(POST_PROCESS_O)

pics/arcfour_crypt_asm.o: $(ARCFOUR_DIR)/sun4u/arcfour_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -o $@ \
		$(ARCFOUR_DIR)/sun4u/arcfour_crypt_asm.s
	$(POST_PROCESS_O)

pics/des_crypt_asm.o: $(DES_DIR)/sun4u/des_crypt_asm.s
	$(COMPILE.s) $(AS_BIGPICFLAGS) -o $@ $(DES_DIR)/sun4u/des_crypt_asm.s
	$(POST_PROCESS_O)
