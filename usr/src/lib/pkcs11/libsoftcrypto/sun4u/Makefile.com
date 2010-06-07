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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

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
#
# Specifying *_OBJS here brings in both *_COMMON_OBJS and *_PSM_OBJS to this
# platform-specific implementation, and *supercedes* (replaces) the common
# version.  Specifying only *_PSM_OBJS is used when the PSM version is
# intended to *augment* (add onto) the common version.
#
# COMMON and PSM source/object setup is done in libsoftcrypto/Makefile.com,
# and does not need to be repeated here.  Only list *_SRCS/*_PSM_SRCS and
# *_OBJS/*_PSM_OBJS that are platform-specific here.  Keep SRCS= and
# OBJECTS= in sync with each other.  Update mapfile-vers to list only
# the functions that are actually compiled into this platform-specific
# library; do not duplicate what is already in common/mapfile-vers unless
# this library is providing a superceded version of that function here.
#
# Note:  This Makefile.com is set up to compile the PSM objects for AES,
# ARCFOUR, and DES to augment the corresponding COMMON objects already
# included in the base libsoftcrypto library.  It does not compile anything
# for sun4u sparc/sparcv9 to supercede a COMMON object from libsoftcrypto.
# See the sun4v platform-specific implementation for an alternate example.
#
# NOTE: BIGNUM is different.  There is actually no COMMON object in
# libsoftcrypto for currently-supported platforms (sun4u, sun4v, i386/amd64).
# The COMMON objects for BIGNUM are a starting point if a new platform is
# ever added.  Thus, BIGNUM_OBJS is listed in every currently-supported
# platform-specific Makefile.com, in effect always overriding what it is
# in the COMMON implementation.  BIGNUM_PSM_OBJS is then used to further
# augment BIGNUM_COMMON_OBJS on a platform-by-platform basis.
#
# Example:
# 1.	common/Makefile.com:
#		FOO_COMMON_OBJS = foo.o
#		FOO_PSM_OBJS = <blank>
#		FOO_OBJS = $(FOO_COMMON_OBJS) $(FOO_PSM_OBJS)
#
#		BAR_COMMON_OBJS = bar.o
#		BAR_PSM_OBJS = <blank>
#		BAR_OBJS = $(BAR_COMMON_OBJS) $(BAR_PSM_OBJS)
#
#		OBJECTS = $(FOO_OBJS) $(BAR_OBJS)
#		LIB = libsoftcrypto
#
#	Compiling here will make a library libsoftcrypto.so containing:
#		foo.o bar.o
#
#	Run time sees, unless it is a sun4u or sun4v platform (see below):
#		foo.o bar.o
#
# 2.	sun4u/Makefile.com:
#		FOO_PSM_OBJS = foo-plus.o
#		OBJECTS = $(FOO_OBJS)		/* defined in common */
#		LIB = libsoftcrypto_psr
#
#	Compiling here will make a library libsoftcrypto_psr.so containing:
#		foo-plus.o
#
#	Run time sees, on a sun4u platform only:
#		foo.o bar.o foo-plus.o		/* note the difference */
#
# 3.	sun4v/Makefile.com:
#		BAR_PSM_OBJS = bar'.o
#		OBJECTS = $(BAR_PSM_OBJS)	/* not $(BAR_OBJS) */
#		LIB - libsoftcrypto_psr
#
#	Compiling here will make a library libsoftcrypto_psr.so containing:
#		bar'.o
#
#	Run time sees, on a sun4v platform only:
#		foo.o bar'.o			/* note the difference */
#
AES_PSM_OBJS= aes_crypt_asm.o
ARCFOUR_PSM_OBJS= arcfour_crypt_asm.o
DES_PSM_OBJS= des_crypt_asm.o
BIGNUM_PSM_OBJS= mont_mulf_asm.o
BIGNUM_FLAGS += -DUSE_FLOATING_POINT

MAPFILES = ../mapfile-vers
OBJECTS = $(AES_OBJS) $(ARCFOUR_OBJS) $(DES_OBJS) $(BIGNUM_OBJS) \
	$(MODES_OBJS)

# Compiler settings
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
