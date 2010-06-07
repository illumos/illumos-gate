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
# lib/pkcs11/libsoftcrypto/Makefile.com
#

# AES
AES_DIR= $(SRC)/common/crypto/aes
AES_COMMON_OBJS= aes_impl.o aes_modes.o
AES_COMMON_SRC= $(AES_COMMON_OBJS:%.o=$(AES_DIR)/%.c)
AES_FLAGS= -I$(AES_DIR)

# Blowfish
BLOWFISH_DIR= $(SRC)/common/crypto/blowfish
BLOWFISH_COMMON_OBJS= blowfish_impl.o
BLOWFISH_COMMON_SRC= $(BLOWFISH_COMMON_OBJS:%.o=$(BLOWFISH_DIR)/%.c)
BLOWFISH_FLAGS= -I$(BLOWFISH_DIR)

# ARCFour
ARCFOUR_DIR= $(SRC)/common/crypto/arcfour
ARCFOUR_COMMON_OBJS= arcfour_crypt.o
ARCFOUR_COMMON_SRC= $(ARCFOUR_COMMON_OBJS:%.o=$(ARCFOUR_DIR)/%.c)
ARCFOUR_FLAGS= -I$(ARCFOUR_DIR)

# DES
DES_DIR= $(SRC)/common/crypto/des
DES_COMMON_OBJS= des_impl.o des_ks.o
DES_COMMON_SRC= $(DES_COMMON_OBJS:%.o=$(DES_DIR)/%.c)
DES_FLAGS= -I$(DES_DIR)

# BIGNUM -- needed by DH, DSA, RSA
BIGNUM_DIR= $(SRC)/common/bignum
BIGNUM_COMMON_OBJS= bignumimpl.o
BIGNUM_COMMON_SRC= $(BIGNUM_COMMON_OBJS:%.o=$(BIGNUM_DIR)/%.c)
BIGNUM_FLAGS= -I$(BIGNUM_DIR)

# Modes
MODES_DIR= $(SRC)/common/crypto/modes
MODES_COMMON_OBJS= modes.o ecb.o cbc.o ctr.o
MODES_COMMON_SRC= $(MODES_COMMON_OBJS:%.o=$(MODES_DIR)/%.c)
MODES_FLAGS= -I$(MODES_DIR)

# DH
DH_DIR= $(SRC)/common/crypto/dh
DH_COMMON_OBJS= dh_impl.o
DH_COMMON_SRC= $(DH_COMMON_OBJS:%.o=$(DH_DIR)/%.c)
DH_FLAGS= $(BIGNUM_FLAGS) -I$(DH_DIR)

# DSA
DSA_DIR= $(SRC)/common/crypto/dsa
DSA_COMMON_OBJS= dsa_impl.o
DSA_COMMON_SRC= $(DSA_COMMON_OBJS:%.o=$(DSA_DIR)/%.c)
DSA_FLAGS= $(BIGNUM_FLAGS) -I$(DSA_DIR)

# RSA
RSA_DIR= $(SRC)/common/crypto/rsa
RSA_COMMON_OBJS= rsa_impl.o
RSA_COMMON_SRC= $(RSA_COMMON_OBJS:%.o=$(RSA_DIR)/%.c)
RSA_FLAGS= $(BIGNUM_FLAGS) -I$(RSA_DIR)

# PADDING -- needed by RSA
PAD_DIR= $(SRC)/common/crypto/padding
PAD_COMMON_OBJS= pkcs1.o pkcs7.o
PAD_COMMON_SRC= $(PAD_COMMON_OBJS:%.o=$(PAD_DIR)/%.c)
PAD_FLAGS= -I$(PAD_DIR)

# Object setup
AES_OBJS= $(AES_COMMON_OBJS) $(AES_PSM_OBJS)
ARCFOUR_OBJS= $(ARCFOUR_COMMON_OBJS) $(ARCFOUR_PSM_OBJS)
BLOWFISH_OBJS= $(BLOWFISH_COMMON_OBJS) $(BLOWFISH_PSM_OBJS)
DES_OBJS= $(DES_COMMON_OBJS) $(DES_PSM_OBJS)
BIGNUM_OBJS= $(BIGNUM_COMMON_OBJS) $(BIGNUM_PSM_OBJS)
MODES_OBJS= $(MODES_COMMON_OBJS) $(MODES_PSM_OBJS)
DH_OBJS= $(DH_COMMON_OBJS) $(DH_PSM_OBJS)
DSA_OBJS= $(DSA_COMMON_OBJS) $(DSA_PSM_OBJS)
RSA_OBJS= $(RSA_COMMON_OBJS) $(RSA_PSM_OBJS)
PAD_OBJS= $(PAD_COMMON_OBJS) $(PAD_PSM_OBJS)

OBJECTS= $(AES_OBJS) $(ARCFOUR_OBJS) $(BIGNUM_OBJS) $(BLOWFISH_OBJS) \
	$(DES_OBJS) $(MODES_OBJS) $(DH_OBJS) $(DSA_OBJS) \
	$(RSA_OBJS) $(PAD_OBJS)

include $(SRC)/lib/Makefile.lib

# Source file setup
AES_SRC= $(AES_COMMON_SRC) $(AES_PSM_SRC)
ARCFOUR_SRC= $(ARCFOUR_COMMON_SRC) $(ARCFOUR_PSM_SRC)
BLOWFISH_SRC= $(BLOWFISH_COMMON_SRC) $(BLOWFISH_PSM_SRC)
DES_SRC= $(DES_COMMON_SRC) $(DES_PSM_SRC)
BIGNUM_SRC= $(BIGNUM_COMMON_SRC) $(BIGNUM_PSM_SRC)
MODES_SRC= $(MODES_COMMON_SRC) $(MODES_PSM_SRC)
DH_SRC= $(DH_COMMON_SRC) $(DH_PSM_SRC)
DSA_SRC= $(DSA_COMMON_SRC) $(DSA_PSM_SRC)
RSA_SRC= $(RSA_COMMON_SRC) $(RSA_PSM_SRC)
PAD_SRC= $(PAD_COMMON_SRC) $(PAD_PSM_SRC)

SRCS=	$(AES_SRC) $(ARCFOUR_SRC) $(BIGNUM_SRC) $(BLOWFISH_SRC) $(DES_SRC) \
	$(MODES_SRC) $(DH_SRC) $(DSA_SRC) $(RSA_SRC) \
	$(PAD_SRC)

# Do not lint ECC and MPI
LINTABLE= \
	$(AES_SRC) $(ARCFOUR_SRC) $(BIGNUM_SRC) $(BLOWFISH_SRC) $(DES_SRC) \
	$(MODES_SRC) $(DH_SRC) $(DSA_SRC) $(RSA_SRC) $(PAD_SRC)

#
# Compiler settings
#

SRCDIR=	$(SRC)/lib/pkcs11/libsoftcrypto/common/
CRYPTODIR= $(SRC)/common/crypto/
UTSDIR= $(SRC)/uts/common/
ROOTLIBDIR= $(ROOT)/usr/lib
ROOTLIBDIR64= $(ROOT)/usr/lib/$(MACH64)
ROOTHWCAPDIR= $(ROOTLIBDIR)/libsoftcrypto

# $(LINTLIB) is not included here;  i386_hwcap1/Makefile does not make
# a lint library, so each of the other platform-specific Makefiles adds
# the lint library target individually
LIBS = $(DYNLIB)
LDLIBS += -lc

CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CPPFLAGS += -I$(SRCDIR) -I$(CRYPTODIR) -I$(UTSDIR) \
	$(BIGNUM_FLAGS) \
	-D_POSIX_PTHREAD_SEMANTICS
ASFLAGS = $(AS_PICFLAGS) -P -D__STDC__ -D_ASM
EXTRA_LINT_FLAGS = \
	$(AES_FLAGS) $(BLOWFISH_FLAGS) $(ARCFOUR_FLAGS) $(DES_FLAGS) \
	$(BIGNUM_FLAGS) $(MODES_FLAGS) $(DH_FLAGS) $(DSA_FLAGS) \
	$(RSA_FLAGS) $(PAD_FLAGS)
LINTFLAGS += $(EXTRA_LINT_FLAGS)
LINTFLAGS64 += $(EXTRA_LINT_FLAGS) -errchk=longptr64

LINTLIB=	llib-l$(LIBNAME).ln
$(LINTLIB)	:= 	SRCS = $(LINTABLE)
lintcheck	:=	SRCS = $(LINTABLE)

all:	$(LIBS)

lint:	lintcheck

pics/%.o:	$(AES_DIR)/%.c
	$(COMPILE.c) $(AES_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(ARCFOUR_DIR)/%.c
	$(COMPILE.c) $(ARCFOUR_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(BIGNUM_DIR)/%.c
	$(COMPILE.c) $(BIGNUM_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(BLOWFISH_DIR)/%.c
	$(COMPILE.c) $(BLOWFISH_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(DES_DIR)/%.c
	$(COMPILE.c) $(DES_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(MODES_DIR)/%.c
	$(COMPILE.c) $(MODES_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(DH_DIR)/%.c
	$(COMPILE.c) $(DH_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(DSA_DIR)/%.c
	$(COMPILE.c) $(DSA_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(RSA_DIR)/%.c
	$(COMPILE.c) $(RSA_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(PAD_DIR)/%.c
	$(COMPILE.c) $(PAD_FLAGS) -o $@ $<
	$(POST_PROCESS_O)

#
# Platform-specific targets
#


SOFT_PSR_DIRS = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
SOFT_PSR_LINKS = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/$(MODULE))

SOFT_PSR64_DIRS = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/$(MACH64))
SOFT_PSR64_LINKS = \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/$(MACH64)/$(MODULE))

INS.slink6 = $(RM) -r $@; \
	$(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@
INS.slink64 = $(RM) -r $@; \
	$(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) $@

$(SOFT_PSR_DIRS) \
$(SOFT_PSR64_DIRS):
	-$(INS.dir)

$(SOFT_PSR_LINKS): $(SOFT_PSR_DIRS)
	-$(INS.slink6)

$(SOFT_PSR64_LINKS): $(SOFT_PSR64_DIRS)
	-$(INS.slink64)


include $(SRC)/lib/Makefile.targ
