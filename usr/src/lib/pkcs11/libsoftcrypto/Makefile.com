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
# lib/pkcs11/libsoftcrypto/Makefile.com
#

# AES
AES_DIR= $(SRC)/common/crypto/aes
AES_COMMON_OBJS= aes_impl.o
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

# BIGNUM
BIGNUM_DIR= $(SRC)/common/bignum
BIGNUM_COMMON_OBJS= bignumimpl.o
BIGNUM_COMMON_SRC= $(BIGNUM_COMMON_OBJS:%.o=$(BIGNUM_DIR)/%.c)
BIGNUM_FLAGS= -I$(BIGNUM_DIR)

# Modes
MODES_DIR= $(SRC)/common/crypto/modes
MODES_COMMON_OBJS= modes.o ecb.o cbc.o ctr.o
MODES_COMMON_SRC= $(MODES_COMMON_OBJS:%.o=$(MODES_DIR)/%.c)


# Object setup
AES_OBJS= $(AES_COMMON_OBJS) $(AES_PSM_OBJS)
ARCFOUR_OBJS= $(ARCFOUR_COMMON_OBJS) $(ARCFOUR_PSM_OBJS)
BLOWFISH_OBJS= $(BLOWFISH_COMMON_OBJS) $(BLOWFISH_PSM_OBJS)
DES_OBJS= $(DES_COMMON_OBJS) $(DES_PSM_OBJS)
BIGNUM_OBJS= $(BIGNUM_COMMON_OBJS) $(BIGNUM_PSM_OBJS)
MODES_OBJS= $(MODES_COMMON_OBJS)

OBJECTS= $(AES_OBJS) $(ARCFOUR_OBJS) $(BIGNUM_OBJS) $(BLOWFISH_OBJS) \
	$(DES_OBJS) $(MODES_OBJS)

include $(SRC)/lib/Makefile.lib

# Source file setup
AES_SRC= $(AES_COMMON_SRC) $(AES_PSM_SRC)
ARCFOUR_SRC= $(ARCFOUR_COMMON_SRC) $(ARCFOUR_PSM_SRC)
BLOWFISH_SRC= $(BLOWFISH_COMMON_SRC) $(BLOWFISH_PSM_SRC)
DES_SRC= $(DES_COMMON_SRC) $(DES_PSM_SRC)
BIGNUM_SRC= $(BIGNUM_COMMON_SRC) $(BIGNUM_PSM_SRC)
MODES_SRC= $(MODES_COMMON_SRC)

SRCS=	$(AES_SRC) $(ARCFOUR_SRC) $(BIGNUM_SRC) $(BLOWFISH_SRC) $(DES_SRC) \
	$(MODES_SRC)

#
# Compiler settings
#

SRCDIR=	$(SRC)/lib/pkcs11/libsoftcrypto/common/
CRYPTODIR= $(SRC)/common/crypto/
MODESDIR= $(SRC)/uts/common/
ROOTLIBDIR= $(ROOT)/usr/lib
ROOTLIBDIR64= $(ROOT)/usr/lib/$(MACH64)
ROOTHWCAPDIR= $(ROOTLIBDIR)/libsoftcrypto

LIBS = $(DYNLIB)

CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CPPFLAGS += -I$(SRCDIR) -I$(CRYPTODIR) -I$(MODESDIR) -D_POSIX_PTHREAD_SEMANTICS
ASFLAGS = $(AS_PICFLAGS) -P -D__STDC__ -D_ASM
LINTFLAGS64 += -errchk=longptr64

all:	$(LIBS)

lint:	$(SRCS)
	$(LINT.c) $(LINTCHECKFLAGS) $(SRCS) $(LDLIBS)

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
	$(COMPILE.c) -o $@ $<
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
	$(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@ $(CHOWNLINK) $(CHGRPLINK)
INS.slink64 = $(RM) -r $@; \
	$(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) \
	$@ $(CHOWNLINK) $(CHGRPLINK)

$(SOFT_PSR_DIRS) \
$(SOFT_PSR64_DIRS):
	-$(INS.dir.root.bin)

$(SOFT_PSR_LINKS): $(SOFT_PSR_DIRS)
	-$(INS.slink6)

$(SOFT_PSR64_LINKS): $(SOFT_PSR64_DIRS)
	-$(INS.slink64)


include $(SRC)/lib/Makefile.targ
