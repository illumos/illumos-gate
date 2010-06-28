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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY= pkcs11_kms.a
VERS= .1

CORE_OBJECTS= \
	kmsAESCrypt.o		\
	kmsAttributeUtil.o	\
	kmsDecrypt.o		\
	kmsDigest.o	 	\
	kmsDualCrypt.o		\
	kmsEncrypt.o		\
	kmsGeneral.o		\
	kmsKeys.o 		\
	kmsKeystoreUtil.o	\
	kmsObject.o 		\
	kmsObjectUtil.o		\
	kmsRand.o		\
	kmsSession.o		\
	kmsSessionUtil.o	\
	kmsSign.o 		\
	kmsSlottable.o		\
	kmsSlotToken.o		\
	kmsVerify.o

OBJECTS= $(CORE_OBJECTS)	

AESDIR=	$(SRC)/common/crypto/aes
KMSAGENTDIR= $(SRC)/lib/libkmsagent/common

include $(SRC)/lib/Makefile.lib

#	set signing mode
POST_PROCESS_SO	+=	; $(ELFSIGN_CRYPTO)

SRCDIR=		../common
CORESRCS =	$(CORE_OBJECTS:%.o=$(SRCDIR)/%.c)

LIBS	=	$(DYNLIB)
LDLIBS  +=      -lc -lcryptoutil -lsoftcrypto -lmd -lavl -lkmsagent

CFLAGS  +=      $(CCVERBOSE)

CPPFLAGS +=	-DUSESOLARIS_AES -DKMSUSERPKCS12

ROOTLIBDIR=     $(ROOT)/usr/lib/security
ROOTLIBDIR64=   $(ROOT)/usr/lib/security/$(MACH64)

lint \
pics/kmsAESCrypt.o \
pics/kmsEncrypt.o \
pics/kmsDecrypt.o \
pics/kmsSlotToken.o \
pics/kmsKeystoreUtil.o \
pics/kmsAttributeUtil.o := CPPFLAGS += -I$(AESDIR) -I$(SRC)/common/crypto

CPPFLAGS += -I$(KMSAGENTDIR)

.KEEP_STATE:

all:	$(LIBS)

#
# -lkmsagent is not here because it is C++ and we don't lint C++ code.
#
LINTLDLIBS =  -lc -lcryptoutil -lavl -lmd -lsoftcrypto

LINTFLAGS64 += -errchk=longptr64 -errtags=yes

lintcheck := SRCS = $(CORESRCS)
lintcheck := LDLIBS = -L$(ROOT)/lib -L$(ROOT)/usr/lib $(LINTLDLIBS)

lintother: $$(OSRCS)
	$(LINT.c) $(LINTCHECKFLAGS) $(OSRCS) $(LINTLDLIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
