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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= libpkcs11.a
VERS= .1


OBJECTS= \
	metaAttrManager.o	\
	metaCrypt.o		\
	metaDigest.o		\
	metaDualCrypt.o		\
	metaGeneral.o		\
	metaKeys.o		\
	metaMechManager.o	\
	metaObject.o		\
	metaObjectManager.o	\
	metaRand.o		\
	metaSession.o		\
	metaSessionManager.o	\
	metaSign.o		\
	metaSlotManager.o	\
	metaSlotToken.o		\
	metaUtil.o		\
	metaVerify.o		\
	pkcs11General.o		\
	pkcs11SlotToken.o	\
	pkcs11Session.o		\
	pkcs11Object.o		\
	pkcs11Crypt.o		\
	pkcs11Digest.o		\
	pkcs11Sign.o		\
	pkcs11Verify.o		\
	pkcs11DualCrypt.o	\
	pkcs11Keys.o		\
	pkcs11Rand.o		\
	pkcs11Slottable.o	\
	pkcs11Conf.o		\
	pkcs11Sessionlist.o	\
	pkcs11SUNWExtensions.o

include ../../../Makefile.lib

SRCDIR=		../common
INCDIR=		../../include

LIBS =		$(DYNLIB)
LDLIBS +=	-lcryptoutil -lc

CFLAGS	+=	$(CCVERBOSE)
CPPFLAGS +=	-I$(INCDIR) -I$(SRCDIR) -D_REENTRANT


CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

.KEEP_STATE:

all:	$(LIBS)


include $(SRC)/lib/Makefile.targ
