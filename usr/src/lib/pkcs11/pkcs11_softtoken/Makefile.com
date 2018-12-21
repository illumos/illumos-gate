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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2018, Joyent, Inc.
#
# lib/pkcs11/pkcs11_softtoken/Makefile.com
#

LIBRARY = pkcs11_softtoken.a
VERS= .1

LCL_OBJECTS = \
	softGeneral.o		\
	softSlotToken.o	\
	softSession.o		\
	softObject.o		\
	softDigest.o		\
	softSign.o		\
	softVerify.o		\
	softDualCrypt.o	\
	softKeys.o		\
	softRand.o		\
	softSessionUtil.o	\
	softDigestUtil.o	\
	softAttributeUtil.o	\
	softObjectUtil.o	\
	softDESCrypt.o		\
	softEncrypt.o		\
	softDecrypt.o		\
	softEncryptUtil.o	\
	softDecryptUtil.o	\
	softSignUtil.o		\
	softVerifyUtil.o	\
	softMAC.o		\
	softRSA.o		\
	softKeysUtil.o		\
	softARCFourCrypt.o	\
	softDSA.o		\
	softDH.o		\
	softAESCrypt.o		\
	softKeystore.o		\
	softKeystoreUtil.o	\
	softSSL.o		\
	softASN1.o		\
	softBlowfishCrypt.o	\
	softEC.o

ASFLAGS = $(AS_PICFLAGS) -P -D__STDC__ -D_ASM $(CPPFLAGS)

ECC_COBJECTS = \
	ec.o ec2_163.o ec2_mont.o ecdecode.o ecl_mult.o ecp_384.o \
	ecp_jac.o ec2_193.o ecl.o ecp_192.o ecp_521.o \
	ecp_jm.o ec2_233.o ecl_curve.o ecp_224.o ecp_aff.o ecp_mont.o \
	ec2_aff.o ec_naf.o ecl_gf.o ecp_256.o oid.o secitem.o \
	ec2_test.o ecp_test.o

MPI_COBJECTS = mp_gf2m.o mpi.o mplogic.o mpmontg.o mpprime.o
RNG_COBJECTS = fips_random.o

ECC_OBJECTS = $(ECC_COBJECTS) $(ECC_PSR_OBJECTS)
MPI_OBJECTS = $(MPI_COBJECTS) $(MPI_PSR_OBJECTS)
RNG_OBJECTS = $(RNG_COBJECTS)
BER_OBJECTS = bprint.o decode.o encode.o io.o

OBJECTS = \
	$(LCL_OBJECTS)		\
	$(MPI_OBJECTS)		\
	$(RNG_OBJECTS)		\
	$(BIGNUM_OBJECTS)       \
	$(BER_OBJECTS)		\
	$(ECC_OBJECTS)

AESDIR=         $(SRC)/common/crypto/aes
BLOWFISHDIR=    $(SRC)/common/crypto/blowfish
ARCFOURDIR=     $(SRC)/common/crypto/arcfour
DESDIR=         $(SRC)/common/crypto/des
DHDIR=		$(SRC)/common/crypto/dh
DSADIR=		$(SRC)/common/crypto/dsa
ECCDIR=		$(SRC)/common/crypto/ecc
MPIDIR=		$(SRC)/common/mpi
RSADIR=		$(SRC)/common/crypto/rsa
RNGDIR=		$(SRC)/common/crypto/rng
SHA1DIR=	$(SRC)/common/crypto/sha1
SHA2DIR=	$(SRC)/common/crypto/sha2
BIGNUMDIR=	$(SRC)/common/bignum
PADDIR=		$(SRC)/common/crypto/padding
BERDIR=		../../../libldap5/sources/ldap/ber

include $(SRC)/lib/Makefile.lib

#	set signing mode
POST_PROCESS_SO +=	; $(ELFSIGN_CRYPTO)

SRCDIR= ../common

SRCS =	\
	$(LCL_OBJECTS:%.o=$(SRCDIR)/%.c) \
	$(MPI_COBJECTS:%.o=$(MPIDIR)/%.c) \
	$(ECC_COBJECTS:%.o=$(ECCDIR)/%.c) \
	$(RNG_COBJECTS:%.o=$(RNGDIR)/%.c)

# libelfsign needs a static pkcs11_softtoken
LIBS    =       $(DYNLIB)
LDLIBS  +=      -lc -lmd -lcryptoutil -lsoftcrypto -lgen

CSTD =	$(CSTD_GNU99)
C99LMODE = -Xc99=%all

CFLAGS	+=      $(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-empty-body

CPPFLAGS += -I$(AESDIR) -I$(BLOWFISHDIR) -I$(ARCFOURDIR) -I$(DESDIR) \
	    -I$(DHDIR) -I$(DSADIR) -I$(ECCDIR) -I$(SRC)/common/crypto \
	    -I$(MPIDIR) -I$(RSADIR) -I$(RNGDIR) \
	    -I$(SHA1DIR) -I$(SHA2DIR) -I$(SRCDIR) \
	    -I$(BIGNUMDIR) -I$(PADDIR) -D_POSIX_PTHREAD_SEMANTICS \
	    -DMP_API_COMPATIBLE -DNSS_ECC_MORE_THAN_SUITE_B

LINTFLAGS64 += -errchk=longptr64

ROOTLIBDIR=     $(ROOT)/usr/lib/security
ROOTLIBDIR64=   $(ROOT)/usr/lib/security/$(MACH64)

LINTSRC = \
	$(LCL_OBJECTS:%.o=$(SRCDIR)/%.c) \
	$(RNG_COBJECTS:%.o=$(RNGDIR)/%.c)

.KEEP_STATE:

all:	$(LIBS)

lint:	$$(LINTSRC)
	$(LINT.c) $(LINTCHECKFLAGS) $(LINTSRC) $(LDLIBS)

pics/%.o:	$(BERDIR)/%.c
	$(COMPILE.c) -o $@ $< -D_SOLARIS_SDK -I$(BERDIR) \
		-I../../../libldap5/include/ldap
	$(POST_PROCESS_O)

pics/%.o:	$(ECCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(MPIDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(RNGDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
