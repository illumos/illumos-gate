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
# lib/pkcs11/pkcs11_softtoken/Makefile.com
#

LIBRARY = pkcs11_softtoken.a
VERS= .1

LCL_OBJECTS = \
	softGeneral.o 		\
	softSlotToken.o 	\
	softSession.o 		\
	softObject.o 		\
	softDigest.o	 	\
	softSign.o 		\
	softVerify.o 		\
	softDualCrypt.o 	\
	softKeys.o 		\
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
	softRandUtil.o		\
	softKeysUtil.o		\
	softARCFourCrypt.o	\
	softDSA.o		\
	softDH.o		\
	softAESCrypt.o		\
	softCrypt.o		\
	softKeystore.o		\
	softKeystoreUtil.o	\
	softSSL.o		\
	softASN1.o		\
	softBlowfishCrypt.o	\
	softEC.o

ASFLAGS = $(AS_PICFLAGS) -P -D__STDC__ -D_ASM $(CPPFLAGS)

AES_COBJECTS = aes_impl.o
ARCFOUR_COBJECTS = arcfour_crypt.o
BLOWFISH_COBJECTS = blowfish_impl.o
DES_COBJECTS = des_impl.o des_ks.o

ECC_COBJECTS = \
	ec.o ec2_163.o ec2_mont.o ecdecode.o ecl_mult.o ecp_384.o \
	ecp_jac.o ec2_193.o ecl.o ecp_192.o ecp_521.o \
	ecp_jm.o ec2_233.o ecl_curve.o ecp_224.o ecp_aff.o ecp_mont.o \
	ec2_aff.o ec_naf.o ecl_gf.o ecp_256.o oid.o secitem.o \
	ec2_test.o ecp_test.o

MODES_COBJECTS = modes.o ecb.o cbc.o ctr.o
MPI_COBJECTS = mp_gf2m.o mpi.o mplogic.o mpmontg.o mpprime.o

RSA_COBJECTS = rsa_impl.o
BIGNUM_COBJECTS = bignumimpl.o

AES_OBJECTS = $(AES_COBJECTS) $(AES_PSR_OBJECTS)
ARCFOUR_OBJECTS = $(ARCFOUR_COBJECTS) $(ARCFOUR_PSR_OBJECTS)
BLOWFISH_OBJECTS = $(BLOWFISH_COBJECTS) $(BLOWFISH_PSR_OBJECTS)
DES_OBJECTS = $(DES_COBJECTS) $(DES_PSR_OBJECTS)
ECC_OBJECTS = $(ECC_COBJECTS) $(ECC_PSR_OBJECTS)
MODES_OBJECTS = $(MODES_COBJECTS) $(MODES_PSR_OBJECTS)
MPI_OBJECTS = $(MPI_COBJECTS) $(MPI_PSR_OBJECTS)
RSA_OBJECTS = $(RSA_COBJECTS) $(RSA_PSR_OBJECTS)
BIGNUM_OBJECTS = $(BIGNUM_COBJECTS) $(BIGNUM_PSR_OBJECTS)

BER_OBJECTS = bprint.o decode.o encode.o io.o

# Sparc userland uses a floating-point implementation of
# Montgomery multiply.  So, USE_FLOATING_POINT is defined here
# for Sparc targets.
#
# x86 does not use floating-point for the kernel or userland.
#
# Sparc has only one integer implementation of big_mul_add_vec()
# and friends, so these functions are called directly.
# So, HWCAP (HardWare CAPabilities) is not defined for Sparc.
#
# x86 has multiple integer implementations to choose from.
# Hardware features are tested at run time, just once,
# on first use.  So, big_mul_add_vec() and friends must be
# called through a function pointer.
#
# AMD64 has a 64x64->128 bit multiply instruction, which makes
# things even faster than i386 SSE2 instructions.  Since there
# is no run-time testing of features, as there is for SSE2,
# there is no need to call big_mul_add_vec() and friends through
# functions pointers, and so HWCAP is not defined.
#
# For now i386 and amd64 use the C code version of mont_mulf

OBJECTS = \
	$(LCL_OBJECTS)		\
	$(AES_OBJECTS)		\
	$(BLOWFISH_OBJECTS)	\
	$(ARCFOUR_OBJECTS)	\
	$(DES_OBJECTS)		\
	$(MODES_OBJECTS)	\
	$(MPI_OBJECTS)		\
	$(RSA_OBJECTS)		\
	$(BIGNUM_OBJECTS)	\
	$(BER_OBJECTS)		\
	$(ECC_OBJECTS)

AESDIR=		$(SRC)/common/crypto/aes
BLOWFISHDIR=	$(SRC)/common/crypto/blowfish
ARCFOURDIR=	$(SRC)/common/crypto/arcfour
DESDIR=		$(SRC)/common/crypto/des
ECCDIR=		$(SRC)/common/crypto/ecc
MODESDIR=	$(SRC)/common/crypto/modes
MPIDIR=		$(SRC)/common/mpi
RSADIR=		$(SRC)/common/crypto/rsa
BIGNUMDIR=	$(SRC)/common/bignum
BERDIR=		../../../libldap5/sources/ldap/ber

include $(SRC)/lib/Makefile.lib

#	set signing mode
POST_PROCESS_SO +=	; $(ELFSIGN_CRYPTO)

SRCDIR= ../common

SRCS =	\
	$(LCL_OBJECTS:%.o=$(SRCDIR)/%.c) \
	$(AES_COBJECTS:%.o=$(AESDIR)/%.c) \
	$(BLOWFISH_COBJECTS:%.o=$(BLOWFISHDIR)/%.c) \
	$(ARCFOUR_COBJECTS:%.o=$(ARCFOURDIR)/%.c) \
	$(DES_COBJECTS:%.o=$(DESDIR)/%.c) \
	$(MODES_COBJECTS:%.o=$(MODESDIR)/%.c) \
	$(MPI_COBJECTS:%.o=$(MPIDIR)/%.c) \
	$(RSA_COBJECTS:%.o=$(RSADIR)/%.c) \
	$(BIGNUM_COBJECTS:%.o=$(BIGNUMDIR)/%.c) \
	$(BIGNUM_PSR_SRCS) \
	$(ECC_COBJECTS:%.o=$(ECCDIR)/%.c)

# libelfsign needs a static pkcs11_softtoken
LIBS    =       $(DYNLIB)
LDLIBS  +=      -lc -lmd -lcryptoutil

CFLAGS 	+=      $(CCVERBOSE)
CPPFLAGS += -I$(AESDIR) -I$(BLOWFISHDIR) -I$(ARCFOURDIR) -I$(DESDIR) \
	    -I$(ECCDIR) -I$(SRC)/common/crypto -I$(MPIDIR) -I$(RSADIR) \
	    -I$(SRCDIR) -I$(BIGNUMDIR) -D_POSIX_PTHREAD_SEMANTICS \
	    -DMP_API_COMPATIBLE -DNSS_ECC_MORE_THAN_SUITE_B

LINTFLAGS64 += -errchk=longptr64

ROOTLIBDIR=     $(ROOT)/usr/lib/security
ROOTLIBDIR64=   $(ROOT)/usr/lib/security/$(MACH64)

LINTSRC = \
	$(AES_COBJECTS:%.o=$(AESDIR)/%.c) \
	$(ARCFOUR_COBJECTS:%.o=$(ARCFOURDIR)/%.c) \
	$(BIGNUM_COBJECTS:%.o=$(BIGNUMDIR)/%.c) \
	$(BIGNUM_PSR_SRCS) \
	$(BLOWFISH_COBJECTS:%.o=$(BLOWFISHDIR)/%.c) \
	$(DES_COBJECTS:%.o=$(DESDIR)/%.c) \
	$(LCL_OBJECTS:%.o=$(SRCDIR)/%.c) \
	$(MODES_COBJECTS:%.o=$(MODESDIR)/%.c) \
	$(RSA_COBJECTS:%.o=$(RSADIR)/%.c)

.KEEP_STATE:

all:	$(LIBS)

lint:	$$(LINTSRC)
	$(LINT.c) $(LINTCHECKFLAGS) $(LINTSRC) $(LDLIBS)

pics/%.o:	$(AESDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(ARCFOURDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(BERDIR)/%.c
	$(COMPILE.c) -o $@ $< -D_SOLARIS_SDK -I$(BERDIR) \
		-I../../../libldap5/include/ldap
	$(POST_PROCESS_O)

pics/%.o:	$(BIGNUMDIR)/%.c
	$(COMPILE.c) -o $@ $(BIGNUM_CFG) $<
	$(POST_PROCESS_O)

pics/%.o:	$(BLOWFISHDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(DESDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(ECCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(MODESDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(MPIDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(RSADIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
