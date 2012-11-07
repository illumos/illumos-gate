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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for KMF Plugins
#

LIBRARY=	kmf_pkcs11.a
VERS=		.1

PKCS11_COBJECTS = pkcs11_spi.o
BIGNUM_COBJECTS = bignumimpl.o
OBJECTS = $(PKCS11_COBJECTS) $(BIGNUM_COBJECTS)

include	$(SRC)/lib/Makefile.lib

LIBLINKS=	$(DYNLIB:.so.1=.so)
KMFINC=		-I../../../include -I../../../ber_der/inc

PKCS11LIBS=	-lkmf -lkmfberder -lmd -lpkcs11 -lcryptoutil -lc

BIGNUMDIR=      $(SRC)/common/bignum

SRCDIR=		../common
INCDIR=		../../include

SRCS =  \
        $(PKCS11_COBJECTS:%.o=$(SRCDIR)/%.c) \
        $(BIGNUM_COBJECTS:%.o=$(BIGNUMDIR)/%.c)


CFLAGS		+=	$(CCVERBOSE)
CPPFLAGS	+=	-D_REENTRANT $(KMFINC) -I$(INCDIR) \
			-I$(ADJUNCT_PROTO)/usr/include/libxml2 -I$(BIGNUMDIR)
LINTFLAGS64	+=	-errchk=longptr64

CERRWARN	+=	-_gcc=-Wno-unused-label

PICS=	$(OBJECTS:%=pics/%)

LDLIBS	+=	$(PKCS11LIBS)

ROOTLIBDIR=	$(ROOTFS_LIBDIR)/crypto
ROOTLIBDIR64=	$(ROOTFS_LIBDIR)/crypto/$(MACH64)

.KEEP_STATE:

LIBS	=	$(DYNLIB)

all:	$(LIBS) $(LINTLIB)

lint: lintcheck

FRC:

pics/%.o:	$(BIGNUMDIR)/%.c
	$(COMPILE.c) -o $@ $(BIGNUM_CFG) $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
