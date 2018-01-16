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

LIBRARY=	kmf_openssl.a
VERS=		.1

OBJECTS=	openssl_spi.o compat.o

include	$(SRC)/lib/Makefile.lib

LIBLINKS=	$(DYNLIB:.so.1=.so)
KMFINC=		-I../../../include -I../../../ber_der/inc

BERLIB=		-lkmf -lkmfberder
BERLIB64=	$(BERLIB)

OPENSSLLIBS=	$(BERLIB) -lcrypto -lcryptoutil -lc
OPENSSLLIBS64=	$(BERLIB64) -lcrypto -lcryptoutil -lc

LINTSSLLIBS	= $(BERLIB) -lcrypto -lcryptoutil -lc
LINTSSLLIBS64	= $(BERLIB64) -lcrypto -lcryptoutil -lc

# Because of varying openssl implementations, we need to not have lint
# complain if we're being liberal in our suppression directives.
LINTFLAGS	+=	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTFLAGS64	+=	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

SRCDIR=		../common
INCDIR=		../../include

CFLAGS		+=	$(CCVERBOSE) 
CPPFLAGS	+=	-D_REENTRANT $(KMFINC) \
			-I$(INCDIR) -I$(ADJUNCT_PROTO)/usr/include/libxml2

CERRWARN	+=	-_gcc=-Wno-unused-label
CERRWARN	+=	-_gcc=-Wno-unused-value
CERRWARN	+=	-_gcc=-Wno-uninitialized

PICS=	$(OBJECTS:%=pics/%)

lint:=	OPENSSLLIBS=	$(LINTSSLLIBS)
lint:=	OPENSSLLIBS64=	$(LINTSSLLIBS64)

LDLIBS32 	+=	$(OPENSSLLIBS)

ROOTLIBDIR=	$(ROOTFS_LIBDIR)/crypto
ROOTLIBDIR64=	$(ROOTFS_LIBDIR)/crypto/$(MACH64)

.KEEP_STATE:

LIBS	=	$(DYNLIB)
all:	$(DYNLIB) $(LINTLIB)

lint: lintcheck

FRC:

include $(SRC)/lib/Makefile.targ
