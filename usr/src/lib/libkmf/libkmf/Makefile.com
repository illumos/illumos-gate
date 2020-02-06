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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2018, Joyent, Inc.
#

LIBRARY= libkmf.a
VERS= .1

OBJECTS= \
	algoid.o \
	certgetsetop.o \
	certop.o \
	client.o \
	csrcrlop.o \
	generalop.o \
	keyop.o \
	kmfoids.o \
	mapping.o \
	pem_encode.o \
	pk11tokens.o \
	policy.o \
	pk11keys.o \
	rdn_parser.o

BERDERLIB=      -lkmfberder
BERDERLIB64=    -lkmfberder

CRYPTOUTILLIB=	 -lcryptoutil
CRYPTOUTILLIB64= -lcryptoutil

include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.rootfs

SRCDIR=	../common
INCDIR=	../../include

LIBS=	$(DYNLIB)

LDLIBS	+=	$(BERDERLIB) $(CRYPTOUTILLIB) -lmd -lpkcs11 -lnsl -lsocket -lc
LDLIBS	+=	-lcustr
NATIVE_LIBS +=	libxml2.so

# DYNLIB libraries do not have lint libs and are not linted
$(DYNLIB) :=    LDLIBS += -lxml2
$(DYNLIB64) :=  LDLIBS64 += -lxml2

CPPFLAGS	+=	-I$(INCDIR) -I$(ADJUNCT_PROTO)/usr/include/libxml2 \
			-I../../ber_der/inc -I$(SRCDIR)

CERRWARN	+=	-_gcc=-Wno-parentheses
CERRWARN	+=	-_gcc=-Wno-switch
CERRWARN	+=	-_gcc=-Wno-type-limits
CERRWARN	+=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

.KEEP_STATE:

all:    $(LIBS)

include $(SRC)/lib/Makefile.targ
