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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libsoftcrypto.a
VERS =		.1

include		../Makefile.com

include		$(SRC)/lib/Makefile.lib

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

# Sources need to be redefined after Makefile.lib inclusion.
SRCS =		$(AES_SRC) $(ARCFOUR_SRC) $(BIGNUM_SRC) $(BLOWFISH_SRC) \
		$(DES_SRC) $(MODES_SRC) $(DH_SRC) $(DSA_SRC) $(RSA_SRC) \
		$(PAD_SRC)

SRCDIR =	$(SRC)/lib/pkcs11/libsoftcrypto/common

LIBS =		$(DYNLIB)
MAPFILEDIR =	../common

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(CRYPTODIR) -I$(UTSDIR) -D_POSIX_PTHREAD_SEMANTICS
LDLIBS +=	-lcryptoutil -lc

# Symbol capabilities objects are i386.
EXTPICS =	../capabilities/intel/i386/pics/symcap.o

.KEEP_STATE:

all:		$(LIBS)

install:	all $(ROOTLIBS) $(ROOTLINKS)

include		../Makefile.targ
