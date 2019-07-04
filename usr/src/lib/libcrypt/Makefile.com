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

LIBRARY=	libcrypt.a
VERS=		.1

OBJECTS=  \
	cryptio.o \
	des.o \
	des_crypt.o \
	des_encrypt.o \
	des_decrypt.o \
	des_soft.o

include ../../Makefile.lib

SRCDIR=		../common

LIBS=		$(DYNLIB)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../inc -I../../common/inc -I../../libgen/inc
LDLIBS +=       -lgen -lc

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

.KEEP_STATE:

all: $(LIBS)


COMPATLINKS =	usr/lib/libcrypt_i.so$(VERS) \
		usr/lib/libcrypt_i.so \
		usr/lib/libcrypt_d.so$(VERS) \
		usr/lib/libcrypt_d.so

COMPATLINKS64 =	usr/lib/$(MACH64)/libcrypt_i.so$(VERS) \
		usr/lib/$(MACH64)/libcrypt_i.so \
		usr/lib/$(MACH64)/libcrypt_d.so$(VERS) \
		usr/lib/$(MACH64)/libcrypt_d.so

$(ROOT)/usr/lib/libcrypt_i.so$(VERS) := COMPATLINKTARGET= libcrypt.so$(VERS)
$(ROOT)/usr/lib/libcrypt_i.so := COMPATLINKTARGET= libcrypt.so
$(ROOT)/usr/lib/libcrypt_d.so$(VERS) := COMPATLINKTARGET= libcrypt.so$(VERS)
$(ROOT)/usr/lib/libcrypt_d.so := COMPATLINKTARGET= libcrypt.so

$(ROOT)/usr/lib/$(MACH64)/libcrypt_i.so$(VERS) := COMPATLINKTARGET= libcrypt.so$(VERS)
$(ROOT)/usr/lib/$(MACH64)/libcrypt_i.so := COMPATLINKTARGET= libcrypt.so
$(ROOT)/usr/lib/$(MACH64)/libcrypt_d.so$(VERS) := COMPATLINKTARGET= libcrypt.so$(VERS)
$(ROOT)/usr/lib/$(MACH64)/libcrypt_d.so := COMPATLINKTARGET= libcrypt.so

include ../../Makefile.targ
