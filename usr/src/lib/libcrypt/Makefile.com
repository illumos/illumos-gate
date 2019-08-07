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

LIBS=		$(DYNLIB) $(LINTLIB)

$(LINTLIB):=	SRCS=$(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../inc -I../../common/inc -I../../libgen/inc
LDLIBS +=       -lgen -lc

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

$(ROOTLINKS) := INS.liblink = \
	$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@; \
		cd $(ROOTLIBDIR); \
		$(RM) libcrypt_i.so$(VERS) libcrypt_i.so ;\
		$(RM) libcrypt_d.so$(VERS) libcrypt_d.so ;\
		$(SYMLINK) libcrypt.so$(VERS) libcrypt_i.so$(VERS); \
		$(SYMLINK) libcrypt.so libcrypt_i.so; \
		$(SYMLINK) libcrypt.so$(VERS) libcrypt_d.so$(VERS); \
		$(SYMLINK) libcrypt.so libcrypt_d.so;

$(ROOTLINKS64) := INS.liblink64 = \
	$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@; \
		cd $(ROOTLIBDIR64); \
		$(RM) libcrypt_i.so$(VERS) libcrypt_i.so ;\
		$(RM) libcrypt_d.so$(VERS) libcrypt_d.so ;\
		$(SYMLINK) libcrypt.so$(VERS) libcrypt_i.so$(VERS); \
		$(SYMLINK) libcrypt.so libcrypt_i.so; \
		$(SYMLINK) libcrypt.so$(VERS) libcrypt_d.so$(VERS); \
		$(SYMLINK) libcrypt.so libcrypt_d.so;


