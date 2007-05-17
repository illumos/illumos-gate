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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = libcrypto_extra.a

OBJECTS = sunw.o							\
	\
	aes/aes_cbc.o	aes/aes_cfb.o	aes/aes_core.o	aes/aes_ctr.o	\
	aes/aes_ecb.o	aes/aes_misc.o	aes/aes_ofb.o			\
	\
	bf/bf_skey.o	bf/bf_ecb.o	bf/bf_cfb64.o	bf/bf_ofb64.o	\
	\
	evp/e_aes.o	evp/e_bf.o	evp/e_rc4.o	evp/c_allc.o	\
	evp/e_old.o							\
	\
	rc4/rc4_enc.o	rc4/rc4_skey.o					\
	\
	$(BF_ENC)							\
	$(RC4_ENC)


BF_ENC =	bf/bf_enc.o

include ../../Makefile.com

# There should be a mapfile here
MAPFILES =

CFLAGS +=	-K PIC -DCRYPTO_UNLIMITED
CFLAGS64 +=	-K PIC -DCRYPTO_UNLIMITED
ZDEFS =		$(ZNODEFS)

SONAME =        $(LIBRARY:.a=.so)$(VERS)

LIBS =		$(DYNLIB)
SRCDIR =	$(OPENSSL_SRC)/crypto

$(LINTLIB) := 	SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all:		subdirs $(LIBS)

lint:		lintcheck

subdirs:	FRC
	@mkdir -p \
		pics/aes \
		pics/bf \
		pics/evp \
		pics/rc4 \

FRC:

pics/%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
