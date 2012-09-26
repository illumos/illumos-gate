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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY	=	libwanbootutil.a
VERS =		.1

# List of locally located modules.
LOC_DIR =	../common
LOC_OBJS =	key_xdr.o \
		key_util.o \
		wbio.o
LOC_SRCS =	$(LOC_OBJS:%.o=$(LOC_DIR)/%.c)

# The crypto modules are located under usr/src/common.
CRYPTO_DIR =	$(SRC)/common/net/wanboot/crypt
CRYPTO_OBJS =	hmac_sha1.o \
		aes.o \
		des3.o \
		des.o \
		cbc.o
CRYPTO_SRCS =	$(CRYPTO_OBJS:%.o=$(CRYPTO_DIR)/%.c)

# Together the local and crypto modules makeup the entire wad.
OBJECTS	=	$(LOC_OBJS) $(CRYPTO_OBJS)

include $(SRC)/lib/Makefile.lib

LIBS +=		$(LINTLIB)
LDLIBS +=	-lc -lnsl -lmd

# Must override SRCS from Makefile.lib since sources have
# multiple source directories.
SRCS =		$(LOC_SRCS) $(CRYPTO_SRCS)

# Must define location of lint library source.
SRCDIR =	$(LOC_DIR)
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

# Library includes sources created via rpcgen. And rpcgen unfortunately
# created unused function variables.
LINTFLAGS +=	-erroff=E_FUNC_VAR_UNUSED

CPPFLAGS +=	-I$(CRYPTO_DIR)

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-uninitialized

install:	all

all:		$(LIBS)

lint:		lintcheck


# Define rule for local modules.
objs/%.o pics/%.o:	$(LOC_DIR)/%.c
			$(COMPILE.c) -o $@ $<
			$(POST_PROCESS_O)

# Define rule for crypto modules.
objs/%.o pics/%.o:	$(CRYPTO_DIR)/%.c
			$(COMPILE.c) -o $@ $<
			$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
