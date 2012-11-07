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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 

LIBRARY = libssl.a

LOCOBJS = stubs.o

COMPOBJS = c_zlib.o

CMNOBJS = s3_both.o	s3_clnt.o	s3_enc.o	s3_lib.o	\
	s3_pkt.o							\
	\
	ssl_algs.o	ssl_cert.o	ssl_ciph.o	ssl_err.o	\
	ssl_err2.o	ssl_lib.o	ssl_rsa.o	ssl_sess.o	\
	\
	$($(MACH)_OBJECTS)

OBJECTS = $(LOCOBJS) $(COMPOBJS) $(CMNOBJS)

include ../Makefile.com

CMNDIR	= $(TOPDIR)/common/openssl/ssl
COMPDIR	= $(TOPDIR)/common/openssl/crypto/comp

SRCS	= $(LOCOBJS:%.o=$(SRCDIR)/%.c) \
	$(COMPOBJS:%.o=$(COMPDIR)/%.c) \
	$(CMNOBJS:%.o=$(CMNDIR)/%.c)

CPPFLAGS += $(OPENSSL_BUILD_CPPFLAGS) $(SOCKCPPFLAGS)
$(LINTLIB) :=	SRCS = $(CMNDIR)/$(LINTSRC)

CERRWARN += -_gcc=-Wno-unused-value

objs/%.o: $(TOPDIR)/common/openssl/crypto/comp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../Makefile.targ
