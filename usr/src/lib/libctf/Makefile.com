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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = libctf.a
VERS = .1

COMMON_OBJS = \
	ctf_create.o \
	ctf_decl.o \
	ctf_error.o \
	ctf_hash.o \
	ctf_labels.o \
	ctf_lookup.o \
	ctf_open.o \
	ctf_types.o \
	ctf_util.o

LIB_OBJS = \
	ctf_lib.o \
	ctf_subr.o

OBJECTS = $(COMMON_OBJS) $(LIB_OBJS)

include ../../Makefile.lib
include ../../Makefile.rootfs

SRCS = $(COMMON_OBJS:%.o=../../../common/ctf/%.c) $(LIB_OBJS:%.o=../common/%.c)
LIBS = $(DYNLIB) $(LINTLIB)

SRCDIR = ../common

CPPFLAGS += -I../common -I../../../common/ctf -DCTF_OLD_VERSIONS
CFLAGS += $(CCVERBOSE)
LDLIBS += -lc

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

objs/%.o pics/%.o: ../../../common/ctf/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
