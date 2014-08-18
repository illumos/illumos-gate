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
# Copyright (c) 2014, Joyent, Inc.  All rights reserved.
#

#
# This Makefile is shared between the libctf native build in tools and
# the libctf build here for the system.
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
	ctf_diff.o \
	ctf_lib.o \
	ctf_subr.o

OBJECTS = $(COMMON_OBJS) $(LIB_OBJS)
MAPFILEDIR = $(SRC)/lib/libctf

include $(SRC)/lib/Makefile.lib

SRCS = $(COMMON_OBJS:%.o=$(SRC)/common/ctf/%.c) $(LIB_OBJS:%.o=$(SRC)/lib/libctf/common/%.c)
LIBS = $(DYNLIB) $(LINTLIB)
LDLIBS = -lc

SRCDIR = $(SRC)/lib/libctf/common

CPPFLAGS += -I$(SRC)/lib/libctf/common -I$(SRC)/common/ctf -DCTF_OLD_VERSIONS
CFLAGS += $(CCVERBOSE)

CERRWARN += -_gcc=-Wno-uninitialized

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)
