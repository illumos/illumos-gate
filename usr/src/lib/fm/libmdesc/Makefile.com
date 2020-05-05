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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY = libmdesc.a
VERS = .1

LIBSRCS =	\
	mdesc_fini.c \
	mdesc_findname.c \
	mdesc_findnodeprop.c \
	mdesc_getproparcs.c \
	mdesc_getpropdata.c \
	mdesc_getpropstr.c \
	mdesc_getpropval.c \
	mdesc_init_intern.c \
	mdesc_nodecount.c \
	mdesc_scandag.c \
	mdesc_walkdag.c

OBJECTS = $(LIBSRCS:%.c=%.o)

include ../../../Makefile.lib
include ../../Makefile.lib

SRCS = $(LIBSRCS:%.c=$(SRC)/common/mdesc/%.c)

LIBS = $(DYNLIB)

SRCDIR =	../common

CPPFLAGS += -I../common -I.
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS64)
LDLIBS += -lc


.KEEP_STATE:

all: $(LIBS)

pics/%.o: $(SRC)/common/mdesc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ
include ../../Makefile.targ
