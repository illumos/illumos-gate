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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

MACHCOBJS = libv12n.o

CMNOBJS=	mdesc_findname.o	\
		mdesc_findnodeprop.o	\
		mdesc_fini.o		\
		mdesc_getpropval.o	\
		mdesc_getpropstr.o	\
		mdesc_init_intern.o	\
		mdesc_nodecount.o	\
		mdesc_rootnode.o	\
		mdesc_scandag.o

OBJS += $(CMNOBJS)

include ../Makefile.com
include ../../Makefile.lib.64

CSTD =	$(CSTD_GNU99)

LDLIBS += -luuid -lc

CPPFLAGS += -I. -I$(SRC)/lib/libds/common -I$(SRC)/cmd/ldmad

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)

pics/%.o: $(SRC)/common/mdesc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
