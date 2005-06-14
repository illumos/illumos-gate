#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for the nisaddcred program
#

PROG=	nisaddcred

SRCS= \
	nisaddcred.c   makelocalcred.c  makedescred.c \
	makersacred.c  makekerbcred.c	makedhextcred.c
OBJS= \
	nisaddcred.o   makelocalcred.o  makedescred.o \
	makersacred.o  makekerbcred.o	makedhextcred.o
UTIL= ../util.a

include $(SRC)/cmd/Makefile.cmd

CPPFLAGS += -I$(SRC)/lib/libnsl/include
CFLAGS += -I$(ROOT)/usr/include 
LDLIBS += -lnsl $(UTIL)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

lint:	lint_SRCS

clean:
	$(RM) $(OBJS)

$(UTIL):
	@cd ..; pwd; $(MAKE) util.a

$(PROG): $(OBJS) $(UTIL)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include $(SRC)/cmd/Makefile.targ
