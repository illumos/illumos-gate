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

LIBRARY =	sn1_brand.a
VERS	=	.1
COBJS	=	sn1_brand.o
ASOBJS	=	sn1_handler.o
OBJECTS	=	$(COBJS) $(ASOBJS)

include ../../../Makefile.lib

LIBS =		$(DYNLIB)
CSRCS	=	$(COBJS:%o=../common/%c)
ASSRCS	=	$(ASOBJS:%o=$(ISASRCDIR)/%s)
SRCS	=	$(CSRCS) $(ASSRCS)
SRCDIR	=	../common

LDLIBS +=	-Wl,-esn1_init -lc
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../common
DYNFLAGS +=	$(BLOCAL) $(ZNOVERSION)
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM -I../common

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ

