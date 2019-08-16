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
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= expr
XPG4PROG= expr
XPG6PROG= expr

EXPROBJ= exprobjs/expr.o exprobjs/compile.o
XPG4EXPROBJ= exprobjs.xpg4/expr.o exprobjs.xpg4/compile.o
XPG6EXPROBJ= exprobjs.xpg6/expr.o exprobjs.xpg6/compile.o

OBJS= $(EXPROBJ) $(XPG4EXPROBJ) $(XPG6EXPROBJ)
SRCS= expr.c compile.c

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-extra
# "missing type for func"
SMATCH=off
$(XPG4) := CFLAGS += -DXPG4
$(XPG6) := CFLAGS += -DXPG6

XGETFLAGS += -a -x expr.xcl

LDLIBS += -lgen

MAPFILES =	$(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS +=	$(MAPFILES:%=-M%)

.KEEP_STATE:

all: $(PROG) $(XPG4) $(XPG6)

install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTXPG6PROG)

$(PROG): exprobjs $(EXPROBJ) $(MAPFILES)
	$(LINK.c) $(EXPROBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4): exprobjs.xpg4 $(XPG4EXPROBJ) $(MAPFILES)
	$(LINK.c) $(XPG4EXPROBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG6): exprobjs.xpg6 $(XPG6EXPROBJ) $(MAPFILES)
	$(LINK.c) $(XPG6EXPROBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

exprobjs/%.o:	%.c
	$(COMPILE.c) -o $@ $<

exprobjs.xpg4/%.o:	%.c
	$(COMPILE.c) -o $@ $<

exprobjs.xpg6/%.o:	%.c
	$(COMPILE.c) -o $@ $<

exprobjs:
	-@mkdir -p $@

exprobjs.xpg4:
	-@mkdir -p $@

exprobjs.xpg6:
	-@mkdir -p $@

clean:
	$(RM) $(OBJS)

lint:	lint_PROG

include ../Makefile.targ
