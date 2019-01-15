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
# Copyright (c) 2018, Joyent, Inc.
#
# Message catalog requires no special processing because messages
# only occur in ./nl.c, not in ../expr/compile.c.

PROG= nl
XPG4PROG= nl

NLOBJ= nlobjs/$(PROG).o nlobjs/compile.o
XPG4NLOBJ= nlobjs.xpg4/$(PROG).o nlobjs.xpg4/compile.o

OBJS = $(NLOBJ) $(XPG4NLOBJ)
SRCS = nl.c ../expr/compile.c

include ../Makefile.cmd

LDLIBS += -lgen
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-variable

# not linted
SMATCH=off

$(XPG4):= CPPFLAGS += -DXPG4

MAPFILE.INT =	../expr/mapfile-intf
LDFLAGS +=	$(MAPFILE.INT:%=-M%)

.KEEP_STATE:

all: $(PROG) $(XPG4)

install: all $(ROOTPROG) $(ROOTXPG4PROG)

$(PROG): nlobjs $(NLOBJ) $(MAPFILE.INT)
	$(LINK.c) $(NLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4): nlobjs.xpg4 $(XPG4NLOBJ) $(MAPFILE.INT)
	$(LINK.c) $(XPG4NLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

nlobjs/%.o:   %.c
	$(COMPILE.c) -o $@ $<

nlobjs/%.o:   ../expr/%.c
	$(COMPILE.c) -o $@ $<

nlobjs.xpg4/%.o:      %.c
	$(COMPILE.c) -o $@ $<

nlobjs.xpg4/%.o:      ../expr/%.c
	$(COMPILE.c) -o $@ $<

nlobjs:
	-@mkdir -p $@

nlobjs.xpg4:
	-@mkdir -p $@

clean:
	$(RM) $(OBJS)

lint:	lint_PROG

include ../Makefile.targ

