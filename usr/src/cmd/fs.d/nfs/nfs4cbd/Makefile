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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		nfs
TYPEPROG=	nfs4cbd

include		../../Makefile.fstype

OBJS=	$(TYPEPROG).o nfs_tbind.o thrpool.o
SRCS=	$(TYPEPROG).c ../../fslib.c ../lib/nfs_tbind.c ../lib/thrpool.c

LDLIBS += -lnsl
CPPFLAGS += -I. -I../.. -I../lib
CFLAGS += $(CCVERBOSE) 

CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-extra

# not linted
SMATCH=off

.KEEP_STATE:

all:	$(TYPEPROG)

$(TYPEPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

nfs_tbind.o:	../lib/nfs_tbind.c
		$(COMPILE.c) ../lib/nfs_tbind.c

thrpool.o:	../lib/thrpool.c
		$(COMPILE.c) ../lib/thrpool.c

install:	$(TYPEPROG)

lint:	lint_SRCS

clean:     
	$(RM) $(OBJS)
