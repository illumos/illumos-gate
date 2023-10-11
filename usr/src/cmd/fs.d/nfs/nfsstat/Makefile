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
# Copyright (c) 2018, Joyent, Inc.

PROG=		nfsstat

include		../../../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
COMMON=	nfs_sec.o
OBJS=	nfsstat.o $(COMMON)
SRCS=	nfsstat.c ../lib/nfs_sec.c

STATCOMMONDIR = $(SRC)/cmd/stat/common

STAT_COMMON_OBJS = timestamp.o
STAT_COMMON_SRCS = $(STAT_COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)
SRCS += $(STAT_COMMON_SRCS)
OBJS += $(STAT_COMMON_OBJS)

CSTD= $(CSTD_GNU99)

CPPFLAGS += -I$(STATCOMMONDIR)
CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

LDLIBS += -lkstat -lnsl

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(LDLIBS) $(OBJS)
		$(POST_PROCESS)

FILEMODE=       0555

.KEEP_STATE:

all:		$(PROG)

nfs_sec.o:	../lib/nfs_sec.c
		$(COMPILE.c) ../lib/nfs_sec.c

%.o:    $(STATCOMMONDIR)/%.c
	$(COMPILE.c) $<

install:	all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ
