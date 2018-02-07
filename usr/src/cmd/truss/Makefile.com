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
# Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2016 by Delphix. All rights reserved.
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/truss/Makefile.com
#

PROG=	truss

OBJS=	main.o listopts.o ipc.o actions.o expound.o codes.o print.o \
	ramdata.o systable.o procset.o stat.o fcall.o htbl.o

SRCS=	$(OBJS:%.o=../%.c)

include ../../Makefile.cmd

CFLAGS		+= $(CCVERBOSE)
CFLAGS64	+= $(CCVERBOSE)

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-switch

CSTD=	$(CSTD_GNU99)

LDLIBS	+= -lproc -lrtld_db -lc_db -lnsl -lsocket -ltsol -lnvpair
CPPFLAGS += -D_REENTRANT -D_LARGEFILE64_SOURCE=1
CPPFLAGS += -I$(SRC)/uts/common/fs/zfs

LINTFLAGS += -erroff=E_STATIC_UNUSED
LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS64 += -erroff=E_STATIC_UNUSED
LINTFLAGS64 += -erroff=E_NAME_USED_NOT_DEF2

.KEEP_STATE:

%.o:	../%.c
	$(COMPILE.c) $<

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

include ../../Makefile.targ
