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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

PROG:sh=	cd ..; basename `pwd`
OBJS= $(PROG).o translate.o
SRCS= $(OBJS:%.o=../%.c)

include ../../Makefile.cmd

INCS +=	-I../../../lib/libzpool/common
INCS +=	-I../../../uts/common/fs/zfs

LDLIBS += -lzpool -lzfs -lnvpair

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)

CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-switch

LINTFLAGS += -erroff=E_STATIC_UNUSED
LINTFLAGS64 += -erroff=E_STATIC_UNUSED

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
