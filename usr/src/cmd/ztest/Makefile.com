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
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Copyright 2017 RackTop Systems.
#

PROG= ztest
OBJS= $(PROG).o
SRCS= $(OBJS:%.o=../%.c)

include ../../Makefile.cmd
include ../../Makefile.ctf

INCS += -I../../../lib/libzpool/common
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../../uts/common/fs/zfs/lua
INCS += -I../../../common/zfs

LDLIBS += -lumem -lzpool -lcmdutils -lm -lnvpair -lfakekernel

C99MODE= -xc99=%all
C99LMODE= -Xc99=%all
CFLAGS += -g $(CCVERBOSE)
CFLAGS64 += -g $(CCVERBOSE)
CPPFLAGS.first = -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS) -DDEBUG

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2

# lint complains about unused inline functions, even though
# they are "inline", not "static inline", with "extern inline"
# implementations and usage in libzpool.
LINTFLAGS += -erroff=E_STATIC_UNUSED
LINTFLAGS64 += -erroff=E_STATIC_UNUSED

CERRWARN += -_gcc=-Wno-switch

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../Makefile.targ

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)
