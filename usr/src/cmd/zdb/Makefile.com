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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2017 RackTop Systems.
#

PROG:sh=	cd ..; basename `pwd`
SRCS= ../$(PROG).c ../zdb_il.c
OBJS= $(PROG).o zdb_il.o

include ../../Makefile.cmd
include ../../Makefile.ctf

INCS += -I../../../lib/libzpool/common
INCS +=	-I../../../uts/common/fs/zfs
INCS +=	-I../../../common/zfs

LDLIBS += -lzpool -lumem -lnvpair -lzfs -lavl -lcmdutils -lfakekernel

CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CPPFLAGS.first = -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS) -DDEBUG

# re-enable warnings that we can tolerate, which are disabled by default
# in Makefile.master
CERRWARN += -_gcc=-Wmissing-braces
CERRWARN += -_gcc=-Wsign-compare

SMOFF += 64bit_shift,all_func_returns

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2

# lint complains about unused inline functions, even though
# they are "inline", not "static inline", with "extern inline"
# implementations and usage in libzpool.
LINTFLAGS += -erroff=E_STATIC_UNUSED
LINTFLAGS64 += -erroff=E_STATIC_UNUSED

LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN
LINTFLAGS64 += -erroff=E_BAD_PTR_CAST_ALIGN

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
