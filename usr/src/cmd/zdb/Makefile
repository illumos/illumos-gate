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
# Copyright 2020 Joyent, Inc.
# Copyright 2017 RackTop Systems.
#

PROG=	zdb
OBJS=	zdb.o zdb_il.o

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

INCS += -I../../lib/libzpool/common
INCS +=	-I../../uts/common/fs/zfs
INCS +=	-I../../common/zfs
INCS += -I../../lib/libzutil/common

LDLIBS += -lzpool -lumem -lnvpair -lzutil -lavl -lfakekernel

CSTD=	$(CSTD_GNU99)

CPPFLAGS.first = -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL
CPPFLAGS += $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

# re-enable warnings that we can tolerate, which are disabled by default
# in Makefile.master
CERRWARN += -_gcc=-Wmissing-braces
CERRWARN += -_gcc=-Wsign-compare

SMOFF += 64bit_shift,all_func_returns

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
