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
# Copyright 2024 Oxide Computer Company

PROG=		zstreamdump
OBJS=		zstreamdump.o $(HEXDUMP_OBJS)
POFILE=		zstreamdump.po

include ../Makefile.cmd
include $(SRC)/common/hexdump/Makefile.com

INCS +=	-I../../uts/common/fs/zfs
INCS +=	-I../../common/zfs

LDLIBS += -lzfs -lnvpair

CSTD=	$(CSTD_GNU99)

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-switch

# not linted
SMATCH=off

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

FRC:

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ
