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

#
# Copyright (c) 2012 by Delphix. All rights reserved.
#

PROG= zhack
SRCS= ../$(PROG).c
OBJS= $(PROG).o

include ../../Makefile.cmd
include ../../Makefile.ctf

INCS += -I../../../lib/libzpool/common
INCS +=	-I../../../uts/common/fs/zfs
INCS +=	-I../../../common/zfs

LDLIBS += -lzpool -lumem -lnvpair -lzfs

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT -DDEBUG $(INCS)

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
