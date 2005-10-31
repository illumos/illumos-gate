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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		availdevs
OBJS_COMMON=	availdevs.o
OBJS=		$(OBJS_COMMON)
SRCS=		$(OBJS_COMMON:%.o=%.c)

include ../Makefile.cmd

ROOTCMDDIR=	$(ROOTLIB)/zfs

INCS += -I../../lib/libzfs_jni/common \
	-I/usr/include/libxml2

LDLIBS += -lzfs_jni -lxml2
CPPFLAGS += $(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(ROOTCMD)

clean:
	$(RM) $(OBJS)

FRC:

include ../Makefile.targ
