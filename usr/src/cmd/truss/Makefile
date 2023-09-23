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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2016 by Delphix. All rights reserved.
# Copyright 2019 Joyent, Inc.
# Copyright 2023 Oxide Computer Co.
#

PROG=	truss

OBJS=			\
	main.o		\
	listopts.o	\
	ipc.o		\
	actions.o	\
	expound.o	\
	codes.o		\
	print.o		\
	ramdata.o	\
	systable.o	\
	procset.o	\
	stat.o		\
	fcall.o		\
	htbl.o

.PARALLEL: $(OBJS)

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

CTF_MODE	= link

CFLAGS		+= $(CCVERBOSE)

CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-switch

# not linted
SMATCH=off

CSTD=	$(CSTD_GNU99)

LDLIBS	+= -lproc -lrtld_db -lc_db -lnsl -lsocket -ltsol -lnvpair
CPPFLAGS += -D_REENTRANT
CPPFLAGS += -I$(SRC)/uts/common/fs/zfs
CPPFLAGS += -I$(SRC)/uts/common

ROOTLINK = $(PROG:%=$(ROOTBIN64)/%)

.KEEP_STATE:

%.o:	%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all: $(PROG)

install: all $(ROOTPROG) $(ROOTLINK)

$(ROOTLINK):
	$(RM) $@; $(SYMLINK) ../../bin/$(@F) $@

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
