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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019, Joyent, Inc.
#

PROG=	fksmbcl

OBJS_LOCAL = \
	fksmbcl_main.o \
	fkdev.o \
	fknewvc.o \
	fkiod_cl.o \
	shares.o

OBJS=	${OBJS_LOCAL}
SRCS=	${OBJS_LOCAL:.o=.c}

include ../../../Makefile.cmd
include ../../../Makefile.ctf

# Force SOURCEDEBUG
CSOURCEDEBUGFLAGS	= -g
CCSOURCEDEBUGFLAGS	= -g
STRIP_STABS	= :

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
# Also, like Makefile.uts, reset CPPFLAGS
# CPPFLAGS.first += -I$(SRC)/lib/libfakekernel/common
CPPFLAGS.first += -I$(SRC)/lib/smbclnt/libfknsmb/common
CPPFLAGS= $(CPPFLAGS.first)

INCS += -I$(SRC)/uts/common/fs/smbclnt
INCS += -I$(SRC)/uts/common
INCS += -I$(SRC)/common/smbclnt
INCS += -I$(SRC)/common

# Allow cpp to find libfknsmb.h etc. via
# include <libfknsmb/common/libfknsmb.h>
INCS += -I$(SRC)/lib/smbclnt
INCS += -I$(SRC)/lib/libsmbfs
INCS += -I$(SRC)/lib/libsmbfs/netsmb

CPPFLAGS += $(INCS)
CPPFLAGS += -D_REENTRANT
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CPPFLAGS += -D_LARGEFILE64_SOURCE=1
CPPFLAGS += -DFKSMBCL
# Always want DEBUG here
CPPFLAGS += -DDEBUG

# needs work
SMOFF += all_func_returns

CSTD=		$(CSTD_GNU99)

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

LDFLAGS += $(ZNOLAZYLOAD)
LDFLAGS += -R/usr/lib/smbfs
LDLIBS += -L$(ROOT)/usr/lib/smbfs
LDLIBS += -lsmbfs -lfksmbfs -lfknsmb
LDLIBS += -lsocket

ROOTSMBDDIR = $(ROOTLIB)/smbfs
ROOTSMBDFILE = $(PROG:%=$(ROOTSMBDDIR)/%)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(OBJS)

# lots of lint due to mixing kernel+user stuff.  give up.
lint:	# lint_SRCS

include ../../../Makefile.targ

install: all $(ROOTSMBDFILE)

$(ROOTSMBDDIR)/%: %
	$(INS.file)
