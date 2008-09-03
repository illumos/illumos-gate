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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = svc.startd
OBJS = \
	contract.o \
	deathrow.o \
	dict.o \
	env.o \
	expand.o \
	file.o \
	fork.o \
	graph.o \
	libscf.o \
	log.o \
	method.o \
	misc.o \
	protocol.o \
	restarter.o \
	specials.o \
	startd.o \
	transition.o \
	wait.o \
	utmpx.o

ALLOBJS = $(OBJS) proc.o

SRCS = $(OBJS:%.o=%.c)

POFILES = $(ALLOBJS:%.o=%.po)

include ../../Makefile.cmd
include ../Makefile.ctf

ROOTCMDDIR=	$(ROOT)/lib/svc/bin

CFLAGS += -v

$(OBJS) := CPPFLAGS += \
	-I. -I../common -D_REENTRANT -D_FILE_OFFSET_BITS=64

$(POFILE) := CPPFLAGS += -I. -I../common

proc.o := CPPFLAGS += -I. -I../common -D_REENTRANT

LDLIBS += \
	-lcontract \
	-lkstat \
	-lnvpair \
	-lrestart \
	-lscf \
	-lsysevent \
	-lumem \
	-luutil

FILEMODE = 0555
OWNER = root
GROUP = sys

# lint doesn't like the unused _umem_*_init()
# And lint thinks uadmin() is undefined.
lint_SRCS := LINTFLAGS += -U_FILE_OFFSET_BITS -xerroff=E_NAME_DEF_NOT_USED2 -u
lint_SRCS := CPPFLAGS += \
	-I. -I../common -D_REENTRANT -D_FILE_OFFSET_BITS=64

.KEEP_STATE:

.PARALLEL: $(ALLOBJS)

all: $(PROG)

$(PROG): $(ALLOBJS)
	$(LINK.c) -o $@ $(ALLOBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTCMD)

clean:
	$(RM) $(ALLOBJS)

lint:   lint_SRCS

include ../../Makefile.targ
