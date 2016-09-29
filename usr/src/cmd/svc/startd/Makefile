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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012 Milan Jurik. All rights reserved.
# Copyright 2016 Toomas Soome <tsoome@me.com>
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

ALLOBJS = $(OBJS) \
	proc.o \
	manifest_hash.o

SRCS = $(OBJS:%.o=%.c) \
	proc.c \
	../common/manifest_hash.c

POFILES = $(OBJS:%.o=%.po) \
	proc.po \
	../common/manifest_hash.po

include ../../Makefile.cmd
include ../../Makefile.ctf

ROOTCMDDIR=	$(ROOT)/lib/svc/bin

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I. -I../common

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-uninitialized

$(OBJS) := CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_REENTRANT

proc.o := CPPFLAGS += -D_REENTRANT

%.o:	../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.ln:	../common/%.c
	$(LINT.c) $(OUTPUT_OPTION) -c $<

LDLIBS += \
	-lcontract \
	-lkstat \
	-lmd5 \
	-lnvpair \
	-lrestart \
	-lscf \
	-lsysevent \
	-lumem \
	-luutil

LDLIBS_i386 +=	-lbe
LDLIBS +=	$(LDLIBS_$(MACH)) -L $(ROOT)/lib/fm -lfmevent
LDFLAGS +=	-R /lib/fm

FILEMODE = 0555

# lint doesn't like the unused _umem_*_init()
# And lint thinks uadmin() is undefined.
lint_SRCS := LINTFLAGS += -U_FILE_OFFSET_BITS -xerroff=E_NAME_DEF_NOT_USED2 -u
lint_SRCS := CPPFLAGS += \
	-I. -I../common -D_REENTRANT -D_FILE_OFFSET_BITS=64

.KEEP_STATE:

.PARALLEL: $(ALLOBJS)

all: $(PROG)

$(PROG): $(ALLOBJS)
	$(LINK.c) -o $@ $(ALLOBJS) $(LDLIBS) $(LDFLAGS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTCMD)

clean:
	$(RM) $(ALLOBJS)

lint:   lint_SRCS

include ../../Makefile.targ
