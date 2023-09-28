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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
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
	definit.o \
	manifest_hash.o

SRCS = $(OBJS:%.o=%.c) \
	proc.c \
	$(SRC)/common/definit/definit.c \
	../common/manifest_hash.c

POFILES = $(OBJS:%.o=%.po) \
	proc.po \
	../common/manifest_hash.po

include ../../Makefile.cmd
include ../../Makefile.ctf

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I. -I../common -I$(SRC)/common/definit

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch
CERRWARN += $(CNOWARN_UNINIT)

# these look like real bugs here, but ...
SMOFF += impossible_mask,signed_integer_overflow_check

$(OBJS) := CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_REENTRANT

proc.o := CPPFLAGS += -D_REENTRANT

%.o:	../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.o:	$(SRC)/common/definit/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

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

#
# While svc.startd only searches for libfmevent, which is in
# $(ROOT)/lib/fm, when resolving dependencies it needs to know to search
# for those in $(ROOT)/usr/lib/fm. However, we don't need a runpath
# because libfmevent has that properly set already, but it doesn't help
# us during the build.
#
LDLIBS_i386 +=	-lbe
LDLIBS +=	$(LDLIBS_$(MACH)) -L$(ROOT)/lib/fm -lfmevent \
		-L$(ROOT)/usr/lib/fm
LDFLAGS +=	-R/lib/fm

FILEMODE = 0555

.KEEP_STATE:

.PARALLEL: $(ALLOBJS)

all: $(PROG)

$(PROG): $(ALLOBJS)
	$(LINK.c) -o $@ $(ALLOBJS) $(LDLIBS) $(LDFLAGS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBSVCBINPROG)

clean:
	$(RM) $(ALLOBJS)

include ../../Makefile.targ
