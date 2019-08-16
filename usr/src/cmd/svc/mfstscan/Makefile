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

PROG =		mfstscan

OBJS =		mfstscan.o \
		manifest_find.o \
		manifest_hash.o

SRCS =		mfstscan.c \
		../common/manifest_find.c \
		../common/manifest_hash.c

POFILES = 	$(SRCS:.c=.po)

ROOTLIBSVCBINPROG = $(ROOT)/lib/svc/bin/$(PROG)

include ../../Makefile.cmd

POFILE =	$(PROG)_all.po
CPPFLAGS +=	-I../common
LDLIBS +=	-lscf -luutil -lmd5
CLOBBERFILES += $(POFILES)

CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-label

lint := LINTFLAGS = -ux -erroff=E_GLOBAL_COULD_BE_STATIC2

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBSVCBINPROG)

$(ROOTLIBSVCBIN)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

%.o: ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)

include ../../Makefile.targ
