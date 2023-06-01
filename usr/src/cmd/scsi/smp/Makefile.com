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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

.KEEP_STATE:
.SUFFIXES:

PROG = smp
SRCS = $(PROG:%=../common/%.c)
OBJS = $(PROG:%=%.o)

include ../../../Makefile.cmd

ROOTLIBSCSI = $(ROOT)/usr/lib/scsi
ROOTPROG = $(ROOTLIBSCSI)/$(PROG)

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CPPFLAGS += -I. -I../common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE)
LDLIBS += -L$(ROOT)/usr/lib/scsi -lsmp
LDFLAGS += -R/usr/lib/scsi

CERRWARN += -_gcc=-Wno-unused-variable

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

$(ROOTLIBSCSI)/%: %
	$(INS.file)

install_h:

install: all $(ROOTPROG)

include ../../../Makefile.targ
