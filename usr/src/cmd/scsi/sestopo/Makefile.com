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

.KEEP_STATE:
.SUFFIXES:

PROG = sestopo
SRCS = $(PROG:%=../common/%.c)
OBJS = $(PROG:%=%.o)

include ../../../Makefile.cmd

ROOTLIBSCSI = $(ROOT)/usr/lib/scsi
ROOTPROG = $(ROOTLIBSCSI)/$(PROG)

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CPPFLAGS += -I. -I../common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-unused-variable
LDLIBS += -L$(ROOT)/usr/lib/scsi -lses -lnvpair
LDFLAGS += -R/usr/lib/scsi

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
