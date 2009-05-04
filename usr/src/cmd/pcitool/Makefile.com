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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = pcitool
OBJS = pcitool.o pcitool_ui.o pcitool_usage.o
SRCS = $(OBJS:%.o=../%.c)

#
# Manpage is in the directory above platform-specific directory
# from which this makefile is called.
#
MAN1MFILES = pcitool.1m
MANFILE_SRC_PATH = ../$(MAN1MFILES)

include $(SRC)/cmd/Makefile.cmd

UTSBASE = ../../../../src/uts

LDLIBS += -ldevinfo

CFLAGS += -D$(MACH) -I$(UTSBASE)/common

LINTFLAGS += -I$(UTSBASE)/common

.KEEP_STATE:

all: $(PROG) $(MANFILE_SRC_PATH)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTMAN1M):
	mkdir -p $(ROOTMAN1M)

$(ROOTMAN1MFILES): $(MANFILE_SRC_PATH) $(ROOTMAN1M)
	$(INS.file) $(MANFILE_SRC_PATH)

install: all $(PROG) $(MANFILE_SRC_PATH)

clean:
	$(RM) $(OBJS) $(PROG)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

%.o:	../%.c
	$(COMPILE.c) -o $@ $<

include $(SRC)/cmd/Makefile.targ
