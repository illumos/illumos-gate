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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG = pcitool
OBJS = pcitool.o pcitool_ui.o pcitool_usage.o
SRCS = $(OBJS:%.o=../%.c)

include $(SRC)/cmd/Makefile.cmd

UTSBASE = ../../../../src/uts

LDLIBS += -ldevinfo

CFLAGS += -D$(MACH) -I$(UTSBASE)/common
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable

LINTFLAGS += -I$(UTSBASE)/common

.KEEP_STATE:

all: $(PROG)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(PROG)

clean:
	$(RM) $(OBJS) $(PROG)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

%.o:	../%.c
	$(COMPILE.c) -o $@ $<

include $(SRC)/cmd/Makefile.targ
