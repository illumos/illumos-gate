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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2018 Joyent, Inc.
# Copyright 2024 Oxide Computer Company
#

PROG = smbios
OBJS = smbios.o bitext.o $(HEXDUMP_OBJS)
SRCS = $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.cmd.64
include $(SRC)/common/hexdump/Makefile.com

CFLAGS += $(CCVERBOSE)
LDLIBS += -lsmbios -ljedec

FILEMODE = 0555
STRIPFLAG =

LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

clean:
	$(RM) $(OBJS)

install: $(ROOTUSRSBINPROG)

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ
