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
# Copyright (c) 2018, Joyent, Inc.

TABLEDIR = ../praudit

PROG = auditreduce
SRCS = main.c option.c proc.c time.c token.c regex2.c $(TABLEDIR)/toktable.c
OBJS = main.o option.o proc.o time.o token.o regex2.o toktable.o

include $(SRC)/cmd/Makefile.cmd

TEXT_DOMAIN = SUNW_OST_OSCMD
POFILE = $(PROG).po
MSGFILES = $(SRCS)

CPPFLAGS += -I$(TABLEDIR) -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS += -lnsl -lbsm -lscf -ltsol

CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses

# false positives / need cleanup
SMOFF += indenting,no_if_block,strcpy_overflow

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

toktable.o:	$(TABLEDIR)/toktable.c
	$(COMPILE.c) $(TABLEDIR)/toktable.c

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

lint: lint_SRCS

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
