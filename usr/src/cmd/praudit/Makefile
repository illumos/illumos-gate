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

XLATEDIR = $(SRC)/lib/libbsm/common

PROG = praudit
SRCS = format.c main.c token.c toktable.c printaudit.c prio.c $(XLATEDIR)/adt_xlate.c
OBJS = format.o main.o token.o toktable.o printaudit.o prio.o adt_xlate.o

include $(SRC)/cmd/Makefile.cmd

TEXT_DOMAIN=SUNW_OST_OSCMD
POFILE = $(PROG).po
POFILES = $(OBJS:.o=.po)
XGETFLAGS += -a -x praudit.xcl

CPPFLAGS += -D_PRAUDIT -I$(XLATEDIR)
CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

SMOFF += signed

LDLIBS += -lbsm -lnsl -lpam -ltsol

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

adt_xlate.o: $(XLATEDIR)/adt_xlate.c
	$(COMPILE.c) $(XLATEDIR)/adt_xlate.c

$(POFILE): $(POFILES)
	$(BUILDPO.pofiles)

adt_xlate.po: $(XLATEDIR)/adt_xlate.c
	$(RM) adt_xlate.po
	$(XGETTEXT) $(XGETFLAGS) $(XLATEDIR)/adt_xlate.c
	$(SED) "/^domain/d" < messages.po > adt_xlate.po
	$(RM) messages.po

_msg:	$(MSGDOMAINPOFILE)

lint:	lint_SRCS

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
