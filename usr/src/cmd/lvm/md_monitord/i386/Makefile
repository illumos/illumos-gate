#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1996, 2000-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# Makefile for logical volume management
#

PROG= mdmonitord

OBJS=		probedev.o \
		md_monitord.o
SRCS=		$(OBJS:%.o=../%.c)

include ../../../Makefile.cmd
include ../../Makefile.lvm

LDLIBS +=	-lmeta

DEFINES += -DDEBUG
CFLAGS += ${DEFINES}

#
#
lint := LINTFLAGS += -m

.KEEP_STATE:

%.o:	../%.c
	$(COMPILE.c) $<

all:     $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

ROOTUSRSBINPROG=$(PROG:%=$(ROOTUSRSBIN)/%)
install: all $(ROOTUSRSBINPROG) 

cstyle:
	${CSTYLE} ${SRCS}

lint:
	${LINT.c} $(LINTFLAGS) ${SRCS}

clean:
	${RM} ${OBJS} *.o

include $(SRC)/cmd/Makefile.targ
