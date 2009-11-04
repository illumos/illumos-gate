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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		ilbadm

ILB_OBJS =	ilbadm.o ilbadm_sg.o ilbadm_rules.o ilbadm_hc.o
ILB_OBJS +=	ilbadm_subr.o ilbadm_import.o ilbadm_nat.o ilbadm_stats.o
LIST_OBJS =	list.o
OBJS =		$(ILB_OBJS) $(LIST_OBJS)

ILB_SRCS=	$(ILB_OBJS:.o=.c)
LIST_SRCS=	$(LIST_OBJS:%.o=../../../../uts/common/os/%.c)

SRCS=		$(ILB_SRC) $(LIST_SRCS)

include	../../../Makefile.cmd
include ../../Makefile.cmd-inet

LDLIBS +=	-lsocket -lnsl -lilb -linetutil -lkstat
CPPFLAGS +=	-I$(SRC)/lib/libilb/common -I$(SRC)/uts/common

C99MODE =	$(C99_ENABLE)

# for debug:
CFLAGS = -g
STRIP_STABS= :

POFILES =	$(ILB_OBJS:%.o=%.po)
POFILE =	$(PROG)_all.po

.KEEP_STATE:
.PARALLEL:

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTUSRSBINPROG)

clean:	
	$(RM) $(OBJS) $(POFILES)

lint:	$(ILB_SRCS)
	$(LINT.c) $(ILB_SRCS) $(LDLIBS)

check:	$(ILB_SRCS) $(PROG).h
	$(CSTYLE) -pP $(ILB_SRCS) $(PROG).h
	$(HDRCHK) $(PROG).h

include ../../../Makefile.targ

# the below is needed to get list.o built
%.o: ../../../../uts/common/os/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
