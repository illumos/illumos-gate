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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		ilbadm

OBJS =	ilbadm.o ilbadm_sg.o ilbadm_rules.o ilbadm_hc.o
OBJS +=	ilbadm_subr.o ilbadm_import.o ilbadm_nat.o ilbadm_stats.o

SRCS=	$(OBJS:.o=.c)

include	../../../Makefile.cmd
include	../../../Makefile.ctf
include ../../Makefile.cmd-inet

LDLIBS +=	-lcmdutils -lsocket -lnsl -lilb -lkstat -lofmt
CPPFLAGS +=	-I$(SRC)/lib/libilb/common -I$(SRC)/uts/common

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

CSTD =	$(CSTD_GNU99)

POFILES =	$(OBJS:%.o=%.po)
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

lint:	$(SRCS)
	$(LINT.c) $(SRCS) $(LDLIBS)

check:	$(SRCS) $(PROG).h
	$(CSTYLE) -pP $(SRCS) $(PROG).h
	$(HDRCHK) $(PROG).h

include ../../../Makefile.targ
