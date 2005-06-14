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
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	Copyright (c) 1988-1992 Sun Microsystems Inc
#	All Rights Reserved.
#
# Makefile for NIS+ server utility commands
#

SCRIPTS=	nissetup  nisclient  nisserver  nispopulate  nisopaccess
PROG=	nisstat nisshowcache nisupdkeys nisping nisctl $(SCRIPTS)
# unsupported programs, which are built, but not installed
UPROG=	nisadm
SRCS=	nisadm.c nisctl.c nisstat.c nisshowcache.c nisupdkeys.c nisping.c
OBJS=	nisadm.o nisctl.o nisstat.o nisshowcache.o nisupdkeys.o nisping.o

include ../../../Makefile.cmd

ROOTNSLIB=	$(ROOT)/usr/lib/nis
ROOTNSPROG=	$(PROG:%=$(ROOTNSLIB)/%)
ROOTSCRIPTS=	$(SCRIPTS:%=$(ROOTNSLIB)/%)

CPPFLAGS += -I$(SRC)/lib/libnsl/include
LDLIBS += -lnsl

$(ROOTSCRIPTS) := FILEMODE = 755

.KEEP_STATE:

all: $(PROG) $(UPROG)

install: all $(ROOTNSLIB) $(ROOTNSPROG)

lint: lint_SRCS

$(ROOTNSLIB):
	$(INS.dir)

$(ROOTNSLIB)/%: %
	$(INS.file)

clean:
	-$(RM) $(OBJS)

include ../../../Makefile.targ
