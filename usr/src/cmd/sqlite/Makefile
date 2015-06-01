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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		sqlite

include ../Makefile.cmd

include $(SRC)/lib/Makefile.lib

SQLITEHDRDIR=	$(ROOTHDRDIR)/sqlite-sys

ROOTLIBSVCBIN=	$(ROOT)/lib/svc/bin
ROOTSQLITE=	$(PROG:%=$(ROOTLIBSVCBIN)/%)

OBJS=		shell.o
$(OBJS) :=	CFLAGS += $(CTF_FLAGS)
$(OBJS) :=	CTFCONVERT_POST = $(CTFCONVERT_O)

CERRWARN +=	-_gcc=-Wno-empty-body

LDLIBS +=	-lsqlite-sys

.KEEP_STATE:

$(ROOTSQLITE)	:= FILEMODE= 555

$(ROOTLIBSVCBIN)/%: %
	$(INS.file)

CPPFLAGS +=	-D_REENTRANT -DTHREADSAFE=1 -DHAVE_USLEEP=1 \
		-I$(SQLITEHDRDIR)

$(PROG): $(OBJS) $(SQLITEHDRDIR)/sqlite.h
	$(LINK.c) -o $@ $(OBJS) \
	    $(MAPFILE.NES:%=-M%) $(MAPFILE.NED:%=-M%) $(LDLIBS)
	$(CTFMERGE) -t -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

all: $(PROG) 

install: all $(ROOTSQLITE)

clean:
	$(RM) $(OBJS)

lint:

include ../Makefile.targ
