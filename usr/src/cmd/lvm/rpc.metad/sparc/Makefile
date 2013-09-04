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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# Makefile for logical volume management
#

PROG= rpc.metad 

DERIVED_FILES = \
		metad_svc.c

OBJECTS=	metad_freeresult.o \
		metad_init.o \
		metad_svc_subr.o

LINTOBJECTS=	metad_freeresult.o \
		metad_init.o \
		metad_svc_subr.o

OBJECTS +=		$(DERIVED_FILES:.c=.o)

SRCS = $(OBJECTS:%.o=../%.c)
LINTSRCS =	$(LINTOBJECTS:%.o=../%.c)

POFILES= $(OBJS:%.o=%.po)

include ../../../Makefile.cmd
include ../../Makefile.lvm

LDLIBS +=	-lmeta -lsocket -lnsl -ldevid

CFLAGS += $(DEFINES)
#
#
lint := LINTFLAGS += -m

%_svc.c := RPCGENFLAGS += -K -1


.KEEP_STATE:

%.o:    ../%.c
	$(COMPILE.c) $<

all:	$(PROG)

$(PROG): $(OBJECTS) 
	$(LINK.c) -o $@ $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS)

ROOTUSRSBINPROG=$(PROG:%=$(ROOTUSRSBIN)/%)
install: all $(ROOTUSRSBINPROG)

catalog:

cstyle:
	${CSTYLE} ${SRCS}

lint:
	${LINT.c} $(LINTFLAGS) ${LINTSRCS}

clean:
	${RM} ${OBJS} ${DERIVED_FILES} *.o

clobber: clean
	$(RM) $(PROG) $(CLOBBERFILES)

metad_svc.c: $(SRC)/head/metad.x
	$(CP) $(SRC)/head/metad.x .
	$(RPCGEN) $(RPCGENFLAGS_SERVER) -DDEBUG metad.x -o $@
	${RM} metad.x
