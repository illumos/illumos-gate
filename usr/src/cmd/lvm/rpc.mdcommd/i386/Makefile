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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

COMMD = rpc.mdcommd
MDDOORS = mddoors

PROG = $(COMMD) $(MDDOORS)

DERIVED_FILES = mdmn_commd_xdr.c

OBJECTS =	mdmn_commd_server.o \
		mdmn_commd_service.o \
		mddoors.o

COMMD_OBJECTS =	mdmn_commd_server.o \
		mdmn_commd_service.o \
		mdmn_subr.o \
		mdmn_commd_xdr.o 

MDDOORS_OBJECTS = mddoors.o

LINTOBJECTS =	mdmn_commd_server.o  mdmn_commd_service.o mdmn_subr.o mddoors.o

OBJECTS +=	$(DERIVED_FILES:.c=.o)

SRCS = $(OBJECTS:%.o=../%.c)
LINTSRCS =	$(LINTOBJECTS:%.o=../%.c)

ROOTLIBLVM = $(ROOTLIB)/lvm

include ../../../Makefile.cmd
include ../../Makefile.lvm

LDLIBS +=	-lmeta

CFLAGS += $(DEFINES)
#
#
lint := LINTFLAGS += -m

%_svc.c := RPCGENFLAGS += -K -1

.KEEP_STATE:

%.o:    ../%.c
	$(COMPILE.c) $<

all:	$(PROG)

$(COMMD): $(DERIVED_FILES) $(COMMD_OBJECTS)
	$(LINK.c) -o $@ $(COMMD_OBJECTS) $(LDLIBS) -lnsl
	$(POST_PROCESS)

$(MDDOORS): ../mddoors.c
	$(COMPILE.c) ../mddoors.c
	$(LINK.c) -o $@ $(MDDOORS_OBJECTS) $(LDLIBS)
	$(POST_PROCESS)

INSTPROGS = $(ROOTUSRSBIN)/$(COMMD) $(ROOTLIBLVM)/$(MDDOORS)
install: all $(ROOTLIBLVM) $(INSTPROGS)

cstyle:
	$(CSTYLE) $(SRCS)

lint:
	for f in $(LINTSRCS) ; do \
		$(LINT.c) $(LINTFLAGS) $$f ; \
	done

clean:
	$(RM) $(OBJECTS) $(DERIVED_FILES) *.o

clobber: clean
	$(RM) $(PROG) $(CLOBBERFILES)

$(DERIVED_FILES): $(SRC)/uts/common/sys/lvm/mdmn_commd.x
	$(RPCGEN) -c $(SRC)/uts/common/sys/lvm/mdmn_commd.x -o $@

$(ROOTLIBLVM)/%: %
	$(INS.file)

$(ROOTLIBLVM):
	$(INS.dir)

