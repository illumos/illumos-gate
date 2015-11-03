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
# Copyright 1996, 2001-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#
#
# Makefile for logical volume management 
#

PROG= rpc.metamhd 

RPCMOD = metamhd

DERIVED_FILES = \
		$(RPCMOD)_svc.c \
		$(RPCMOD)_xdr.c \
		mhdx_xdr.c

OBJECTS=	\
		mhd_drive.o \
		mhd_error.o \
		mhd_failfast.o \
		mhd_freeresult.o \
		mhd_init.o \
		mhd_mem.o \
		mhd_metamhd.o \
		mhd_set.o \
		mhd_synch.o \
		mhd_time.o

LINTOBJECTS=	\
		mhd_drive.o \
		mhd_error.o \
		mhd_failfast.o \
		mhd_freeresult.o \
		mhd_init.o \
		mhd_mem.o \
		mhd_metamhd.o \
		mhd_set.o \
		mhd_synch.o \
		mhd_time.o

OBJECTS += $(DERIVED_FILES:.c=.o)

SRCS = $(OBJECTS:%.o=../%.c)
LINTSRCS = $(LINTOBJECTS:%.o=../%.c)

include ../../../Makefile.cmd
include ../../Makefile.lvm


MDLIBS =
LDLIBS +=	-ladm -lsocket -lnsl

POFILES= $(OBJECTS:%.o=%.po)


$(RPCMOD)_svc.c := RPCGENFLAGS += -A -K -1

DEFINES += -D_REENTRANT
CFLAGS += $(DEFINES)


#
#
lint := LINTFLAGS += -m

.KEEP_STATE:

%.o:	../%.c
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
	${RM} ${OBJECTS} ${DERIVED_FILES} *.o

clobber: clean
	$(RM) $(PROG) $(CLOBBERFILES)

metamhd_svc.c: $(SRC)/head/metamhd.x
	$(CP) $(SRC)/head/metamhd.x .
	$(RPCGEN) $(RPCGENFLAGS_SERVER) metamhd.x -o $@
	${RM} metamhd.x

metamhd_xdr.c: $(SRC)/head/metamhd.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/head/metamhd.x -o $@

mhdx_xdr.c: $(SRC)/uts/common/sys/lvm/mhdx.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/uts/common/sys/lvm/mhdx.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head") ; print $$0}' >$@
