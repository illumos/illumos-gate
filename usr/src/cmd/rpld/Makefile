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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/rpld/Makefile
#

PROG=	rpld

CONFILE=	rpld.conf

OBJS= 	rpld.o llcsetup.o debug.o sighandler.o params.o \
	clientop.o rplin.o rplout.o

LIBOBJS=	dl_open.o dl_bind.o dl_snd.o dl_rcv.o dl_addr.o dl_close.o \
	 	dl_unbind.o dl_attach.o dl_info.o dl_error.o

rplin.o :=	CFLAGS += -_gcc=-Wno-return-type

LIBDLA= 	libdla.a

LIBS= 		$(LIBDLA) -lsocket

ARFLAGS=	r

CLOBBERFILES=	$(LIBDLA)

include ../Makefile.cmd

$(ROOTETC)/$(CONFILE):=	FILEMODE = 644

CPPFLAGS +=	-I.

.KEEP_STATE:

all:	$(PROG)

$(PROG): 	$(OBJS) $(LIBDLA)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(LIBS)
	$(POST_PROCESS)

$(LIBDLA): 	$(LIBOBJS)
	$(AR) $(ARFLAGS) $(LIBDLA) $?
	$(POST_PROCESS_A)

install:	all $(ROOTUSRSBINPROG) $(ROOTETC)/$(CONFILE)

clean:
	$(RM) $(OBJS) $(LIBOBJS)

lint:	lint_PROG

include ../Makefile.targ
