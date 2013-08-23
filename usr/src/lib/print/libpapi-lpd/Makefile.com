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

LIBRARY =		psm-lpd.a
VERS =			.1
COMMON_OBJS = lpd-misc.o
OBJECTS = job.o library.o lpd-cancel.o lpd-job.o lpd-query.o printer.o \
	service.o $(COMMON_OBJS)

include ../../../Makefile.lib
include ../../../Makefile.rootfs

SRCDIR =	../common

ROOTLIBDIR=	$(ROOT)/usr/lib/print
ROOTLIBDIR64=	$(ROOT)/usr/lib/print/$(MACH)

EXTRALINKS=	$(ROOTLIBDIR)/psm-rfc-1179.so
$(EXTRALINKS):	$(ROOTLINKS)
	$(RM) $@; $(SYMLINK) $(LIBLINKS) $@

LIBS =			$(DYNLIB)

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)
CPPFLAGS +=	-I../../libpapi-common/common

CERRWARN +=	-_gcc=-Wno-unused-variable

MAPFILES =	$(SRCDIR)/mapfile

LDLIBS +=	-lc

CLOBBERFILES += $(PROG)

.KEEP_STATE:

all:	$(LIBS) $(PROG)

lint:	lintcheck

include ../../../Makefile.targ

#
#	NEEDED to build lpd-port
#
PROG =	lpd-port
LPD_PORT_OBJS = lpd-port.o $(COMMON_OBJS)

$(PROG) :=	LDLIBS += -lsocket -lnsl -lsendfile

PROG_OBJS = $(LPD_PORT_OBJS:%=pics/%)
OBJS += $(PROG_OBJS)

LDFLAGS.cmd = \
        $(ENVLDFLAGS1) $(ENVLDFLAGS2) $(ENVLDFLAGS3) $(BDIRECT) \
        $(MAPFILE.NES:%=-M%) $(MAPFILE.PGA:%=-M%) $(MAPFILE.NED:%=-M%)

$(PROG):	$(PROG_OBJS)
	$(LINK.c) -o $@ $(PROG_OBJS) $(LDFLAGS.cmd) $(LDLIBS)
	$(POST_PROCESS)

# needed for the 'install' phase
ROOTLIBPRINTPROG =	$(PROG:%=$(ROOTLIBDIR)/%)
$(ROOTLIBPRINTPROG) :=	FILEMODE = 04511

$(ROOTLIBDIR)/%:	$(ROOTLIBDIR) %
	$(INS.file)
$(ROOTLIBDIR):
	$(INS.dir)
