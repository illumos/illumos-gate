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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =		libipp-listener.a
VERS =			.0
OBJECTS = \
	cancel-job.o common.o create-job.o cups-accept-jobs.o \
	cups-get-classes.o cups-get-default.o cups-get-printers.o \
	cups-move-job.o cups-reject-jobs.o disable-printer.o enable-printer.o \
	get-job-attributes.o get-jobs.o get-printer-attributes.o hold-job.o \
	ipp-listener.o pause-printer.o print-job.o purge-jobs.o release-job.o \
	restart-job.o resume-printer.o send-document.o set-job-attributes.o \
	set-printer-attributes.o validate-job.o

include ../../../Makefile.lib
include ../../../Makefile.rootfs

SRCDIR =	../common

ROOTLIBDIR=	$(ROOT)/usr/lib

LIBS =			$(DYNLIB)

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-DSOLARIS_PRIVATE_POST_0_9
CPPFLAGS +=	-I$(SRCDIR)
CPPFLAGS +=	-I../../libpapi-common/common
CPPFLAGS +=	-I../../libipp-core/common

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

MAPFILES =	$(SRCDIR)/mapfile

LDLIBS +=	-lipp-core -lpapi -lc -lsocket -lnsl

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../../Makefile.targ
