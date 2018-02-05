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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY = libscsi.a
VERS = .1

OBJECTS = \
	scsi_engine.o \
	scsi_errno.o \
	scsi_status.o \
	scsi_subr.o

include ../../../Makefile.lib
include ../../Makefile.defs

SRCS = $(OBJECTS:%.o=../common/%.c)
CSTD = $(CSTD_GNU99)
CPPFLAGS += -I../common -I. -D_REENTRANT
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CFLAGS += $(CCVERBOSE)

CERRWARN += -_gcc=-Wno-type-limits

LDLIBS += \
	-lumem \
	-lc
LIBS =		$(DYNLIB) $(LINTLIB)
ROOTLIBDIR =	$(ROOTSCSILIBDIR)
ROOTLIBDIR64 =	$(ROOTSCSILIBDIR)/$(MACH64)

CLEANFILES += \
	../common/scsi_errno.c

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all : $(LIBS)

lint : lintcheck

../common/scsi_errno.c: ../common/mkerrno.sh ../common/libscsi.h
	sh ../common/mkerrno.sh < ../common/libscsi.h > $@

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ
include ../../Makefile.rootdirs
