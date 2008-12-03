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
#

HDRS =          libfdisk.h
ROOTHDRDIR=     $(ROOT)/usr/include
ROOTHDRS=       $(HDRS:%=$(ROOTHDRDIR)/%)
CHECKDIRS=	$(HDRS:%.h=%.check)
HDRDIR =        ./

$(ROOTHDRDIR)/%: %
        $(INS.file)

all :=		TARGET = all
install_h:=	TARGET = install_h

install_h: $(ROOTHDRS)

LIBRARY= libfdisk.a
VERS= .1

PICS=   pics/libfdisk.o

pics/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

OBJECTS= \
libfdisk.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR =	.

C99MODE=	$(C99_DISABLE)

MAPFILES += mapfile-vers

CPPFLAGS += -I.
LDLIBS += -lc

i386_CFLAGS += -D_LARGEFILE64_SOURCE
i386_CFLAGS += -D_FILE_OFFSET_BITS=64

.KEEP_STATE:

LIBS=	$(DYNLIB) $(LINTLIB)

all: $(LIBS)

lint: lintcheck

install: all $(ROOTLIBS) $(ROOTLINKS) $(ROOTLINT)


# include library targets
include ../../Makefile.targ
