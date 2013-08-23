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

PROG= cdrw

OBJS= main.o mmc.o device.o transport.o util.o msgs.o misc_scsi.o dumpinfo.o \
      toshiba.o bstream.o options.o trackio.o write_image.o blank.o \
      write_audio.o dae.o copycd.o

include ../Makefile.cmd
include ../hal/Makefile.hal

SRCS= $(OBJS:.o=.c)

LDLIBS +=	-lhal -lsecdb
NONLINTLDLIBS =	-ldbus-1
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
CPPFLAGS +=	-D_REENTRANT -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(HAL_DBUS_CPPFLAGS)
LINTFLAGS += 	-um

$(ROOTBIN)/cdrw := FILEMODE = 04755

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS) $(NONLINTLDLIBS) $(CFLAGS)
	$(POST_PROCESS)

install: all $(ROOTPROG) 

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

$(POFILE) : $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS) | $(XGETTEXT) $(XGETFLAGS) -
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

sb: $(SRCS)
	$(COMPILE.c) -xsbfast $(SRCS)

include ../Makefile.targ
