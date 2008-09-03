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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/ssh/libopenbsd-compat/Makefile.com
#

LIBRARY	=	libopenbsd-compat.a
VERS =		.1

OBJECTS =	\
		bsd-arc4random.o \
		bsd-cray.o \
		bsd-cygwin_util.o \
		bsd-getpeereid.o \
		bsd-misc.o \
		bsd-asprintf.o \
		bsd-snprintf.o \
		bsd-waitpid.o \
		fake-getaddrinfo.o \
		fake-getnameinfo.o \
		xmmap.o \
		base64.o \
		bindresvport.o \
		daemon.o \
		dirname.o \
		getcwd.o \
		getgrouplist.o \
		getopt.o \
		glob.o \
		inet_aton.o \
		inet_ntoa.o \
		inet_ntop.o \
		mktemp.o \
		readpassphrase.o \
		realpath.o \
		rresvport.o \
		setenv.o \
		setproctitle.o \
		sigact.o \
		strlcat.o \
		strlcpy.o \
		strmode.o \
		port-irix.o \
		port-aix.o

include $(SRC)/lib/Makefile.lib

BUILD.AR =	$(RM) $@ ; $(AR) $(ARFLAGS) $@ $(AROBJS)

SRCDIR =	../common
SRCS =		$(OBJECTS:%.o=../common/%.c)

LIBS =		$(LIBRARY) $(LINTLIB)

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

POFILE_DIR =	../..

.KEEP_STATE:

all:		$(LIBS)

# lint requires the (non-installed) lint library
lint:		$(LINTLIB) .WAIT lintcheck

include $(SRC)/lib/Makefile.targ

objs/%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.ssh-common
include ../../Makefile.msg.targ
