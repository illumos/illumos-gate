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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	libssh.a
VERS =		.1

OBJECTS =	\
		addrmatch.o \
		atomicio.o \
		authfd.o \
		authfile.o \
		bufaux.o \
		buffer.o \
		canohost.o \
		channels.o \
		cipher.o \
		cipher-ctr.o \
		compat.o \
		compress.o \
		crc32.o \
		deattack.o \
		dh.o \
		dispatch.o \
		engine.o \
		entropy.o \
		fatal.o \
		g11n.o \
		hostfile.o \
		key.o \
		kex.o \
		kexdh.o \
		kexdhc.o \
		kexdhs.o \
		kexgex.o \
		kexgexc.o \
		kexgexs.o \
		kexgssc.o \
		kexgsss.o \
		log.o \
		mac.o \
		match.o \
		misc.o \
		mpaux.o \
		msg.o \
		nchan.o \
		packet.o \
		progressmeter.o \
		proxy-io.o \
		radix.o \
		readconf.o \
		readpass.o \
		rsa.o \
		sftp-common.o \
		ssh-dss.o \
		ssh-gss.o \
		ssh-rsa.o \
		tildexpand.o \
		ttymodes.o \
		uidswap.o \
		uuencode.o \
		xlist.o \
		xmalloc.o

include $(SRC)/lib/Makefile.lib

BUILD.AR =       $(RM) $@ ; $(AR) $(ARFLAGS) $@ $(AROBJS)

SRCDIR =	../common
SRCS =		$(OBJECTS:%.o=../common/%.c)

LIBS =		$(LIBRARY) $(LINTLIB)

# Define LDLIBS conditionally for lintcheck, rather than in general, since
# we're building an archive library which itself links to nothing, we just
# want lint to know about these libraries.
lintcheck  :=	LDLIBS += -lcrypto -lz -lsocket -lnsl -lc
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

POFILE_DIR =	../..

.KEEP_STATE:

all:		$(LIBS)

# lint requires the (not installed) lint library
lint:		$(LINTLIB) .WAIT lintcheck

include $(SRC)/lib/Makefile.targ

objs/%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.ssh-common
include ../../Makefile.msg.targ
