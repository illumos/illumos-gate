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
# cmd/ssh/sftp/Makefile

PROG =		sftp

OBJS =		\
		sftp.o \
		sftp-client.o \
		sftp-glob.o

SRCS =		$(OBJS:.o=.c)

include ../../Makefile.cmd
include ../Makefile.ssh-common

DIRS= $(ROOTLIBSUNSSH)

LDLIBS +=	$(SSH_COMMON_LDLIBS) -lsocket -lcrypto -ltecla

POFILE_DIR =	..

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(PROG)

$(PROG):	$(OBJS) ../libssh/$(MACH)/libssh.a ../libopenbsd-compat/$(MACH)/libopenbsd-compat.a
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(DYNFLAGS)
	$(POST_PROCESS)

$(DIRS):
	$(INS.dir)

$(ROOTBIN)/sftp: $(ROOTLIBSUNSSH)/sftp
	-$(RM) $@; $(SYMLINK) ../lib/sunssh/sftp $@

install:	all $(DIRS) $(ROOTPROG)

clean:
	$(RM) -f $(OBJS) $(PROG)

lint:		lint_SRCS

include ../Makefile.msg.targ
include ../../Makefile.targ
