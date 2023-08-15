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
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG =	vntsd
SRCS =	auth.c cmd.c common.c console.c listen.c queue.c read.c vntsd.c \
	vntsdvcc.c write.c
OBJS = $(SRCS:.c=.o)

MANIFEST = vntsd.xml
SVCMETHOD = svc-vntsd

include ../Makefile.cmd

POFILES = $(SRCS:.c=.po)
POFILE = $(PROG)_msg.po

CFLAGS += $(CCVERBOSE)

LDLIBS += -lsocket -lnsl -lsecdb

ROOTCMDDIR =	$(ROOTLIB)/ldoms
ROOTMANIFESTDIR = $(ROOTSVCPLATFORMSUN4V)

.KEEP_STATE:

all: $(PROG)

install: all		\
	$(ROOTCMD)	\
	$(ROOTMANIFEST) \
	$(ROOTSVCMETHOD)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

check: $(CHKMANIFEST)

lint: lint_SRCS

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
