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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = vscand
SRCS =	vs_main.c	\
		vs_eng.c	\
		vs_icap.c	\
		vs_svc.c	\
		vs_door.c	\
		vs_stats.c
HDRS	= vs_incl.h vs_icap.h
OBJS = $(SRCS:%.c=%.o)
POFILES = $(SRCS:.c=.po)

include ../../Makefile.cmd

DEFS = -I.
LDLIBS += -lsecdb -lumem -lbsm -lnsl -lsocket -lc -L$(ROOT)/usr/lib/vscan -lvscan
LDFLAGS += -R/usr/lib/vscan
CFLAGS += $(DEFS)
CFLAGS += $(CCVERBOSE)
CFLAGS += -D_FILE_OFFSET_BITS=64
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-switch

LINTFLAGS += -mu
CSTD =       $(CSTD_GNU99)
C99LMODE =      -Xc99=%all

MANIFEST = vscan.xml
ROOTMANIFESTDIR= $(ROOTSVCSYSTEM)/filesystem
ROOTVSCANDIR=   $(ROOTLIB)/vscan
ROOTVSCANFILE = $(PROG:%=$(ROOTVSCANDIR)/%)
CHECKHDRS=	$(HDRS:%.h=%.check)

FILEMODE = 0555
$(ROOTVSCANFILE):= FILEMODE = 0555

$(ROOTVSCANDIR):
	$(INS.dir)

$(ROOTVSCANDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(PROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

check: $(CHECKHDRS) $(CHKMANIFEST)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

include ../../Makefile.targ

install: all .WAIT $(ROOTVSCANDIR) $(ROOTVSCANFILE) $(ROOTMANIFEST)
