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

PROG       = fpsd

SRCS = fpsd_main.c fpsd_sched.c fpsd_util.c fpsd_esutil.c fpsd_log.c
OBJS = $(SRCS:%.c=%.o)

MANIFEST = $(PROG).xml

include ../../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

ROOTLIBFPS= $(ROOTLIB)/fps
ROOTLIBFPSDAEMON= $(PROG:%=$(ROOTLIBFPS)/%)

POFILES = $(SRCS:%.c=%.po)

CPPFLAGS += -I../include -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS

CFLAGS += $(CCMT)

LDLIBS  += -lc -ldevinfo -ldoor -lkstat -lscf -lgen

LDFLAGS += $(ZIGNORE)

.KEEP_STATE:

##### beginning of dependency lines #####

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTLIBFPS) $(ROOTLIBFPSDAEMON) $(ROOTMANIFESTDIR) \
         $(ROOTMANIFEST)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

$(ROOTLIBFPS):
	$(INS.dir)

$(ROOTLIBFPS)/%:      %
	$(INS.file)

$(POFILE):  $(POFILES) FRC
	 @$(RM) $@
	 $(CAT) $(POFILES) > $@

include ../../Makefile.targ

FRC:
