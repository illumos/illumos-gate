#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		availdevs

include ../Makefile.cmd

ROOTCMDDIR=	$(ROOTLIB)/zfs

INCS += -I$(ADJUNCT_PROTO)/usr/include/libxml2

#
# There is no lint library for libxml2, so we need to avoid linking against
# it during lint, as well as turning off the warnings lint would generate.
#
LDLIBS += -lzfs_jni -lnvpair -lzfs
all install := LDLIBS += -lxml2
LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2

CPPFLAGS += $(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
$(NOT_RELEASE_BUILD) CPPFLAGS += -DDEBUG

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTCMD)

clean:

lint: lint_PROG

include ../Makefile.targ
