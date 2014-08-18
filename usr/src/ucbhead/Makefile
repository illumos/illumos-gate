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
# Copyright 1989-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ucbhead/Makefile
#
# include global definitions
include ../Makefile.master

LN= ln

HDRS= curses.h dbm.h setjmp.h sgtty.h signal.h stdio.h strings.h unistd.h

SYSHDRS= \
dir.h        fcntl.h      file.h       ioctl.h \
param.h      resource.h   rusage.h     signal.h \
sysmacros.h  ttychars.h   types.h      vfs.h \
wait.h

ROOTHDRS= $(HDRS:%=$(ROOT)/usr/ucbinclude/%)  \
	$(SYSHDRS:%=$(ROOT)/usr/ucbinclude/sys/%)

DIRS= sys
ROOTDIRS= $(ROOT)/usr/ucbinclude $(DIRS:%=$(ROOT)/usr/ucbinclude/%)

FCNTLH= $(ROOT)/usr/ucbinclude/fcntl.h
SYSFCNTLH= $(ROOT)/usr/ucbinclude/sys/fcntl.h

INS.FCNTLH=	$(RM) $@; $(SYMLINK) sys/fcntl.h $@

# install rules
$(ROOT)/usr/ucbinclude/sys/%: sys/%
	$(INS.file)

$(ROOT)/usr/ucbinclude/%: %
	$(INS.file)

.KEEP_STATE:

install_h: $(ROOTDIRS) $(ROOTHDRS) $(FCNTLH)

$(FCNTLH): $(SYSFCNTLH)
	$(INS.FCNTLH)

$(ROOTDIRS):
	$(INS.dir)

