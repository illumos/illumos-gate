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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 1989-1999,2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/sparc/v7/sys/Makefile
#
# include global definitions
include ../../../../Makefile.master

HDRS=  \
	machpcb.h	\
	machtrap.h	\
	mutex_impl.h	\
	privregs.h	\
	prom_isa.h	\
	psr.h		\
	traptrace.h

ROOTINCV7= $(ROOT)/usr/include/v7
ROOTDIR= $(ROOTINCV7)/sys
ROOTDIRS= $(ROOTDIR)

ROOTHDRS= $(HDRS:%=$(ROOTDIR)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS)

install_h: $(ROOTINCV7) .WAIT $(ROOTDIRS) .WAIT $(ROOTHDRS)

$(ROOTINCV7):
	$(INS.dir)

$(ROOTDIRS):	$(ROOTINCV7)
	$(INS.dir)

check:	$(CHECKHDRS)
