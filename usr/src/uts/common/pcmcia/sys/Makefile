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
#ident	"%W%	%E% SMI"
#
# Copyright (c) 1995-1996 by Sun Microsystems, Inc.
# All rights reserved.
#
# uts/common/pcmcia/sys/Makefile
#
# include global definitions
include ../../../../Makefile.master

HDRS=	cis.h			\
	cis_handlers.h		\
	cis_protos.h		\
	cs.h			\
	cs_priv.h		\
	cs_strings.h		\
	cs_types.h		\
	cs_stubs.h

ROOTDIR=	$(ROOT)/usr/include/sys
ROOTHDRS=	$(HDRS:%=$(ROOTDIR)/%)

# install rules

$(ROOTDIR)/%: %
	$(INS.file)

CHECKHDRS= $(HDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIR) .WAIT $(ROOTHDRS)

$(ROOTDIR):
	$(INS.dir)

check:	$(CHECKHDRS)
