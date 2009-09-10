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
# uts/common/net/Makefile
#
# include global definitions
include ../../../Makefile.master

HDRS=	af.h if.h if_arp.h if_dl.h if_types.h route.h pfkeyv2.h pfpolicy.h \
	ppp-comp.h ppp_defs.h pppio.h vjcompress.h sppptun.h pppoe.h radix.h \
	wpa.h simnet.h bridge.h bridge_impl.h trill.h

ROOTDIRS= $(ROOT)/usr/include/net

ROOTHDRS= $(HDRS:%=$(ROOT)/usr/include/net/%)

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)
