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
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/common/ipp/Makefile
#	This makefile installs IPP framework and module header files
#
# include global definitions
include ../../../Makefile.master

HDRS =				\
	ipp.h			\
	ipp_impl.h		\
	ippctl.h		\
	ipp_config.h

IPGPCHDRS =			\
	ipgpc.h

DSCPMKHDRS =			\
	dscpmk.h

DLCOSMKHDRS =			\
	dlcosmk.h

FLOWACCTHDRS =			\
	flowacct.h

METERSHDRS =			\
	meter.h

ipgpc/%.check:	ipgpc/%.h
	$(DOT_H_CHECK)

dscpmk/%.check:	dscpmk/%.h
	$(DOT_H_CHECK)

meters/%.check:	meters/%.h
	$(DOT_H_CHECK)

flowacct/%.check:flowacct/%.h
	$(DOT_H_CHECK)

dlcosmk/%.check:	dlcosmk/%.h
	$(DOT_H_CHECK)

CHECKHDRS =						\
	$(HDRS:%.h=%.check)				\
	$(IPGPCHDRS:%.h=ipgpc/%.check)			\
	$(DSCPMKHDRS:%.h=dscpmk/%.check)		\
	$(DLCOSMKHDRS:%.h=dlcosmk/%.check)		\
	$(FLOWACCTHDRS:%.h=flowacct/%.check)		\
	$(METERSHDRS:%.h=meters/%.check)

ROOTDIR =	$(ROOT)/usr/include/ipp

ROOTDIRS =						\
	$(ROOTDIR)					\
	$(ROOTDIR)/ipgpc				\
	$(ROOTDIR)/dscpmk				\
	$(ROOTDIR)/meters				\
	$(ROOTDIR)/dlcosmk				\
	$(ROOTDIR)/flowacct

ROOTHDRS =	$(HDRS:%=$(ROOTDIR)/%)
ROOTMODHDRS =	$(IPGPCHDRS:%=$(ROOTDIR)/ipgpc/%)	\
		$(DSCPMKHDRS:%=$(ROOTDIR)/dscpmk/%)	\
		$(DLCOSMKHDRS:%=$(ROOTDIR)/dlcosmk/%)	\
		$(FLOWACCTHDRS:%=$(ROOTDIR)/flowacct/%)	\
		$(METERSHDRS:%=$(ROOTDIR)/meters/%)

$(ROOTDIR)/%:	%
	$(INS.file)

$(ROOTDIR)/flowacct/%:	flowacct/%
	$(INS.file)

$(ROOTDIR)/ipgpc/%:	ipgpc/%
	$(INS.file)

$(ROOTDIR)/dscpmk/%:	dscpmk/%
	$(INS.file)

$(ROOTDIR)/dlcosmk/%:	dlcosmk/%
	$(INS.file)

$(ROOTDIR)/meters/%:	meters/%
	$(INS.file)

.KEEP_STATE:

.PARALLEL:			\
	$(CHECKHDRS)		\
	$(ROOTHDRS)

install_h:			\
	$(ROOTDIRS)		\
	$(ROOTHDRS)		\
	.WAIT			\
	$(ROOTMODHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)

