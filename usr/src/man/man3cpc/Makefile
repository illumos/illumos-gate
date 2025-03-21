#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3cpc

MANFILES=	cpc.3cpc			\
		cpc_access.3cpc			\
		cpc_bind_curlwp.3cpc		\
		cpc_bind_event.3cpc		\
		cpc_buf_create.3cpc		\
		cpc_count_usr_events.3cpc	\
		cpc_enable.3cpc			\
		cpc_event.3cpc			\
		cpc_event_diff.3cpc		\
		cpc_getcpuver.3cpc		\
		cpc_npic.3cpc			\
		cpc_open.3cpc			\
		cpc_pctx_bind_event.3cpc	\
		cpc_set_create.3cpc		\
		cpc_seterrfn.3cpc		\
		cpc_seterrhndlr.3cpc		\
		cpc_shared_open.3cpc		\
		cpc_strtoevent.3cpc		\
		cpc_version.3cpc		\
		generic_events.3cpc		\
		pctx_capture.3cpc		\
		pctx_set_events.3cpc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
