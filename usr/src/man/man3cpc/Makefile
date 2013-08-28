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

MANSECT= 	3cpc

MANFILES= 	cpc.3cpc			\
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

MANLINKS=	cpc_bind_cpu.3cpc			\
		cpc_bind_pctx.3cpc			\
		cpc_buf_add.3cpc			\
		cpc_buf_copy.3cpc			\
		cpc_buf_destroy.3cpc			\
		cpc_buf_get.3cpc			\
		cpc_buf_hrtime.3cpc			\
		cpc_buf_set.3cpc			\
		cpc_buf_sub.3cpc			\
		cpc_buf_tick.3cpc			\
		cpc_buf_zero.3cpc			\
		cpc_caps.3cpc				\
		cpc_cciname.3cpc			\
		cpc_close.3cpc				\
		cpc_count_sys_events.3cpc		\
		cpc_cpuref.3cpc				\
		cpc_disable.3cpc			\
		cpc_event_accum.3cpc			\
		cpc_eventtostr.3cpc			\
		cpc_getcciname.3cpc			\
		cpc_getcpuref.3cpc			\
		cpc_getnpic.3cpc			\
		cpc_getusage.3cpc			\
		cpc_pctx_invalidate.3cpc		\
		cpc_pctx_rele.3cpc			\
		cpc_pctx_take_sample.3cpc		\
		cpc_rele.3cpc				\
		cpc_request_preset.3cpc			\
		cpc_set_add_request.3cpc		\
		cpc_set_destroy.3cpc			\
		cpc_set_restart.3cpc			\
		cpc_set_sample.3cpc			\
		cpc_shared_bind_event.3cpc		\
		cpc_shared_close.3cpc			\
		cpc_shared_rele.3cpc			\
		cpc_shared_take_sample.3cpc		\
		cpc_take_sample.3cpc			\
		cpc_unbind.3cpc				\
		cpc_walk_attrs.3cpc			\
		cpc_walk_events_all.3cpc		\
		cpc_walk_events_pic.3cpc		\
		cpc_walk_generic_events_all.3cpc	\
		cpc_walk_generic_events_pic.3cpc	\
		cpc_walk_names.3cpc			\
		cpc_walk_requests.3cpc			\
		pctx_create.3cpc			\
		pctx_release.3cpc			\
		pctx_run.3cpc

cpc_bind_cpu.3cpc			:= LINKSRC = cpc_bind_curlwp.3cpc
cpc_bind_pctx.3cpc			:= LINKSRC = cpc_bind_curlwp.3cpc
cpc_request_preset.3cpc			:= LINKSRC = cpc_bind_curlwp.3cpc
cpc_set_restart.3cpc			:= LINKSRC = cpc_bind_curlwp.3cpc
cpc_unbind.3cpc				:= LINKSRC = cpc_bind_curlwp.3cpc

cpc_rele.3cpc				:= LINKSRC = cpc_bind_event.3cpc
cpc_take_sample.3cpc			:= LINKSRC = cpc_bind_event.3cpc

cpc_buf_add.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_copy.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_destroy.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_get.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_hrtime.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_set.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_sub.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_tick.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_buf_zero.3cpc			:= LINKSRC = cpc_buf_create.3cpc
cpc_set_sample.3cpc			:= LINKSRC = cpc_buf_create.3cpc

cpc_count_sys_events.3cpc		:= LINKSRC = cpc_count_usr_events.3cpc

cpc_disable.3cpc			:= LINKSRC = cpc_enable.3cpc

cpc_event_accum.3cpc			:= LINKSRC = cpc_event_diff.3cpc

cpc_getcciname.3cpc			:= LINKSRC = cpc_getcpuver.3cpc
cpc_getcpuref.3cpc			:= LINKSRC = cpc_getcpuver.3cpc
cpc_getnpic.3cpc			:= LINKSRC = cpc_getcpuver.3cpc
cpc_getusage.3cpc			:= LINKSRC = cpc_getcpuver.3cpc
cpc_walk_names.3cpc			:= LINKSRC = cpc_getcpuver.3cpc

cpc_caps.3cpc				:= LINKSRC = cpc_npic.3cpc
cpc_cciname.3cpc			:= LINKSRC = cpc_npic.3cpc
cpc_cpuref.3cpc				:= LINKSRC = cpc_npic.3cpc
cpc_walk_attrs.3cpc			:= LINKSRC = cpc_npic.3cpc
cpc_walk_events_all.3cpc		:= LINKSRC = cpc_npic.3cpc
cpc_walk_events_pic.3cpc		:= LINKSRC = cpc_npic.3cpc
cpc_walk_generic_events_all.3cpc	:= LINKSRC = cpc_npic.3cpc
cpc_walk_generic_events_pic.3cpc	:= LINKSRC = cpc_npic.3cpc

cpc_close.3cpc				:= LINKSRC = cpc_open.3cpc

cpc_pctx_invalidate.3cpc		:= LINKSRC = cpc_pctx_bind_event.3cpc
cpc_pctx_rele.3cpc			:= LINKSRC = cpc_pctx_bind_event.3cpc
cpc_pctx_take_sample.3cpc		:= LINKSRC = cpc_pctx_bind_event.3cpc

cpc_set_add_request.3cpc		:= LINKSRC = cpc_set_create.3cpc
cpc_set_destroy.3cpc			:= LINKSRC = cpc_set_create.3cpc
cpc_walk_requests.3cpc			:= LINKSRC = cpc_set_create.3cpc

cpc_shared_bind_event.3cpc		:= LINKSRC = cpc_shared_open.3cpc
cpc_shared_close.3cpc			:= LINKSRC = cpc_shared_open.3cpc
cpc_shared_rele.3cpc			:= LINKSRC = cpc_shared_open.3cpc
cpc_shared_take_sample.3cpc		:= LINKSRC = cpc_shared_open.3cpc

cpc_eventtostr.3cpc			:= LINKSRC = cpc_strtoevent.3cpc

pctx_create.3cpc			:= LINKSRC = pctx_capture.3cpc
pctx_release.3cpc			:= LINKSRC = pctx_capture.3cpc
pctx_run.3cpc				:= LINKSRC = pctx_capture.3cpc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
