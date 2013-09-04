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

MANSECT= 	3tnf

MANFILES= 	TNF_DECLARE_RECORD.3tnf		\
	 	TNF_PROBE.3tnf			\
	 	libtnfctl.3tnf			\
	 	tnf_process_disable.3tnf	\
	 	tnfctl_buffer_alloc.3tnf	\
	 	tnfctl_close.3tnf		\
	 	tnfctl_indirect_open.3tnf	\
	 	tnfctl_internal_open.3tnf	\
	 	tnfctl_kernel_open.3tnf		\
	 	tnfctl_pid_open.3tnf		\
	 	tnfctl_probe_apply.3tnf		\
	 	tnfctl_probe_state_get.3tnf	\
	 	tnfctl_register_funcs.3tnf	\
	 	tnfctl_strerror.3tnf		\
	 	tnfctl_trace_attrs_get.3tnf	\
	 	tnfctl_trace_state_set.3tnf	\
	 	tracing.3tnf

MANLINKS=	TNF_DEBUG.3tnf				\
		TNF_DEFINE_RECORD_1.3tnf		\
		TNF_DEFINE_RECORD_2.3tnf		\
		TNF_DEFINE_RECORD_3.3tnf		\
		TNF_DEFINE_RECORD_4.3tnf		\
		TNF_DEFINE_RECORD_5.3tnf		\
		TNF_PROBE_0.3tnf			\
		TNF_PROBE_0_DEBUG.3tnf			\
		TNF_PROBE_1.3tnf			\
		TNF_PROBE_1_DEBUG.3tnf			\
		TNF_PROBE_2.3tnf			\
		TNF_PROBE_2_DEBUG.3tnf			\
		TNF_PROBE_3.3tnf			\
		TNF_PROBE_3_DEBUG.3tnf			\
		TNF_PROBE_4.3tnf			\
		TNF_PROBE_4_DEBUG.3tnf			\
		TNF_PROBE_5.3tnf			\
		TNF_PROBE_5_DEBUG.3tnf			\
		tnf_process_enable.3tnf			\
		tnf_thread_disable.3tnf			\
		tnf_thread_enable.3tnf			\
		tnfctl_buffer_dealloc.3tnf		\
		tnfctl_check_libs.3tnf			\
		tnfctl_continue.3tnf			\
		tnfctl_exec_open.3tnf			\
		tnfctl_filter_list_add.3tnf		\
		tnfctl_filter_list_delete.3tnf		\
		tnfctl_filter_list_get.3tnf		\
		tnfctl_filter_state_set.3tnf		\
		tnfctl_probe_apply_ids.3tnf		\
		tnfctl_probe_connect.3tnf		\
		tnfctl_probe_disable.3tnf		\
		tnfctl_probe_disconnect_all.3tnf	\
		tnfctl_probe_enable.3tnf		\
		tnfctl_probe_trace.3tnf			\
		tnfctl_probe_untrace.3tnf

TNF_DEFINE_RECORD_1.3tnf		:= LINKSRC = TNF_DECLARE_RECORD.3tnf
TNF_DEFINE_RECORD_2.3tnf		:= LINKSRC = TNF_DECLARE_RECORD.3tnf
TNF_DEFINE_RECORD_3.3tnf		:= LINKSRC = TNF_DECLARE_RECORD.3tnf
TNF_DEFINE_RECORD_4.3tnf		:= LINKSRC = TNF_DECLARE_RECORD.3tnf
TNF_DEFINE_RECORD_5.3tnf		:= LINKSRC = TNF_DECLARE_RECORD.3tnf

TNF_DEBUG.3tnf				:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_0.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_0_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_1.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_1_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_2.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_2_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_3.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_3_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_4.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_4_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_5.3tnf			:= LINKSRC = TNF_PROBE.3tnf
TNF_PROBE_5_DEBUG.3tnf			:= LINKSRC = TNF_PROBE.3tnf

tnf_process_enable.3tnf			:= LINKSRC = tnf_process_disable.3tnf
tnf_thread_disable.3tnf			:= LINKSRC = tnf_process_disable.3tnf
tnf_thread_enable.3tnf			:= LINKSRC = tnf_process_disable.3tnf

tnfctl_buffer_dealloc.3tnf		:= LINKSRC = tnfctl_buffer_alloc.3tnf

tnfctl_check_libs.3tnf			:= LINKSRC = tnfctl_indirect_open.3tnf

tnfctl_continue.3tnf			:= LINKSRC = tnfctl_pid_open.3tnf
tnfctl_exec_open.3tnf			:= LINKSRC = tnfctl_pid_open.3tnf

tnfctl_probe_apply_ids.3tnf		:= LINKSRC = tnfctl_probe_apply.3tnf

tnfctl_probe_connect.3tnf		:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_probe_disable.3tnf		:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_probe_disconnect_all.3tnf	:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_probe_enable.3tnf		:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_probe_trace.3tnf			:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_probe_untrace.3tnf		:= LINKSRC = tnfctl_probe_state_get.3tnf
tnfctl_filter_list_add.3tnf		:= LINKSRC = tnfctl_trace_state_set.3tnf
tnfctl_filter_list_delete.3tnf		:= LINKSRC = tnfctl_trace_state_set.3tnf
tnfctl_filter_list_get.3tnf		:= LINKSRC = tnfctl_trace_state_set.3tnf
tnfctl_filter_state_set.3tnf		:= LINKSRC = tnfctl_trace_state_set.3tnf

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
