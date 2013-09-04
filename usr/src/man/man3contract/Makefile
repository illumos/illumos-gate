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

MANSECT= 	3contract

MANFILES= 	ct_ctl_adopt.3contract			\
	 	ct_dev_status_get_dev_state.3contract	\
	 	ct_dev_tmpl_set_aset.3contract		\
	 	ct_event_read.3contract			\
	 	ct_pr_event_get_pid.3contract		\
	 	ct_pr_status_get_param.3contract	\
	 	ct_pr_tmpl_set_transfer.3contract	\
	 	ct_status_read.3contract		\
	 	ct_tmpl_activate.3contract

MANLINKS=	ct_ctl_abandon.3contract		\
		ct_ctl_ack.3contract			\
		ct_ctl_nack.3contract			\
		ct_ctl_newct.3contract			\
		ct_ctl_qack.3contract			\
		ct_dev_status_get_aset.3contract	\
		ct_dev_status_get_minor.3contract	\
		ct_dev_status_get_noneg.3contract	\
		ct_dev_tmpl_clear_noneg.3contract	\
		ct_dev_tmpl_get_aset.3contract		\
		ct_dev_tmpl_get_minor.3contract		\
		ct_dev_tmpl_get_noneg.3contract		\
		ct_dev_tmpl_set_minor.3contract		\
		ct_dev_tmpl_set_noneg.3contract		\
		ct_event_free.3contract			\
		ct_event_get_ctid.3contract		\
		ct_event_get_evid.3contract		\
		ct_event_get_flags.3contract		\
		ct_event_get_nevid.3contract		\
		ct_event_get_newct.3contract		\
		ct_event_get_type.3contract		\
		ct_event_read_critical.3contract	\
		ct_event_reliable.3contract		\
		ct_event_reset.3contract		\
		ct_pr_event_get_exitstatus.3contract	\
		ct_pr_event_get_gcorefile.3contract	\
		ct_pr_event_get_pcorefile.3contract	\
		ct_pr_event_get_ppid.3contract		\
		ct_pr_event_get_sender.3contract	\
		ct_pr_event_get_senderct.3contract	\
		ct_pr_event_get_signal.3contract	\
		ct_pr_event_get_zcorefile.3contract	\
		ct_pr_status_get_contracts.3contract	\
		ct_pr_status_get_fatal.3contract	\
		ct_pr_status_get_members.3contract	\
		ct_pr_status_get_svc_aux.3contract	\
		ct_pr_status_get_svc_creator.3contract	\
		ct_pr_status_get_svc_ctid.3contract	\
		ct_pr_status_get_svc_fmri.3contract	\
		ct_pr_tmpl_get_fatal.3contract		\
		ct_pr_tmpl_get_param.3contract		\
		ct_pr_tmpl_get_svc_aux.3contract	\
		ct_pr_tmpl_get_svc_fmri.3contract	\
		ct_pr_tmpl_get_transfer.3contract	\
		ct_pr_tmpl_set_fatal.3contract		\
		ct_pr_tmpl_set_param.3contract		\
		ct_pr_tmpl_set_svc_aux.3contract	\
		ct_pr_tmpl_set_svc_fmri.3contract	\
		ct_status_free.3contract		\
		ct_status_get_cookie.3contract		\
		ct_status_get_critical.3contract	\
		ct_status_get_holder.3contract		\
		ct_status_get_id.3contract		\
		ct_status_get_informative.3contract	\
		ct_status_get_nevents.3contract		\
		ct_status_get_nevid.3contract		\
		ct_status_get_ntime.3contract		\
		ct_status_get_qtime.3contract		\
		ct_status_get_state.3contract		\
		ct_status_get_type.3contract		\
		ct_status_get_zoneid.3contract		\
		ct_tmpl_clear.3contract			\
		ct_tmpl_create.3contract		\
		ct_tmpl_get_cookie.3contract		\
		ct_tmpl_get_critical.3contract		\
		ct_tmpl_get_informative.3contract	\
		ct_tmpl_set_cookie.3contract		\
		ct_tmpl_set_critical.3contract		\
		ct_tmpl_set_informative.3contract

ct_ctl_abandon.3contract		:= LINKSRC = ct_ctl_adopt.3contract
ct_ctl_ack.3contract			:= LINKSRC = ct_ctl_adopt.3contract
ct_ctl_nack.3contract			:= LINKSRC = ct_ctl_adopt.3contract
ct_ctl_newct.3contract			:= LINKSRC = ct_ctl_adopt.3contract
ct_ctl_qack.3contract			:= LINKSRC = ct_ctl_adopt.3contract

ct_dev_status_get_aset.3contract	:= LINKSRC = ct_dev_status_get_dev_state.3contract
ct_dev_status_get_minor.3contract	:= LINKSRC = ct_dev_status_get_dev_state.3contract
ct_dev_status_get_noneg.3contract	:= LINKSRC = ct_dev_status_get_dev_state.3contract

ct_dev_tmpl_clear_noneg.3contract	:= LINKSRC = ct_dev_tmpl_set_aset.3contract
ct_dev_tmpl_get_aset.3contract		:= LINKSRC = ct_dev_tmpl_set_aset.3contract
ct_dev_tmpl_get_minor.3contract		:= LINKSRC = ct_dev_tmpl_set_aset.3contract
ct_dev_tmpl_get_noneg.3contract		:= LINKSRC = ct_dev_tmpl_set_aset.3contract
ct_dev_tmpl_set_minor.3contract		:= LINKSRC = ct_dev_tmpl_set_aset.3contract
ct_dev_tmpl_set_noneg.3contract		:= LINKSRC = ct_dev_tmpl_set_aset.3contract

ct_event_free.3contract			:= LINKSRC = ct_event_read.3contract
ct_event_get_ctid.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_get_evid.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_get_flags.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_get_nevid.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_get_newct.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_get_type.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_read_critical.3contract	:= LINKSRC = ct_event_read.3contract
ct_event_reliable.3contract		:= LINKSRC = ct_event_read.3contract
ct_event_reset.3contract		:= LINKSRC = ct_event_read.3contract

ct_pr_event_get_exitstatus.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_gcorefile.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_pcorefile.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_ppid.3contract		:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_sender.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_senderct.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_signal.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract
ct_pr_event_get_zcorefile.3contract	:= LINKSRC = ct_pr_event_get_pid.3contract

ct_pr_status_get_contracts.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_fatal.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_members.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_svc_aux.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_svc_creator.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_svc_ctid.3contract	:= LINKSRC = ct_pr_status_get_param.3contract
ct_pr_status_get_svc_fmri.3contract	:= LINKSRC = ct_pr_status_get_param.3contract

ct_pr_tmpl_get_fatal.3contract		:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_get_param.3contract		:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_get_svc_aux.3contract	:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_get_svc_fmri.3contract	:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_get_transfer.3contract	:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_set_fatal.3contract		:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_set_param.3contract		:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_set_svc_aux.3contract	:= LINKSRC = ct_pr_tmpl_set_transfer.3contract
ct_pr_tmpl_set_svc_fmri.3contract	:= LINKSRC = ct_pr_tmpl_set_transfer.3contract

ct_status_free.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_cookie.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_critical.3contract	:= LINKSRC = ct_status_read.3contract
ct_status_get_holder.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_id.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_informative.3contract	:= LINKSRC = ct_status_read.3contract
ct_status_get_nevents.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_nevid.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_ntime.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_qtime.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_state.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_type.3contract		:= LINKSRC = ct_status_read.3contract
ct_status_get_zoneid.3contract		:= LINKSRC = ct_status_read.3contract

ct_tmpl_clear.3contract			:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_create.3contract		:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_get_cookie.3contract		:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_get_critical.3contract		:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_get_informative.3contract	:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_set_cookie.3contract		:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_set_critical.3contract		:= LINKSRC = ct_tmpl_activate.3contract
ct_tmpl_set_informative.3contract	:= LINKSRC = ct_tmpl_activate.3contract

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
