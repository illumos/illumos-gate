#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	ct_tmpl_activate
include		<libcontract.h>
declaration	int ct_tmpl_activate(int)
version		SUNW_1.1
end

function	ct_tmpl_clear
include		<libcontract.h>
declaration	int ct_tmpl_clear(int)
version		SUNW_1.1
end

function	ct_tmpl_create
include		<libcontract.h>
declaration	int ct_tmpl_create(int, ctid_t *)
version		SUNW_1.1
end

function	ct_tmpl_set_cookie
include		<libcontract.h>
declaration	int ct_tmpl_set_cookie(int, uint64_t)
version		SUNW_1.1
end

function	ct_tmpl_get_cookie
include		<libcontract.h>
declaration	int ct_tmpl_get_cookie(int, uint64_t *)
version		SUNW_1.1
end

function	ct_tmpl_set_critical
include		<libcontract.h>
declaration	int ct_tmpl_set_critical(int, uint_t)
version		SUNW_1.1
end

function	ct_tmpl_get_critical
include		<libcontract.h>
declaration	int ct_tmpl_get_critical(int, uint_t *)
version		SUNW_1.1
end

function	ct_tmpl_set_informative
include		<libcontract.h>
declaration	int ct_tmpl_set_informative(int, uint_t)
version		SUNW_1.1
end

function	ct_tmpl_get_informative
include		<libcontract.h>
declaration	int ct_tmpl_get_informative(int, uint_t *)
version		SUNW_1.1
end

function	ct_ctl_adopt
include		<libcontract.h>
declaration	int ct_ctl_adopt(int)
version		SUNW_1.1
end

function	ct_ctl_abandon
include		<libcontract.h>
declaration	int ct_ctl_abandon(int)
version		SUNW_1.1
end

function	ct_ctl_ack
include		<libcontract.h>
declaration	int ct_ctl_ack(int, ctevid_t)
version		SUNW_1.1
end

function	ct_ctl_qack
include		<libcontract.h>
declaration	int ct_ctl_qack(int, ctevid_t)
version		SUNW_1.1
end

function	ct_ctl_newct
include		<libcontract.h>
declaration	int ct_ctl_newct(int, ctevid_t, int)
version		SUNW_1.1
end

function	ct_status_read
include		<libcontract.h>
declaration	int ct_status_read(int, int, ct_stathdl_t *)
version		SUNW_1.1
end

function	ct_status_free
include		<libcontract.h>
declaration	void ct_status_free(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_id
include		<libcontract.h>
declaration	ctid_t ct_status_get_id(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_zoneid
include		<libcontract.h>
declaration	zoneid_t ct_status_get_zoneid(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_type
include		<libcontract.h>
declaration	const char *ct_status_get_type(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_holder
include		<libcontract.h>
declaration	id_t ct_status_get_holder(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_state
include		<libcontract.h>
declaration	ctstate_t ct_status_get_state(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_nevents
include		<libcontract.h>
declaration	int ct_status_get_nevents(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_ntime
include		<libcontract.h>
declaration	int ct_status_get_ntime(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_qtime
include		<libcontract.h>
declaration	int ct_status_get_qtime(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_nevid
include		<libcontract.h>
declaration	ctevid_t ct_status_get_nevid(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_informative
include		<libcontract.h>
declaration	uint_t ct_status_get_informative(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_critical
include		<libcontract.h>
declaration	uint_t ct_status_get_critical(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_status_get_cookie
include		<libcontract.h>
declaration	uint64_t ct_status_get_cookie(ct_stathdl_t)
version		SUNW_1.1
end

function	ct_event_read
include		<libcontract.h>
declaration	int ct_event_read(int, ct_evthdl_t *)
version		SUNW_1.1
end

function	ct_event_read_critical
include		<libcontract.h>
declaration	int ct_event_read_critical(int, ct_evthdl_t *)
version		SUNW_1.1
end

function	ct_event_reset
include		<libcontract.h>
declaration	int ct_event_reset(int)
version		SUNW_1.1
end

function	ct_event_reliable
include		<libcontract.h>
declaration	int ct_event_reliable(int)
version		SUNW_1.1
end

function	ct_event_free
include		<libcontract.h>
declaration	void ct_event_free(ct_evthdl_t)
version		SUNW_1.1
end

function	ct_event_get_flags
include		<libcontract.h>
declaration	uint_t ct_event_get_flags(ct_evthdl_t)
version		SUNW_1.1
end

function	ct_event_get_ctid
include		<libcontract.h>
declaration	ctid_t ct_event_get_ctid(ct_evthdl_t)
version		SUNW_1.1
end

function	ct_event_get_evid
include		<libcontract.h>
declaration	ctevid_t ct_event_get_evid(ct_evthdl_t)
version		SUNW_1.1
end

function	ct_event_get_type
include		<libcontract.h>
declaration	uint_t ct_event_get_type(ct_evthdl_t)
version		SUNW_1.1
end

function	ct_event_get_nevid
include		<libcontract.h>
declaration	int ct_event_get_nevid(ct_evthdl_t, ctevid_t *)
version		SUNW_1.1
end

function	ct_event_get_newct
include		<libcontract.h>
declaration	int ct_event_get_newct(ct_evthdl_t, ctid_t *)
version		SUNW_1.1
end

function	ct_pr_tmpl_set_transfer
include		<libcontract.h>
declaration	int ct_pr_tmpl_set_transfer(int, ctid_t)
version		SUNW_1.1
end

function	ct_pr_tmpl_set_fatal
include		<libcontract.h>
declaration	int ct_pr_tmpl_set_fatal(int, uint_t)
version		SUNW_1.1
end

function	ct_pr_tmpl_set_param
include		<libcontract.h>
declaration	int ct_pr_tmpl_set_param(int, uint_t)
version		SUNW_1.1
end

function	ct_pr_tmpl_get_transfer
include		<libcontract.h>
declaration	int ct_pr_tmpl_get_transfer(int, ctid_t *)
version		SUNW_1.1
end

function	ct_pr_tmpl_get_fatal
include		<libcontract.h>
declaration	int ct_pr_tmpl_get_fatal(int, uint_t *)
version		SUNW_1.1
end

function	ct_pr_tmpl_get_param
include		<libcontract.h>
declaration	int ct_pr_tmpl_get_param(int, uint_t *)
version		SUNW_1.1
end

function	ct_pr_event_get_pid
include		<libcontract.h>
declaration	int ct_pr_event_get_pid(ct_evthdl_t, pid_t *)
version		SUNW_1.1
end

function	ct_pr_event_get_ppid
include		<libcontract.h>
declaration	int ct_pr_event_get_ppid(ct_evthdl_t, pid_t *)
version		SUNW_1.1
end

function	ct_pr_event_get_signal
include		<libcontract.h>
declaration	int ct_pr_event_get_signal(ct_evthdl_t, int *)
version		SUNW_1.1
end

function	ct_pr_event_get_sender
include		<libcontract.h>
declaration	int ct_pr_event_get_sender(ct_evthdl_t, pid_t *)
version		SUNW_1.1
end

function	ct_pr_event_get_senderct
include		<libcontract.h>
declaration	int ct_pr_event_get_senderct(ct_evthdl_t, ctid_t *)
version		SUNW_1.1
end

function	ct_pr_event_get_exitstatus
include		<libcontract.h>
declaration	int ct_pr_event_get_exitstatus(ct_evthdl_t, int *)
version		SUNW_1.1
end

function	ct_pr_event_get_pcorefile
include		<libcontract.h>
declaration	int ct_pr_event_get_pcorefile(ct_evthdl_t, const char **)
version		SUNW_1.1
end

function	ct_pr_event_get_gcorefile
include		<libcontract.h>
declaration	int ct_pr_event_get_gcorefile(ct_evthdl_t, const char **)
version		SUNW_1.1
end

function	ct_pr_event_get_zcorefile
include		<libcontract.h>
declaration	int ct_pr_event_get_zcorefile(ct_evthdl_t, const char **)
version		SUNW_1.1
end

function	ct_pr_status_get_param
include		<libcontract.h>
declaration	int ct_pr_status_get_param(ct_stathdl_t, uint_t *)
version		SUNW_1.1
end

function	ct_pr_status_get_fatal
include		<libcontract.h>
declaration	int ct_pr_status_get_fatal(ct_stathdl_t, uint_t *)
version		SUNW_1.1
end

function	ct_pr_status_get_members
include		<libcontract.h>
declaration	int ct_pr_status_get_members(ct_stathdl_t, pid_t **, uint_t *)
version		SUNW_1.1
end

function	ct_pr_status_get_contracts
include		<libcontract.h>
declaration	int ct_pr_status_get_contracts(ct_stathdl_t, ctid_t **, uint_t *)
version		SUNW_1.1
end
