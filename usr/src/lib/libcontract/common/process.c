/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ctfs.h>
#include <sys/contract.h>
#include <sys/contract/process.h>
#include <errno.h>
#include <unistd.h>
#include <libnvpair.h>
#include <libcontract.h>
#include "libcontract_impl.h"

/*
 * Process contract template routines
 */

int
ct_pr_tmpl_set_transfer(int fd, ctid_t ctid)
{
	return (ct_tmpl_set_internal(fd, CTPP_SUBSUME, ctid));
}

int
ct_pr_tmpl_set_fatal(int fd, uint_t events)
{
	return (ct_tmpl_set_internal(fd, CTPP_EV_FATAL, events));
}

int
ct_pr_tmpl_set_param(int fd, uint_t param)
{
	return (ct_tmpl_set_internal(fd, CTPP_PARAMS, param));
}

int
ct_pr_tmpl_set_svc_fmri(int fd, const char *fmri)
{
	return (ct_tmpl_set_internal_string(fd, CTPP_SVC_FMRI, fmri));
}

int
ct_pr_tmpl_set_svc_aux(int fd, const char *desc)
{
	return (ct_tmpl_set_internal_string(fd, CTPP_CREATOR_AUX, desc));
}

int
ct_pr_tmpl_get_transfer(int fd, ctid_t *ctid)
{
	return (ct_tmpl_get_internal(fd, CTPP_SUBSUME, (uint_t *)ctid));
}

int
ct_pr_tmpl_get_fatal(int fd, uint_t *events)
{
	return (ct_tmpl_get_internal(fd, CTPP_EV_FATAL, events));
}

int
ct_pr_tmpl_get_param(int fd, uint_t *param)
{
	return (ct_tmpl_get_internal(fd, CTPP_PARAMS, param));
}

int
ct_pr_tmpl_get_svc_fmri(int fd, char *fmri, size_t size)
{
	return (ct_tmpl_get_internal_string(fd, CTPP_SVC_FMRI, fmri, size));
}

int
ct_pr_tmpl_get_svc_aux(int fd, char *desc, size_t size)
{
	return (ct_tmpl_get_internal_string(fd, CTPP_CREATOR_AUX, desc, size));
}

/*
 * Process contract event routines
 */

int
ct_pr_event_get_pid(ct_evthdl_t evthdl, pid_t *pid)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPE_PID, (uint_t *)pid));
}

int
ct_pr_event_get_ppid(ct_evthdl_t evthdl, pid_t *ppid)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_FORK)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPE_PPID, (uint_t *)ppid));
}

int
ct_pr_event_get_signal(ct_evthdl_t evthdl, int *signal)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_SIGNAL)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPE_SIGNAL, (uint_t *)signal));
}

int
ct_pr_event_get_sender(ct_evthdl_t evthdl, pid_t *sender)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_SIGNAL)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPE_SENDER, (uint_t *)sender));
}

int
ct_pr_event_get_senderct(ct_evthdl_t evthdl, ctid_t *sendct)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_SIGNAL)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPE_SENDCT, (uint_t *)sendct));
}

int
ct_pr_event_get_exitstatus(ct_evthdl_t evthdl, int *exitstatus)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_EXIT)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_int32(info->nvl, CTPE_EXITSTATUS, exitstatus));
}

int
ct_pr_event_get_pcorefile(ct_evthdl_t evthdl, const char **pcorefile)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_CORE)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPE_PCOREFILE,
	    (char **)pcorefile));
}

int
ct_pr_event_get_gcorefile(ct_evthdl_t evthdl, const char **gcorefile)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_CORE)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPE_GCOREFILE,
	    (char **)gcorefile));
}

int
ct_pr_event_get_zcorefile(ct_evthdl_t evthdl, const char **zcorefile)
{
	struct ctlib_event_info *info = evthdl;
	if (info->event.ctev_cttype != CTT_PROCESS)
		return (EINVAL);
	if (info->event.ctev_type != CT_PR_EV_CORE)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPE_ZCOREFILE,
	    (char **)zcorefile));
}

/*
 * Process contract status routines
 */

int
ct_pr_status_get_param(ct_stathdl_t stathdl, uint_t *param)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPS_PARAMS, param));
}

int
ct_pr_status_get_fatal(ct_stathdl_t stathdl, uint_t *fatal)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32(info->nvl, CTPS_EV_FATAL, fatal));
}

int
ct_pr_status_get_members(ct_stathdl_t stathdl, pid_t **members, uint_t *n)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32_array(info->nvl, CTPS_MEMBERS,
	    (uint_t **)members, n));
}

int
ct_pr_status_get_contracts(ct_stathdl_t stathdl, ctid_t **contracts,
    uint_t *n)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_uint32_array(info->nvl, CTPS_CONTRACTS,
	    (uint_t **)contracts, n));
}

int
ct_pr_status_get_svc_fmri(ct_stathdl_t stathdl, char **svc_fmri)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPS_SVC_FMRI, svc_fmri));
}

int
ct_pr_status_get_svc_aux(ct_stathdl_t stathdl, char **svc_aux)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPS_CREATOR_AUX, svc_aux));
}

int
ct_pr_status_get_svc_ctid(ct_stathdl_t stathdl, ctid_t *ctid)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_int32(info->nvl, CTPS_SVC_CTID,
	    (int32_t *)ctid));
}

int
ct_pr_status_get_svc_creator(ct_stathdl_t stathdl, char **svc_creator)
{
	struct ctlib_status_info *info = stathdl;
	if (info->status.ctst_type != CTT_PROCESS)
		return (EINVAL);
	if (info->nvl == NULL)
		return (ENOENT);
	return (nvlist_lookup_string(info->nvl, CTPS_SVC_CREATOR, svc_creator));
}
