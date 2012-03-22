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
/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include "ses2_impl.h"

static int
elem_setprop_device(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_device_ctl_impl_t *dip;
	const char *name;
	boolean_t v;

	if ((dip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		dip->sdci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_RMV) == 0)
		dip->sdci_rqst_remove = v;
	else if (strcmp(name, SES_DEV_PROP_READY_TO_INSERT) == 0)
		dip->sdci_rqst_insert = v;
	else if (strcmp(name, SES_DEV_PROP_REQ_MISSING) == 0)
		dip->sdci_rqst_missing = v;
	else if (strcmp(name, SES_DEV_PROP_DO_NOT_REMOVE) == 0)
		dip->sdci_do_not_remove = v;
	else if (strcmp(name, SES_DEV_PROP_REQ_ACTIVE) == 0)
		dip->sdci_rqst_active = v;
	else if (strcmp(name, SES_DEV_PROP_BYP_B) == 0)
		dip->sdci_enable_byp_b = v;
	else if (strcmp(name, SES_DEV_PROP_BYP_A) == 0)
		dip->sdci_enable_byp_a = v;
	else if (strcmp(name, SES_PROP_OFF) == 0)
		dip->sdci_device_off = v;
	else if (strcmp(name, SES_DEV_PROP_FAULT_RQSTD) == 0)
		dip->sdci_rqst_fault = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_psu(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_psu_ctl_impl_t *pip;
	const char *name;
	boolean_t v;

	if ((pip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		pip->spci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_REQUESTED_ON) == 0)
		pip->spci_rqst_on = v;
	else if (strcmp(name, SES_PROP_FAIL) == 0)
		pip->spci_rqst_fail = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_cooling(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_cooling_ctl_impl_t *cip;
	const char *name;
	boolean_t v1;
	uint64_t v64;

	if ((cip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);

	if (strcmp(name, SES_COOLING_PROP_SPEED_CODE) == 0) {
		(void) nvpair_value_uint64(nvp, &v64);
		cip->scci_requested_speed_code = v64;
		return (0);
	}

	(void) nvpair_value_boolean_value(nvp, &v1);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		cip->scci_rqst_ident = v1;
	else if (strcmp(name, SES_PROP_REQUESTED_ON) == 0)
		cip->scci_rqst_on = v1;
	else if (strcmp(name, SES_PROP_FAIL) == 0)
		cip->scci_rqst_fail = v1;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_temp(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_temp_ctl_impl_t *tip;
	const char *name;
	boolean_t v;

	if ((tip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		tip->stci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		tip->stci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_lock(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_lock_ctl_impl_t *lip;
	const char *name;
	boolean_t v;

	if ((lip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		lip->slci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		lip->slci_rqst_ident = v;
	else if (strcmp(name, SES_LOCK_PROP_UNLOCKED) == 0)
		lip->slci_unlock = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_alarm(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_alarm_ctl_impl_t *aip;
	const char *name;
	boolean_t v;

	if ((aip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		aip->saci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		aip->saci_rqst_ident = v;
	else if (strcmp(name, SES_ALARM_PROP_UNRECOV) == 0)
		aip->saci_unrecov = v;
	else if (strcmp(name, SES_ALARM_PROP_CRIT) == 0)
		aip->saci_crit = v;
	else if (strcmp(name, SES_ALARM_PROP_NONCRIT) == 0)
		aip->saci_noncrit = v;
	else if (strcmp(name, SES_ALARM_PROP_INFO) == 0)
		aip->saci_info = v;
	else if (strcmp(name, SES_ALARM_PROP_REMIND) == 0)
		aip->saci_set_remind = v;
	else if (strcmp(name, SES_ALARM_PROP_MUTED) == 0)
		aip->saci_set_mute = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_esc(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_controller_ctl_impl_t *cip;
	const char *name;
	boolean_t v;

	if ((cip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		cip->scci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		cip->scci_rqst_ident = v;
	else if (strcmp(name, SES_ESC_PROP_SELECT) == 0)
		cip->scci_select_element = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_scc(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_scc_ctl_impl_t *sip;
	const char *name;
	boolean_t v;

	if ((sip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		sip->ssci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		sip->ssci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_ups(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_ups_ctl_impl_t *uip;
	const char *name;
	boolean_t v;

	if ((uip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		uip->suci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		uip->suci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_cache(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_nvcache_ctl_impl_t *cip;
	const char *name;
	boolean_t v;

	if ((cip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		cip->snci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		cip->snci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_keypad(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_keypad_ctl_impl_t *kip;
	const char *name;
	boolean_t v;

	if ((kip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		kip->skci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		kip->skci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_display(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_display_ctl_impl_t *dip;
	const char *name;
	boolean_t v1;
	uint16_t v16;
	uint64_t v64;

	if ((dip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);


	name = nvpair_name(nvp);

	if (strcmp(name, SES_DPY_PROP_MODE) == 0) {
		(void) nvpair_value_uint64(nvp, &v64);
		dip->sdci_display_mode = v64;
		return (0);
	} else if (strcmp(name, SES_DPY_PROP_CHAR) == 0) {
		(void) nvpair_value_uint16(nvp, &v16);
		SCSI_WRITE16(&dip->sdci_display_character, v16);
		return (0);
	}

	(void) nvpair_value_boolean_value(nvp, &v1);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		dip->sdci_rqst_fail = v1;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		dip->sdci_rqst_ident = v1;
	else
		ses_panic("Bad property %s", name);
	return (0);
}

static int
elem_setprop_px(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_port_ctl_impl_t *pip;
	const char *name;
	boolean_t v;

	if ((pip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);

	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		pip->spci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		pip->spci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_DISABLED) == 0)
		pip->spci_disable = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_lang(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_lang_ctl_impl_t *lip;
	const char *name;
	boolean_t v1;
	uint64_t v64;

	if ((lip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);

	if (strcmp(name, SES_LANG_PROP_LANGCODE) == 0) {
		(void) nvpair_value_uint64(nvp, &v64);
		SCSI_WRITE16(&lip->slci_language_code, v64);
		return (0);
	}

	(void) nvpair_value_boolean_value(nvp, &v1);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		lip->slci_rqst_ident = v1;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_comm(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_comm_ctl_impl_t *cip;
	const char *name;
	boolean_t v;

	if ((cip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		cip->scci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		cip->scci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_DISABLED) == 0)
		cip->scci_disable = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_voltage(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_voltage_ctl_impl_t *vip;
	const char *name;
	boolean_t v;

	if ((vip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		vip->svci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		vip->svci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_current(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_current_ctl_impl_t *cip;
	const char *name;
	boolean_t v;

	if ((cip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		cip->scci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		cip->scci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_itp(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_itp_ctl_impl_t *iip;
	const char *name;
	boolean_t v;

	if ((iip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		iip->sici_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		iip->sici_rqst_ident = v;
	else if (strcmp(name, SES_ITP_PROP_ENABLED) == 0)
		iip->sici_enable = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_sse(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_ss_ctl_impl_t *sip;
	const char *name;
	boolean_t v;

	if ((sip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		sip->ssci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		sip->ssci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_arraydev(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_array_device_ctl_impl_t *aip;
	const char *name;
	boolean_t v;

	if ((aip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_AD_PROP_RR_ABORT) == 0)
		aip->sadci_rqst_rr_abort = v;
	else if (strcmp(name, SES_AD_PROP_REBUILD) == 0)
		aip->sadci_rqst_rebuild = v;
	else if (strcmp(name, SES_AD_PROP_IN_FAILED_ARRAY) == 0)
		aip->sadci_rqst_in_failed_array = v;
	else if (strcmp(name, SES_AD_PROP_IN_CRIT_ARRAY) == 0)
		aip->sadci_rqst_in_crit_array = v;
	else if (strcmp(name, SES_AD_PROP_CONS_CHK) == 0)
		aip->sadci_rqst_cons_check = v;
	else if (strcmp(name, SES_AD_PROP_HOT_SPARE) == 0)
		aip->sadci_rqst_hot_spare = v;
	else if (strcmp(name, SES_AD_PROP_RSVD_DEVICE) == 0)
		aip->sadci_rqst_rsvd_device = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		aip->sadci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_RMV) == 0)
		aip->sadci_rqst_remove = v;
	else if (strcmp(name, SES_DEV_PROP_READY_TO_INSERT) == 0)
		aip->sadci_rqst_insert = v;
	else if (strcmp(name, SES_DEV_PROP_REQ_MISSING) == 0)
		aip->sadci_rqst_missing = v;
	else if (strcmp(name, SES_DEV_PROP_DO_NOT_REMOVE) == 0)
		aip->sadci_do_not_remove = v;
	else if (strcmp(name, SES_DEV_PROP_REQ_ACTIVE) == 0)
		aip->sadci_rqst_active = v;
	else if (strcmp(name, SES_DEV_PROP_BYP_B) == 0)
		aip->sadci_enable_byp_b = v;
	else if (strcmp(name, SES_DEV_PROP_BYP_A) == 0)
		aip->sadci_enable_byp_a = v;
	else if (strcmp(name, SES_PROP_OFF) == 0)
		aip->sadci_device_off = v;
	else if (strcmp(name, SES_DEV_PROP_FAULT_RQSTD) == 0)
		aip->sadci_rqst_fault = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_expander(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_expander_ctl_impl_t *eip;
	const char *name;
	boolean_t v;

	if ((eip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_FAIL) == 0)
		eip->seci_rqst_fail = v;
	else if (strcmp(name, SES_PROP_IDENT) == 0)
		eip->seci_rqst_ident = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_setprop_sasconn(ses_plugin_t *sp, ses_node_t *np, ses2_diag_page_t page,
    nvpair_t *nvp)
{
	ses2_sasconn_ctl_impl_t *sip;
	const char *name;
	boolean_t v;

	if ((sip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	name = nvpair_name(nvp);
	(void) nvpair_value_boolean_value(nvp, &v);

	if (strcmp(name, SES_PROP_IDENT) == 0)
		sip->ssci_rqst_ident = v;
	else if (strcmp(name, SES_PROP_FAIL) == 0)
		sip->ssci_rqst_fail = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

static int
elem_common_setprop_threshold(ses_plugin_t *sp, ses_node_t *np,
    ses2_diag_page_t page, nvpair_t *nvp)
{
	ses2_threshold_impl_t *tip;
	ses2_threshold_in_page_impl_t *tp;
	ses2_threshold_out_page_impl_t *tpout;
	const char *name;
	uint64_t v;
	size_t len = 0;
	size_t i, trnums;

	ASSERT(page == SES2_DIAGPAGE_THRESHOLD_IO);

	if ((tip = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, np, B_FALSE)) == NULL)
		return (-1);

	/* Get whole IN and OUT pages to copy filled thresholds */
	if ((tpout = ses_plugin_ctlpage_lookup(sp, ses_node_snapshot(np),
	    page, 0, NULL, B_FALSE)) == NULL)
		return (-1);
	if ((tp = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
	    page, NULL, &len)) == NULL)
		return (-1);

	len -= offsetof(ses2_threshold_in_page_impl_t, stipi_thresholds[0]);
	trnums = len / sizeof (ses2_threshold_impl_t);

	/* Do copy filled thresholds from In to Out page */
	for (i = 0; i < trnums; i++) {
		boolean_t filled = B_FALSE;
		ses2_threshold_impl_t *toutp = &tpout->stopi_thresholds[i];
		ses2_threshold_impl_t *tinp = &tp->stipi_thresholds[i];

		if (tinp->sti_high_crit != 0 || tinp->sti_high_warn != 0 ||
		    tinp->sti_low_crit != 0 || tinp->sti_low_warn != 0)
			filled = B_TRUE;

		if (toutp->sti_high_crit == 0 && toutp->sti_high_warn == 0 &&
		    toutp->sti_low_crit == 0 && toutp->sti_low_warn == 0 &&
		    filled)
			*toutp = *tinp;
	}

	name = nvpair_name(nvp);
	(void) nvpair_value_uint64(nvp, &v);

	if (strcmp(name, SES_PROP_THRESH_CRIT_HI) == 0)
		tip->sti_high_crit = v;
	else if (strcmp(name, SES_PROP_THRESH_CRIT_LO) == 0)
		tip->sti_low_crit = v;
	else if (strcmp(name, SES_PROP_THRESH_WARN_HI) == 0)
		tip->sti_high_warn = v;
	else if (strcmp(name, SES_PROP_THRESH_WARN_LO) == 0)
		tip->sti_low_warn = v;
	else
		ses_panic("Bad property %s", name);

	return (0);
}

#define	SES_THRESHOLD_CTL_PROPS	\
{	\
	.scp_name = SES_PROP_THRESH_CRIT_HI,	\
	.scp_type = DATA_TYPE_UINT64,	\
	.scp_num = SES2_DIAGPAGE_THRESHOLD_IO,	\
	.scp_setprop = elem_common_setprop_threshold	\
},	\
{	\
	.scp_name = SES_PROP_THRESH_WARN_HI,	\
	.scp_type = DATA_TYPE_UINT64,	\
	.scp_num = SES2_DIAGPAGE_THRESHOLD_IO,	\
	.scp_setprop = elem_common_setprop_threshold	\
},	\
{	\
	.scp_name = SES_PROP_THRESH_CRIT_LO,	\
	.scp_type = DATA_TYPE_UINT64,	\
	.scp_num = SES2_DIAGPAGE_THRESHOLD_IO,	\
	.scp_setprop = elem_common_setprop_threshold	\
},	\
{	\
	.scp_name = SES_PROP_THRESH_WARN_LO,	\
	.scp_type = DATA_TYPE_UINT64,	\
	.scp_num = SES2_DIAGPAGE_THRESHOLD_IO,	\
	.scp_setprop = elem_common_setprop_threshold	\
}

static const ses2_ctl_prop_t device_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_PROP_RMV,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_READY_TO_INSERT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_REQ_MISSING,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_DO_NOT_REMOVE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_REQ_ACTIVE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_BYP_B,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_BYP_A,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_PROP_OFF,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	.scp_name = SES_DEV_PROP_FAULT_RQSTD,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_device,
},
{
	NULL
}
};

static const ses2_ctl_prop_t psu_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_psu
},
{
	.scp_name = SES_PROP_REQUESTED_ON,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_psu
},
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_psu
},
{
	NULL
}
};

static const ses2_ctl_prop_t cooling_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cooling
},
{
	.scp_name = SES_COOLING_PROP_SPEED_CODE,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cooling
},
{
	.scp_name = SES_PROP_REQUESTED_ON,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cooling
},
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cooling
},
{
	NULL
}
};

static const ses2_ctl_prop_t temp_props[] = {
	SES_COMMON_CTL_PROPS,
	SES_THRESHOLD_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_temp
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_temp
},
{
	NULL
}
};

static const ses2_ctl_prop_t lock_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_lock
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_lock
},
{
	.scp_name = SES_LOCK_PROP_UNLOCKED,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_lock
},
{
	NULL
}
};

static const ses2_ctl_prop_t alarm_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_UNRECOV,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_CRIT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_NONCRIT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_INFO,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_REMIND,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	.scp_name = SES_ALARM_PROP_MUTED,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_alarm
},
{
	NULL
}
};

static const ses2_ctl_prop_t esc_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_esc
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_esc
},
{
	.scp_name = SES_ESC_PROP_SELECT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_esc
},
{
	NULL
}
};

static const ses2_ctl_prop_t scc_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_scc
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_scc
},
{
	NULL
}
};

static const ses2_ctl_prop_t cache_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cache
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_cache
},
{
	NULL
}
};

static const ses2_ctl_prop_t ups_props[] = {
	SES_COMMON_CTL_PROPS,
	SES_THRESHOLD_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_ups
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_ups
},
{
	NULL
}
};

static const ses2_ctl_prop_t display_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_DPY_PROP_MODE,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_display
},
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_display
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_display
},
{
	.scp_name = SES_DPY_PROP_CHAR,
	.scp_type = DATA_TYPE_UINT16,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_display
},
{
	NULL
}
};

static const ses2_ctl_prop_t keypad_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_keypad
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_keypad
},
{
	NULL
}
};

static const ses2_ctl_prop_t px_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_px
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_px
},
{
	.scp_name = SES_PROP_DISABLED,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_px
},
{
	NULL
}
};

static const ses2_ctl_prop_t lang_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_lang
},
{
	.scp_name = SES_LANG_PROP_LANGCODE,
	.scp_type = DATA_TYPE_UINT64,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_lang
},
{
	NULL
}
};

static const ses2_ctl_prop_t comm_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_comm
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_comm
},
{
	.scp_name = SES_PROP_DISABLED,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_comm
},
{
	NULL
}
};

static const ses2_ctl_prop_t voltage_props[] = {
	SES_COMMON_CTL_PROPS,
	SES_THRESHOLD_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_voltage
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_voltage
},
{
	NULL
}
};

static const ses2_ctl_prop_t current_props[] = {
	SES_COMMON_CTL_PROPS,
	SES_THRESHOLD_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_current
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_current
},
{
	NULL
}
};

static const ses2_ctl_prop_t itp_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_itp
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_itp
},
{
	.scp_name = SES_ITP_PROP_ENABLED,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_itp
},
{
	NULL
}
};

static const ses2_ctl_prop_t sse_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_sse
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_sse
},
{
	NULL
}
};

static const ses2_ctl_prop_t arraydev_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_AD_PROP_RR_ABORT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_REBUILD,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_IN_FAILED_ARRAY,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_IN_CRIT_ARRAY,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_CONS_CHK,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_HOT_SPARE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_RSVD_DEVICE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_AD_PROP_OK,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_PROP_RMV,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_READY_TO_INSERT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_REQ_MISSING,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_DO_NOT_REMOVE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_REQ_ACTIVE,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_BYP_B,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_BYP_A,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_PROP_OFF,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	.scp_name = SES_DEV_PROP_FAULT_RQSTD,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_arraydev
},
{
	NULL
}
};

static const ses2_ctl_prop_t expander_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_expander
},
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_expander
},
{
	NULL
}
};

static const ses2_ctl_prop_t sasconn_props[] = {
	SES_COMMON_CTL_PROPS,
{
	.scp_name = SES_PROP_IDENT,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_sasconn
},
{
	.scp_name = SES_PROP_FAIL,
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	.scp_setprop = elem_setprop_sasconn
},
{
	NULL
}
};

/*ARGSUSED*/
static int
elem_setdef_threshold(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_threshold_impl_t *tip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTL64(props, SES_PROP_THRESH_CRIT_HI, tip->sti_high_crit);
	SES_NV_CTL64(props, SES_PROP_THRESH_CRIT_LO, tip->sti_low_crit);
	SES_NV_CTL64(props, SES_PROP_THRESH_WARN_HI, tip->sti_high_warn);
	SES_NV_CTL64(props, SES_PROP_THRESH_WARN_LO, tip->sti_low_warn);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_device(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_device_ctl_impl_t *dip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, dip->sdci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_RMV, dip->sdci_rqst_remove);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_READY_TO_INSERT,
	    dip->sdci_rqst_insert);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_REQ_MISSING,
	    dip->sdci_rqst_missing);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_DO_NOT_REMOVE,
	    dip->sdci_do_not_remove);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_REQ_ACTIVE,
	    dip->sdci_rqst_active);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_BYP_B, dip->sdci_enable_byp_b);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_BYP_A, dip->sdci_enable_byp_a);
	SES_NV_CTLBOOL(props, SES_PROP_OFF, dip->sdci_device_off);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_FAULT_RQSTD,
	    dip->sdci_rqst_fault);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_psu(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_psu_ctl_impl_t *pip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, pip->spci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_REQUESTED_ON, pip->spci_rqst_on);
	SES_NV_CTLBOOL(props, SES_PROP_FAIL, pip->spci_rqst_fail);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_cooling(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_cooling_ctl_impl_t *cip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, cip->scci_rqst_ident);
	SES_NV_CTL64(props, SES_COOLING_PROP_SPEED_CODE,
	    cip->scci_requested_speed_code);
	SES_NV_CTLBOOL(props, SES_PROP_REQUESTED_ON, cip->scci_rqst_on);
	SES_NV_CTLBOOL(props, SES_PROP_FAIL, cip->scci_rqst_fail);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_temp(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_temp_ctl_impl_t *tip = data;
	nvlist_t *props = ses_node_props(np);

	if (page == SES2_DIAGPAGE_THRESHOLD_IO)
		return (elem_setdef_threshold(np, page, data));

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, tip->stci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, tip->stci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_lock(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_lock_ctl_impl_t *lip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, lip->slci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, lip->slci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_LOCK_PROP_UNLOCKED, lip->slci_unlock);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_alarm(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_alarm_ctl_impl_t *aip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, aip->saci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, aip->saci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_UNRECOV, aip->saci_unrecov);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_CRIT, aip->saci_crit);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_NONCRIT, aip->saci_noncrit);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_INFO, aip->saci_info);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_REMIND, aip->saci_set_remind);
	SES_NV_CTLBOOL(props, SES_ALARM_PROP_MUTED, aip->saci_set_mute);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_esc(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_controller_ctl_impl_t *cip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, cip->scci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, cip->scci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_ESC_PROP_SELECT,
	    cip->scci_select_element);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_scc(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_scc_ctl_impl_t *sip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, sip->ssci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, sip->ssci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_cache(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_nvcache_ctl_impl_t *cip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, cip->snci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, cip->snci_rqst_ident);

	return (0);
}

static int
elem_setdef_ups(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_ups_ctl_impl_t *uip = data;
	nvlist_t *props = ses_node_props(np);

	if (page == SES2_DIAGPAGE_THRESHOLD_IO)
		return (elem_setdef_threshold(np, page, data));

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, uip->suci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, uip->suci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_display(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_display_ctl_impl_t *dip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTL64(props, SES_DPY_PROP_MODE, dip->sdci_display_mode);
	SES_NV_CTLBOOL(props, SES_PROP_FAIL, dip->sdci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, dip->sdci_rqst_ident);
	SES_NV_CTL16(props, SES_DPY_PROP_CHAR,
	    dip->sdci_display_character);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_keypad(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_keypad_ctl_impl_t *kip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, kip->skci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, kip->skci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_px(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_port_ctl_impl_t *pip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, pip->spci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, pip->spci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_DISABLED, pip->spci_disable);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_lang(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_lang_ctl_impl_t *lip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, lip->slci_rqst_ident);
	SES_NV_CTL16(props, SES_LANG_PROP_LANGCODE,
	    lip->slci_language_code);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_comm(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_comm_ctl_impl_t *cip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, cip->scci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, cip->scci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_DISABLED, cip->scci_disable);

	return (0);
}

static int
elem_setdef_voltage(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_voltage_ctl_impl_t *vip = data;
	nvlist_t *props = ses_node_props(np);

	if (page == SES2_DIAGPAGE_THRESHOLD_IO)
		return (elem_setdef_threshold(np, page, data));

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, vip->svci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, vip->svci_rqst_ident);

	return (0);
}

static int
elem_setdef_current(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_current_ctl_impl_t *cip = data;
	nvlist_t *props = ses_node_props(np);

	if (page == SES2_DIAGPAGE_THRESHOLD_IO)
		return (elem_setdef_threshold(np, page, data));

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, cip->scci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, cip->scci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_itp(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_itp_ctl_impl_t *iip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, iip->sici_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, iip->sici_rqst_ident);
	SES_NV_CTLBOOL(props, SES_ITP_PROP_ENABLED, iip->sici_enable);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_sse(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_ss_ctl_impl_t *sip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, sip->ssci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, sip->ssci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_arraydev(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_array_device_ctl_impl_t *aip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_AD_PROP_RR_ABORT,
	    aip->sadci_rqst_rr_abort);
	SES_NV_CTLBOOL(props, SES_AD_PROP_REBUILD,
	    aip->sadci_rqst_rebuild);
	SES_NV_CTLBOOL(props, SES_AD_PROP_IN_FAILED_ARRAY,
	    aip->sadci_rqst_in_failed_array);
	SES_NV_CTLBOOL(props, SES_AD_PROP_IN_CRIT_ARRAY,
	    aip->sadci_rqst_in_crit_array);
	SES_NV_CTLBOOL(props, SES_AD_PROP_CONS_CHK,
	    aip->sadci_rqst_cons_check);
	SES_NV_CTLBOOL(props, SES_AD_PROP_HOT_SPARE,
	    aip->sadci_rqst_hot_spare);
	SES_NV_CTLBOOL(props, SES_AD_PROP_RSVD_DEVICE,
	    aip->sadci_rqst_rsvd_device);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, aip->sadci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_RMV, aip->sadci_rqst_remove);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_READY_TO_INSERT,
	    aip->sadci_rqst_insert);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_REQ_MISSING,
	    aip->sadci_rqst_missing);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_DO_NOT_REMOVE,
	    aip->sadci_do_not_remove);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_REQ_ACTIVE,
	    aip->sadci_rqst_active);

	SES_NV_CTLBOOL(props, SES_DEV_PROP_BYP_B, aip->sadci_enable_byp_b);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_BYP_A, aip->sadci_enable_byp_a);
	SES_NV_CTLBOOL(props, SES_PROP_OFF, aip->sadci_device_off);
	SES_NV_CTLBOOL(props, SES_DEV_PROP_FAULT_RQSTD,
	    aip->sadci_rqst_fault);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_expander(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_expander_ctl_impl_t *eip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_FAIL, eip->seci_rqst_fail);
	SES_NV_CTLBOOL(props, SES_PROP_IDENT, eip->seci_rqst_ident);

	return (0);
}

/*ARGSUSED*/
static int
elem_setdef_sasconn(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	ses2_sasconn_ctl_impl_t *sip = data;
	nvlist_t *props = ses_node_props(np);

	SES_NV_CTLBOOL(props, SES_PROP_IDENT, sip->ssci_rqst_ident);
	SES_NV_CTLBOOL(props, SES_PROP_FAIL, sip->ssci_rqst_fail);

	return (0);
}

#define	CTL_DESC(_e, _n)	\
	{	\
		.scd_et = _e,	\
		.scd_props = _n##_props,	\
		.scd_setdef = elem_setdef_##_n	\
	}

static const ses2_ctl_desc_t ctl_descs[] = {
	CTL_DESC(SES_ET_DEVICE, device),
	CTL_DESC(SES_ET_POWER_SUPPLY, psu),
	CTL_DESC(SES_ET_COOLING, cooling),
	CTL_DESC(SES_ET_TEMPERATURE_SENSOR, temp),
	CTL_DESC(SES_ET_DOOR_LOCK, lock),
	CTL_DESC(SES_ET_AUDIBLE_ALARM, alarm),
	CTL_DESC(SES_ET_ESC_ELECTRONICS, esc),
	CTL_DESC(SES_ET_SCC_ELECTRONICS, scc),
	CTL_DESC(SES_ET_NONVOLATILE_CACHE, cache),
	CTL_DESC(SES_ET_UPS, ups),
	CTL_DESC(SES_ET_DISPLAY, display),
	CTL_DESC(SES_ET_KEY_PAD_ENTRY, keypad),
	CTL_DESC(SES_ET_SCSI_PORT_XCVR, px),
	CTL_DESC(SES_ET_LANGUAGE, lang),
	CTL_DESC(SES_ET_COMMUNICATION_PORT, comm),
	CTL_DESC(SES_ET_VOLTAGE_SENSOR, voltage),
	CTL_DESC(SES_ET_CURRENT_SENSOR, current),
	CTL_DESC(SES_ET_SCSI_TARGET_PORT, itp),
	CTL_DESC(SES_ET_SCSI_INITIATOR_PORT, itp),
	CTL_DESC(SES_ET_SIMPLE_SUBENCLOSURE, sse),
	CTL_DESC(SES_ET_ARRAY_DEVICE, arraydev),
	CTL_DESC(SES_ET_SAS_EXPANDER, expander),
	CTL_DESC(SES_ET_SAS_CONNECTOR, sasconn),
	{ .scd_et = -1 }
};

int
ses2_element_ctl(ses_plugin_t *sp, ses_node_t *np, const char *op,
    nvlist_t *nvl)
{
	const ses2_ctl_desc_t *dp;
	nvlist_t *props = ses_node_props(np);
	uint64_t type;

	if (strcmp(op, SES_CTL_OP_SETPROP) != 0)
		return (0);

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
	    &type) == 0);

	for (dp = &ctl_descs[0]; dp->scd_et != -1; dp++)
		if (dp->scd_et == type)
			break;

	if (dp->scd_et == -1)
		return (0);

	return (ses2_setprop(sp, np, dp->scd_props, nvl));
}

int
ses2_element_setdef(ses_node_t *np, ses2_diag_page_t page, void *data)
{
	const ses2_ctl_desc_t *dp;
	nvlist_t *props = ses_node_props(np);
	uint64_t type;

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE, &type) == 0);

	for (dp = &ctl_descs[0]; dp->scd_et != -1; dp++)
		if (dp->scd_et == type)
			break;

	if (dp->scd_et == -1)
		return (0);

	if (dp->scd_setdef(np, page, data) != 0)
		return (-1);

	return (0);
}
