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
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <libnvpair.h>

#include <scsi/libses.h>
#include "ses2_impl.h"

static int
elem_parse_device(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_device_status_impl_t *dip = (ses2_device_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, SES_DEV_PROP_SLOT_ADDR,
	    dip->sdsi_slot_addr);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    dip->sdsi_report);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    dip->sdsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_RMV, dip->sdsi_rmv);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_READY_TO_INSERT,
	    dip->sdsi_ready_to_insert);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_ENC_BYP_B,
	    dip->sdsi_enclosure_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_ENC_BYP_A,
	    dip->sdsi_enclosure_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DO_NOT_REMOVE,
	    dip->sdsi_do_not_remove);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_APP_BYP_A,
	    dip->sdsi_app_client_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DEV_BYP_B,
	    dip->sdsi_device_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DEV_BYP_A,
	    dip->sdsi_device_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_BYP_B,
	    dip->sdsi_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_BYP_A,
	    dip->sdsi_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_OFF,
	    dip->sdsi_device_off);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_FAULT_RQSTD,
	    dip->sdsi_fault_reqstd);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_FAULT_SENSED,
	    dip->sdsi_fault_sensed);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_APP_BYP_B,
	    dip->sdsi_app_client_bypassed_b);

	return (0);
}

static int
elem_parse_psu(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_psu_status_impl_t *pip = (ses2_psu_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    pip->spsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_DC_OVER_CURRENT,
	    pip->spsi_dc_over_current);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_DC_UNDER_VOLTAGE,
	    pip->spsi_dc_under_voltage);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_DC_OVER_VOLTAGE,
	    pip->spsi_dc_over_voltage);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_DC_FAIL,
	    pip->spsi_dc_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_AC_FAIL,
	    pip->spsi_ac_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_TEMP_WARN,
	    pip->spsi_temp_warn);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PSU_PROP_OVERTEMP_FAIL,
	    pip->spsi_overtmp_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_OFF, pip->spsi_off);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REQUESTED_ON,
	    pip->spsi_rqsted_on);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, pip->spsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_HOT_SWAP,
	    pip->spsi_hot_swap);

	return (0);
}

static int
elem_parse_cooling(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_cooling_status_impl_t *cip = (ses2_cooling_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, SES_COOLING_PROP_FAN_SPEED,
	    SES2_ES_COOLING_ST_FAN_SPEED(cip));
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    cip->scsi_ident);
	SES_NV_ADD(uint64, nverr, nvl, SES_COOLING_PROP_SPEED_CODE,
	    cip->scsi_actual_speed_code);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_OFF, cip->scsi_off);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REQUESTED_ON,
	    cip->scsi_requested_on);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, cip->scsi_fail);

	return (0);
}

static int
elem_parse_temp(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_temp_status_impl_t *tip = (ses2_temp_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, tip->stsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, tip->stsi_fail);
	SES_NV_ADD(int64, nverr, nvl, SES_TEMP_PROP_TEMP,
	    SES2_ES_TEMP_ST_TEMPERATURE(tip));
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_UNDER,
	    tip->stsi_ut_warn);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_CRIT_UNDER,
	    tip->stsi_ut_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_OVER,
	    tip->stsi_ot_warn);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_CRIT_OVER,
	    tip->stsi_ot_fail);

	return (0);
}

static int
elem_parse_lock(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_lock_status_impl_t *lip = (ses2_lock_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL,
	    lip->slsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    lip->slsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_LOCK_PROP_UNLOCKED,
	    lip->slsi_unlocked);

	return (0);
}

static int
elem_parse_alarm(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_alarm_status_impl_t *aip = (ses2_alarm_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, aip->sasi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    aip->sasi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_UNRECOV,
	    aip->sasi_unrecov);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_CRIT,
	    aip->sasi_crit);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_NONCRIT,
	    aip->sasi_noncrit);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_INFO,
	    aip->sasi_info);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_REMIND,
	    aip->sasi_remind);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_MUTED,
	    aip->sasi_muted);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ALARM_PROP_RQST_MUTE,
	    aip->sasi_rqst_mute);

	return (0);
}

static int
elem_parse_esc(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_controller_status_impl_t *cip =
	    (ses2_controller_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, cip->scsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, cip->scsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    cip->scsi_report);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_HOT_SWAP,
	    cip->scsi_hot_swap);

	return (0);
}

static int
elem_parse_scc(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_scc_status_impl_t *sip = (ses2_scc_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, sip->sss_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, sip->sss_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    sip->sss_report);

	return (0);
}

static int
elem_parse_cache(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_nvcache_status_impl_t *np = (ses2_nvcache_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, np->snsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    np->snsi_ident);
	SES_NV_ADD(uint64, nverr, nvl, SES_CACHE_PROP_SIZE,
	    SES2_NVCACHE_SIZE(np));

	return (0);
}

static int
elem_parse_ups(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_ups_status_impl_t *uip = (ses2_ups_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, SES_UPS_PROP_TIMELEFT,
	    uip->susi_battery_status);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_INTF_FAIL,
	    uip->susi_intf_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_WARN,
	    uip->susi_warn);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_UPS_FAIL,
	    uip->susi_ups_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_DC_FAIL,
	    uip->susi_dc_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_AC_FAIL,
	    uip->susi_ac_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_AC_QUAL,
	    uip->susi_ac_qual);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_AC_HI,
	    uip->susi_ac_hi);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_AC_LO,
	    uip->susi_ac_lo);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_BPF, uip->susi_bpf);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_UPS_PROP_BATT_FAIL,
	    uip->susi_batt_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, uip->susi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, uip->susi_ident);

	return (0);
}

static int
elem_parse_display(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_display_status_impl_t *dip = (ses2_display_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, SES_DPY_PROP_MODE,
	    dip->sdsi_display_mode_status);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, dip->sdsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, dip->sdsi_ident);
	SES_NV_ADD(uint16, nverr, nvl, SES_DPY_PROP_CHAR,
	    dip->sdsi_display_character_status);

	return (0);
}

static int
elem_parse_keypad(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_keypad_status_impl_t *kip = (ses2_keypad_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, kip->sksi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, kip->sksi_ident);

	return (0);
}

static int
elem_parse_px(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_port_status_impl_t *pip = (ses2_port_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, pip->spsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, pip->spsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    pip->spsi_report);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PX_PROP_XMIT_FAIL,
	    pip->spsi_xmit_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PX_PROP_LOL, pip->spsi_lol);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_DISABLED,
	    pip->spsi_disabled);

	return (0);
}

static int
elem_parse_lang(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_lang_status_impl_t *lip = (ses2_lang_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    lip->slsi_ident);
	SES_NV_ADD(uint64, nverr, nvl, SES_LANG_PROP_LANGCODE,
	    SCSI_READ16(&lip->slsi_language_code));

	return (0);
}

static int
elem_parse_comm(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_comm_status_impl_t *cip = (ses2_comm_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, cip->scsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    cip->scsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_DISABLED,
	    cip->scsi_disabled);

	return (0);
}

static int
elem_parse_voltage(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_voltage_status_impl_t *vip = (ses2_voltage_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_CRIT_UNDER,
	    vip->svsi_crit_under);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_CRIT_OVER,
	    vip->svsi_crit_over);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_UNDER,
	    vip->svsi_warn_under);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_OVER,
	    vip->svsi_warn_over);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, vip->svsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, vip->svsi_ident);
	SES_NV_ADD(int64, nverr, nvl, SES_VS_PROP_VOLTAGE_MV,
	    SCSI_READ16(&vip->svsi_voltage));

	return (0);
}

static int
elem_parse_current(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_current_status_impl_t *cip = (ses2_current_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_CRIT_OVER,
	    cip->scsi_crit_over);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_WARN_OVER,
	    cip->scsi_warn_over);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, cip->scsi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, cip->scsi_ident);
	SES_NV_ADD(int64, nverr, nvl, SES_CS_PROP_CURRENT_MA,
	    SCSI_READ16(&cip->scsi_current));

	return (0);
}

static int
elem_parse_itp(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_itp_status_impl_t *iip = (ses2_itp_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, iip->sisi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT,
	    iip->sisi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    iip->sisi_report);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_ITP_PROP_ENABLED,
	    iip->sisi_enabled);

	return (0);
}

static int
elem_parse_sse(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_ss_status_impl_t *sip = (ses2_ss_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, sip->sss_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, sip->sss_ident);
	SES_NV_ADD(uint64, nverr, nvl, SES_SS_PROP_SHORT_STATUS,
	    sip->sss_short_status);

	return (0);
}

static int
elem_parse_arraydev(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_array_device_status_impl_t *aip =
	    (ses2_array_device_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_RR_ABORT,
	    aip->sadsi_rr_abort);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_REBUILD,
	    aip->sadsi_rebuild);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_IN_FAILED_ARRAY,
	    aip->sadsi_in_failed_array);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_IN_CRIT_ARRAY,
	    aip->sadsi_in_crit_array);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_CONS_CHK,
	    aip->sadsi_cons_chk);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_HOT_SPARE,
	    aip->sadsi_hot_spare);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_RSVD_DEVICE,
	    aip->sadsi_rsvd_device);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_AD_PROP_OK, aip->sadsi_ok);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_REPORT,
	    aip->sadsi_report);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, aip->sadsi_ident);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_RMV, aip->sadsi_rmv);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_READY_TO_INSERT,
	    aip->sadsi_ready_to_insert);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_ENC_BYP_B,
	    aip->sadsi_enclosure_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_ENC_BYP_A,
	    aip->sadsi_enclosure_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DO_NOT_REMOVE,
	    aip->sadsi_do_not_remove);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_APP_BYP_A,
	    aip->sadsi_app_client_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DEV_BYP_B,
	    aip->sadsi_device_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_DEV_BYP_A,
	    aip->sadsi_device_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_BYP_B,
	    aip->sadsi_bypassed_b);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_BYP_A,
	    aip->sadsi_bypassed_a);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_OFF,
	    aip->sadsi_device_off);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_FAULT_RQSTD,
	    aip->sadsi_fault_reqstd);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_FAULT_SENSED,
	    aip->sadsi_fault_sensed);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_APP_BYP_B,
	    aip->sadsi_app_client_bypassed_b);

	return (0);
}

static int
elem_parse_expander(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_expander_status_impl_t *eip = (ses2_expander_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, eip->sesi_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, eip->sesi_ident);

	return (0);
}

static int
elem_parse_sasconn(const ses2_elem_status_impl_t *esip, nvlist_t *nvl)
{
	ses2_sasconn_status_impl_t *sip = (ses2_sasconn_status_impl_t *)esip;
	int nverr;

	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_FAIL, sip->sss_fail);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_IDENT, sip->sss_ident);
	SES_NV_ADD(uint64, nverr, nvl, SES_SC_PROP_CONNECTOR_TYPE,
	    sip->sss_connector_type);
	SES_NV_ADD(uint64, nverr, nvl, SES_SC_PROP_PHYSICAL_LINK,
	    sip->sss_connector_physical_link);

	return (0);
}

static const struct status_parser {
	ses2_element_type_t type;
	int (*func)(const ses2_elem_status_impl_t *, nvlist_t *);
} status_parsers[] = {
	{ SES_ET_DEVICE, elem_parse_device },
	{ SES_ET_POWER_SUPPLY, elem_parse_psu },
	{ SES_ET_COOLING, elem_parse_cooling },
	{ SES_ET_TEMPERATURE_SENSOR, elem_parse_temp },
	{ SES_ET_DOOR_LOCK, elem_parse_lock },
	{ SES_ET_AUDIBLE_ALARM, elem_parse_alarm },
	{ SES_ET_ESC_ELECTRONICS, elem_parse_esc },
	{ SES_ET_SCC_ELECTRONICS, elem_parse_scc },
	{ SES_ET_NONVOLATILE_CACHE, elem_parse_cache },
	{ SES_ET_UPS, elem_parse_ups },
	{ SES_ET_DISPLAY, elem_parse_display },
	{ SES_ET_KEY_PAD_ENTRY, elem_parse_keypad },
	{ SES_ET_SCSI_PORT_XCVR, elem_parse_px },
	{ SES_ET_LANGUAGE, elem_parse_lang },
	{ SES_ET_COMMUNICATION_PORT, elem_parse_comm },
	{ SES_ET_VOLTAGE_SENSOR, elem_parse_voltage },
	{ SES_ET_CURRENT_SENSOR, elem_parse_current },
	{ SES_ET_SCSI_TARGET_PORT, elem_parse_itp },
	{ SES_ET_SCSI_INITIATOR_PORT, elem_parse_itp },
	{ SES_ET_SIMPLE_SUBENCLOSURE, elem_parse_sse },
	{ SES_ET_ARRAY_DEVICE, elem_parse_arraydev },
	{ SES_ET_SAS_EXPANDER, elem_parse_expander },
	{ SES_ET_SAS_CONNECTOR, elem_parse_sasconn },
	{ (ses2_element_type_t)-1, NULL }
};

static int
elem_parse_sd(ses_plugin_t *spp, ses_node_t *np)
{
	ses2_elem_status_impl_t *esip;
	const struct status_parser *sp;
	nvlist_t *nvl = ses_node_props(np);
	size_t len;
	int nverr;
	uint64_t type;

	if ((esip = ses_plugin_page_lookup(spp,
	    ses_node_snapshot(np), SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,
	    np, &len)) == NULL)
		return (0);

	VERIFY(nvlist_lookup_uint64(nvl, SES_PROP_ELEMENT_TYPE,
	    &type) == 0);

	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_STATUS_CODE,
	    esip->sesi_common.sesi_status_code);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_SWAP,
	    esip->sesi_common.sesi_swap);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_DISABLED,
	    esip->sesi_common.sesi_disabled);
	SES_NV_ADD(boolean_value, nverr, nvl, SES_PROP_PRDFAIL,
	    esip->sesi_common.sesi_prdfail);

	for (sp = &status_parsers[0]; sp->type != (ses2_element_type_t)-1; sp++)
		if (sp->type == type && sp->func != NULL)
			return (sp->func(esip, nvl));

	return (0);
}

static int
elem_parse_descr(ses_plugin_t *sp, ses_node_t *np)
{
	char *desc;
	size_t len;
	nvlist_t *props = ses_node_props(np);
	int nverr;

	if ((desc = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
	    SES2_DIAGPAGE_ELEMENT_DESC, np, &len)) == NULL)
		return (0);

	SES_NV_ADD(fixed_string, nverr, props, SES_PROP_DESCRIPTION,
	    desc, len);

	return (0);
}

static int
elem_parse_aes_fc(const ses2_aes_descr_fc_eip_impl_t *fp,
    nvlist_t *nvl, size_t len)
{
	int nverr, i;
	nvlist_t **nva;
	int nports;

	if (len < offsetof(ses2_aes_descr_fc_eip_impl_t,
	    sadfi_ports))
		return (0);

	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_BAY_NUMBER,
	    fp->sadfi_bay_number);
	SES_NV_ADD(uint64, nverr, nvl, SES_FC_PROP_NODE_NAME,
	    SCSI_READ64(&fp->sadfi_node_name));

	nports = MIN(fp->sadfi_n_ports,
	    (len - offsetof(ses2_aes_descr_fc_eip_impl_t,
	    sadfi_ports)) / sizeof (ses2_aes_port_descr_impl_t));

	if (nports == 0)
		return (0);

	nva = ses_zalloc(nports * sizeof (nvlist_t *));
	if (nva == NULL)
		return (-1);

	for (i = 0; i < nports; i++) {
		if ((nverr = nvlist_alloc(&nva[i], NV_UNIQUE_NAME, 0)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_FC_PROP_LOOP_POS,
		    fp->sadfi_ports[i].sapdi_port_loop_position)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_FC_PROP_REQ_HARDADDR,
		    fp->sadfi_ports[i].sapdi_port_requested_hard_address)) != 0)
			goto fail;
		nverr = nvlist_add_uint64(nva[i], SES_FC_PROP_N_PORT_ID,
		    SCSI_READ24(fp->sadfi_ports[i].sapdi_n_port_identifier));
		if (nverr != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_FC_PROP_N_PORT_NAME,
		    SCSI_READ64(&fp->sadfi_ports[i].sapdi_n_port_name))) != 0)
			goto fail;
	}

	if ((nverr = nvlist_add_nvlist_array(nvl, SES_FC_PROP_PORTS,
	    nva, nports)) != 0)
		goto fail;

	for (i = 0; i < nports && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (0);

fail:
	for (i = 0; i < nports && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (ses_set_nverrno(nverr, NULL));
}

static int
elem_parse_aes_device(const ses2_aes_descr_eip_impl_t *dep, nvlist_t *nvl,
    size_t len)
{
	ses2_aes_descr_fc_eip_impl_t *fp;
	ses2_aes_descr_sas0_eip_impl_t *s0ep;
	ses2_aes_descr_sas0_impl_t *s0p;
	ses2_aes_descr_impl_t *dip;
	nvlist_t **nva;
	int nverr, i;
	size_t nphy;

	if (dep->sadei_eip) {
		s0ep = (ses2_aes_descr_sas0_eip_impl_t *)
		    dep->sadei_protocol_specific;
		s0p = (ses2_aes_descr_sas0_impl_t *)
		    dep->sadei_protocol_specific;
	} else {
		dip = (ses2_aes_descr_impl_t *)dep;
		s0ep = NULL;
		s0p = (ses2_aes_descr_sas0_impl_t *)
		    dip->sadei_protocol_specific;
	}

	if (dep->sadei_invalid)
		return (0);

	if (dep->sadei_protocol_identifier == SPC4_PROTO_FIBRE_CHANNEL) {
		fp = (ses2_aes_descr_fc_eip_impl_t *)
		    dep->sadei_protocol_specific;

		if (!SES_WITHIN_PAGE_STRUCT(fp, dep, len))
			return (0);

		return (elem_parse_aes_fc(fp, nvl, len -
		    offsetof(ses2_aes_descr_eip_impl_t,
		    sadei_protocol_specific)));
	} else if (dep->sadei_protocol_identifier != SPC4_PROTO_SAS) {
		return (0);
	}

	if (s0p->sadsi_descriptor_type != SES2_AESD_SAS_DEVICE)
		return (0);

	SES_NV_ADD(boolean_value, nverr, nvl, SES_DEV_PROP_SAS_NOT_ALL_PHYS,
	    s0p->sadsi_not_all_phys);
	if (s0ep != NULL) {
		SES_NV_ADD(uint64, nverr, nvl, SES_PROP_BAY_NUMBER,
		    s0ep->sadsi_bay_number);
		nphy = MIN(s0ep->sadsi_n_phy_descriptors,
		    (len - offsetof(ses2_aes_descr_sas0_eip_impl_t,
		    sadsi_phys)) / sizeof (ses2_aes_phy0_descr_impl_t));
	} else {
		nphy = MIN(s0p->sadsi_n_phy_descriptors,
		    (len - offsetof(ses2_aes_descr_sas0_impl_t,
		    sadsi_phys)) / sizeof (ses2_aes_phy0_descr_impl_t));
	}

	if (nphy == 0)
		return (0);

	nva = ses_zalloc(nphy * sizeof (nvlist_t *));
	if (nva == NULL)
		return (-1);

	for (i = 0; i < nphy; i++) {
		ses2_aes_phy0_descr_impl_t *pp;
		pp = s0ep != NULL ? &s0ep->sadsi_phys[i] : &s0p->sadsi_phys[i];
		if ((nverr = nvlist_alloc(&nva[i], NV_UNIQUE_NAME, 0)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_SAS_PROP_DEVICE_TYPE,
		    pp->sapdi_device_type)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_SMPI_PORT, pp->sapdi_smp_initiator_port)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_STPI_PORT, pp->sapdi_stp_initiator_port)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_SSPI_PORT, pp->sapdi_ssp_initiator_port)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_SATA_DEVICE, pp->sapdi_sata_device)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_SMPT_PORT, pp->sapdi_smp_target_port)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_STPT_PORT, pp->sapdi_stp_target_port)) != 0)
			goto fail;
		if ((nverr = nvlist_add_boolean_value(nva[i],
		    SES_SAS_PROP_SSPT_PORT, pp->sapdi_ssp_target_port)) != 0)
			goto fail;
		nverr = nvlist_add_uint64(nva[i], SES_SAS_PROP_ATT_ADDR,
		    SCSI_READ64(&pp->sapdi_attached_sas_address));
		if (nverr != 0)
			goto fail;
		nverr = nvlist_add_uint64(nva[i], SES_SAS_PROP_ADDR,
		    SCSI_READ64(&pp->sapdi_sas_address));
		if (nverr != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_SAS_PROP_PHY_ID,
		    pp->sapdi_phy_identifier)) != 0)
			goto fail;
	}

	if ((nverr = nvlist_add_nvlist_array(nvl, SES_SAS_PROP_PHYS,
	    nva, nphy)) != 0)
		goto fail;

	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (0);

fail:
	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (ses_set_nverrno(nverr, NULL));
}

static int
elem_parse_aes_expander(const ses2_aes_descr_eip_impl_t *dep, nvlist_t *nvl,
    size_t len)
{
	ses2_aes_descr_exp_impl_t *sep;
	nvlist_t **nva;
	int nverr, i;
	size_t nphy;

	if (dep->sadei_invalid)
		return (0);

	/*
	 * This should never happen; no current SAS expander can have any
	 * other kind of ports.  But maybe someday - one could envision a
	 * SAS expander with iSCSI target ports, for example.
	 */
	if (dep->sadei_protocol_identifier != SPC4_PROTO_SAS)
		return (0);

	sep = (ses2_aes_descr_exp_impl_t *)dep->sadei_protocol_specific;
	if (sep->sadei_descriptor_type != SES2_AESD_SAS_OTHER)
		return (0);

	SES_NV_ADD(uint64, nverr, nvl, SES_EXP_PROP_SAS_ADDR,
	    SCSI_READ64(&sep->sadei_sas_address));

	nphy = MIN(sep->sadei_n_exp_phy_descriptors,
	    (len - offsetof(ses2_aes_descr_exp_impl_t,
	    sadei_phys)) / sizeof (ses2_aes_exp_phy_descr_impl_t));

	if (nphy == 0)
		return (0);

	nva = ses_zalloc(nphy * sizeof (nvlist_t *));
	if (nva == NULL)
		return (-1);

	for (i = 0; i < nphy; i++) {
		if ((nverr = nvlist_alloc(&nva[i], NV_UNIQUE_NAME, 0)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_PROP_CE_IDX,
		    sep->sadei_phys[i].saepdi_connector_element_index)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_PROP_OE_IDX,
		    sep->sadei_phys[i].saepdi_other_element_index)) != 0)
			goto fail;
	}

	if ((nverr = nvlist_add_nvlist_array(nvl, SES_SAS_PROP_PHYS,
	    nva, nphy)) != 0)
		goto fail;

	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (0);

fail:
	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (ses_set_nverrno(nverr, NULL));
}

static int
elem_parse_aes_misc(const ses2_aes_descr_eip_impl_t *dep, nvlist_t *nvl,
    size_t len)
{
	ses2_aes_descr_fc_eip_impl_t *fp;
	ses2_aes_descr_sas1_impl_t *s1p;
	nvlist_t **nva;
	int nverr, i;
	size_t nphy;

	if (dep->sadei_invalid)
		return (0);

	if (dep->sadei_protocol_identifier == SPC4_PROTO_FIBRE_CHANNEL) {
		fp = (ses2_aes_descr_fc_eip_impl_t *)
		    dep->sadei_protocol_specific;

		if (!SES_WITHIN_PAGE_STRUCT(fp, dep, len))
			return (0);

		return (elem_parse_aes_fc(fp, nvl, len -
		    offsetof(ses2_aes_descr_eip_impl_t,
		    sadei_protocol_specific)));
	} else if (dep->sadei_protocol_identifier != SPC4_PROTO_SAS) {
		return (0);
	}

	s1p = (ses2_aes_descr_sas1_impl_t *)dep->sadei_protocol_specific;
	if (s1p->sadsi_descriptor_type == SES2_AESD_SAS_DEVICE)
		return (0);

	nphy = MIN(s1p->sadsi_n_phy_descriptors,
	    (len - offsetof(ses2_aes_descr_sas1_impl_t,
	    sadsi_phys)) / sizeof (ses2_aes_phy1_descr_impl_t));

	if (nphy == 0)
		return (0);

	nva = ses_zalloc(nphy * sizeof (nvlist_t *));
	if (nva == NULL)
		return (-1);

	for (i = 0; i < nphy; i++) {
		if ((nverr = nvlist_alloc(&nva[i], NV_UNIQUE_NAME, 0)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_PROP_CE_IDX,
		    s1p->sadsi_phys[i].sapdi_connector_element_index)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_PROP_OE_IDX,
		    s1p->sadsi_phys[i].sapdi_other_element_index)) != 0)
			goto fail;
		if ((nverr = nvlist_add_uint64(nva[i], SES_SAS_PROP_ADDR,
		    SCSI_READ64(&s1p->sadsi_phys[i].sapdi_sas_address))) != 0)
			goto fail;
	}

	if ((nverr = nvlist_add_nvlist_array(nvl, SES_SAS_PROP_PHYS,
	    nva, nphy)) != 0)
		goto fail;

	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);

	ses_free(nva);
	return (0);

fail:
	for (i = 0; i < nphy && nva[i] != NULL; i++)
		nvlist_free(nva[i]);
	ses_free(nva);
	return (nverr);
}

static const struct aes_parser {
	ses2_element_type_t type;
	int (*func)(const ses2_aes_descr_eip_impl_t *, nvlist_t *, size_t);
} aes_parsers[] = {
	{ SES_ET_DEVICE, elem_parse_aes_device },
	{ SES_ET_SCSI_TARGET_PORT, elem_parse_aes_misc },
	{ SES_ET_SCSI_INITIATOR_PORT, elem_parse_aes_misc },
	{ SES_ET_ESC_ELECTRONICS, elem_parse_aes_misc },
	{ SES_ET_ARRAY_DEVICE, elem_parse_aes_device },
	{ SES_ET_SAS_EXPANDER, elem_parse_aes_expander },
	{ (ses2_element_type_t)-1, NULL }
};

static int
elem_parse_aes(ses_plugin_t *sp, ses_node_t *np)
{
	ses2_aes_descr_eip_impl_t *dep;
	nvlist_t *props = ses_node_props(np);
	const struct aes_parser *app;
	uint64_t type;
	size_t len;

	if (ses_node_type(np) == SES_NODE_AGGREGATE)
		return (0);

	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
	    &type) == 0);

	for (app = &aes_parsers[0]; app->func != NULL; app++)
		if (app->type == type)
			break;
	if (app->func == NULL)
		return (0);

	if ((dep = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
	    SES2_DIAGPAGE_ADDL_ELEM_STATUS, np, &len)) == NULL)
		return (0);

	return (app->func(dep, props, len));
}

static int
elem_parse_threshold(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap = ses_node_snapshot(np);
	ses2_threshold_impl_t *tp;
	nvlist_t *nvl = ses_node_props(np);
	int nverr;
	uint64_t type;
	size_t len;

	VERIFY(nvlist_lookup_uint64(nvl, SES_PROP_ELEMENT_TYPE,
	    &type) == 0);

	switch (type) {
	case SES_ET_TEMPERATURE_SENSOR:
	case SES_ET_UPS:
	case SES_ET_VOLTAGE_SENSOR:
	case SES_ET_CURRENT_SENSOR:
		break;
	default:
		return (0);
	}

	if ((tp = ses_plugin_page_lookup(sp, snap,
	    SES2_DIAGPAGE_THRESHOLD_IO, np, &len)) == NULL)
		return (0);

	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_THRESH_CRIT_HI,
	    tp->sti_high_crit);
	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_THRESH_WARN_HI,
	    tp->sti_high_warn);
	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_THRESH_CRIT_LO,
	    tp->sti_low_crit);
	SES_NV_ADD(uint64, nverr, nvl, SES_PROP_THRESH_WARN_LO,
	    tp->sti_low_warn);

	return (0);
}

int
ses2_fill_element_node(ses_plugin_t *sp, ses_node_t *np)
{
	int err;

	if ((err = elem_parse_sd(sp, np)) != 0)
		return (err);

	if ((err = elem_parse_descr(sp, np)) != 0)
		return (err);

	if ((err = elem_parse_aes(sp, np)) != 0)
		return (err);

	if ((err = elem_parse_threshold(sp, np)) != 0)
		return (err);

	return (0);
}
