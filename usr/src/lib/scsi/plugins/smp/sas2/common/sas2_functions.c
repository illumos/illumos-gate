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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/generic/smp_frames.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>
#include "sas2.h"

/*ARGSUSED*/
static size_t
sas2_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN);
}

/*ARGSUSED*/
static off_t
sas2_rq_dataoff(smp_action_t *ap, smp_target_t *tp)
{
	size_t len;

	smp_action_get_request_frame(ap, NULL, &len);

	if (len > SMP_REQ_MINLEN)
		return (offsetof(smp_request_frame_t, srf_data[0]));

	return (-1);
}

static void
sas2_rq_setframe(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_request_frame_t *fp;
	uint_t cap;
	uint16_t change_count;
	uint16_t *rqcc;
	size_t rqlen, rslen;

	smp_action_get_request_frame(ap, (void *)&fp, &rqlen);
	smp_action_get_response_frame(ap, NULL, &rslen);
	cap = smp_target_getcap(tp);

	fp->srf_frame_type = SMP_FRAME_TYPE_REQUEST;
	fp->srf_function = dp->sfd_function;

	if (cap & SMP_TARGET_C_LONG_RESP) {
		fp->srf_allocated_response_len = (rslen - SMP_RESP_MINLEN) / 4;
		fp->srf_request_len = (rqlen - SMP_REQ_MINLEN) / 4;
	} else {
		fp->srf_allocated_response_len = 0;
		fp->srf_request_len = 0;
	}

	/*
	 * If this command requires that the expected expander change count
	 * be set (as many do), we will attempt to set it based on the
	 * most recently executed command.  However, if the user has set it
	 * already, we will not overwrite that setting.  It is the consumer's
	 * responsibility to keep track of expander changes each time it
	 * receives a new change count in a response.
	 */
	if (dp->sfd_flags & SMP_FD_F_NEEDS_CHANGE_COUNT) {
		ASSERT(rqlen >= SMP_REQ_MINLEN + sizeof (uint16_t));
		/* LINTED - alignment */
		rqcc = (uint16_t *)(&fp->srf_data[0]);
		if (SCSI_READ16(rqcc) == 0) {
			change_count = smp_target_get_change_count(tp);
			SCSI_WRITE16(rqcc, change_count);
		}
	}
}

/*ARGSUSED*/
static size_t
sas2_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	smp_response_frame_t *fp;
	size_t len;

	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (0);

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static off_t
sas2_rs_dataoff(smp_action_t *ap, smp_target_t *tp)
{
	size_t len;

	smp_action_get_response_frame(ap, NULL, &len);

	if (len > SMP_RESP_MINLEN)
		return (offsetof(smp_request_frame_t, srf_data[0]));

	return (-1);
}

static void
sas2_rs_getparams(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp;
	smp_response_frame_t *fp;
	size_t len;
	uint16_t change_count;

	dp = smp_action_get_function_def(ap);

	smp_action_get_response_frame(ap, (void **)&fp, &len);

	smp_action_set_result(ap, fp->srf_result);

	if (!(dp->sfd_flags & SMP_FD_F_PROVIDES_CHANGE_COUNT))
		return;

	if (len <= SMP_RESP_MINLEN + sizeof (uint16_t))
		return;

	change_count = SCSI_READ16(&fp->srf_data[0]);
	smp_target_set_change_count(tp, change_count);
}

/*ARGSUSED*/
static size_t
sas2_report_general_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_REPORT_GENERAL);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, 24));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_manufacturer_info_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_REPORT_MANUFACTURER_INFO);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, 56));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_self_config_status_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_self_config_status_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_zone_perm_table_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_zone_perm_table_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_broadcast_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_broadcast_req_t));
}

/*ARGSUSED*/
static size_t
sas2_discover_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_discover_req_t));
}

/*ARGSUSED*/
static size_t
sas2_discover_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_DISCOVER);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, 48));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_error_log_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_phy_error_log_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_error_log_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_REPORT_PHY_ERROR_LOG);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, sizeof (smp_report_phy_error_log_resp_t)));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_sata_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_phy_sata_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_sata_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_REPORT_PHY_SATA);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, 52));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_route_info_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_route_info_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_route_info_rs_datalen(smp_action_t *ap, smp_target_t *tp)
{
	const smp_function_def_t *dp = smp_action_get_function_def(ap);
	smp_response_frame_t *fp;
	size_t len;

	ASSERT(dp->sfd_function == SMP_FUNC_REPORT_ROUTE_INFO);
	smp_action_get_response_frame(ap, (void **)&fp, &len);

	if (len >= SMP_RESP_MINLEN)
		len -= SMP_RESP_MINLEN;
	else
		return (0);

	len &= ~3;

	if (fp->srf_response_len == 0)
		return (MIN(len, sizeof (smp_report_route_info_resp_t)));

	return (MIN(len, 4 * (fp->srf_response_len)));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_event_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_phy_event_req_t));
}

/*ARGSUSED*/
static size_t
sas2_discover_list_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_discover_list_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_phy_event_list_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_report_phy_event_list_req_t));
}

/*ARGSUSED*/
static size_t
sas2_report_exp_route_table_list_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN +
	    sizeof (smp_report_exp_route_table_list_req_t));
}

/*ARGSUSED*/
static size_t
sas2_config_general_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_config_general_req_t));
}

/*ARGSUSED*/
static size_t
sas2_enable_disable_zoning_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_enable_disable_zoning_req_t));
}

/*ARGSUSED*/
static size_t
sas2_zoned_broadcast_rq_len(size_t user, smp_target_t *tp)
{
	size_t descrsz;

	if (user == 0 || user > 1008) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	descrsz = P2ROUNDUP((user - 1), 4);

	return (SMP_REQ_MINLEN + descrsz + sizeof (smp_zoned_broadcast_req_t));
}

/*ARGSUSED*/
static size_t
sas2_zone_lock_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_zone_lock_req_t));
}

/*ARGSUSED*/
static size_t
sas2_zone_activate_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_zone_activate_req_t));
}

/*ARGSUSED*/
static size_t
sas2_zone_unlock_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_zone_unlock_req_t));
}

/*ARGSUSED*/
static size_t
sas2_config_zone_manager_password_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN +
	    sizeof (smp_config_zone_manager_password_req_t));
}

/*ARGSUSED*/
static size_t
sas2_config_zone_phy_info_rq_len(size_t user, smp_target_t *tp)
{
	if (user == 0 || user > 252) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_config_zone_phy_info_req_t) +
	    (user - 1) * sizeof (smp_zone_phy_config_descr_t));
}

static size_t
sas2_config_zone_perm_table_rq_len(size_t user, smp_target_t *tp)
{
	uint_t cap = smp_target_getcap(tp);
	size_t maxdescr, descrsz;

	if (cap & SMP_TARGET_C_ZG_256)
		descrsz = sizeof (smp_zone_perm_descr256_t);
	else
		descrsz = sizeof (smp_zone_perm_descr128_t);

	maxdescr = (1020 - sizeof (smp_config_zone_perm_table_req_t)) / descrsz;

	if (user == 0 || user > maxdescr) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_config_zone_perm_table_req_t) - 1 +
	    user * descrsz);
}

/*ARGSUSED*/
static size_t
sas2_config_route_info_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_config_route_info_req_t));
}

/*ARGSUSED*/
static size_t
sas2_phy_control_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_phy_control_req_t));
}

/*ARGSUSED*/
static size_t
sas2_phy_test_function_rq_len(size_t user, smp_target_t *tp)
{
	if (user != 0) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_phy_test_function_req_t));
}

/*ARGSUSED*/
static size_t
sas2_config_phy_event_rq_len(size_t user, smp_target_t *tp)
{
	if (user == 0 || user > 126) {
		(void) smp_set_errno(ESMP_RANGE);
		return (0);
	}

	return (SMP_REQ_MINLEN + sizeof (smp_config_phy_event_req_t) +
	    (user - 1) * sizeof (smp_phy_event_config_descr_t));
}

smp_function_def_t sas2_functions[] = {
{
	.sfd_function = SMP_FUNC_REPORT_GENERAL,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_report_general_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_MANUFACTURER_INFO,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_report_manufacturer_info_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_SELF_CONFIG_STATUS,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_self_config_status_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_ZONE_PERM_TABLE,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_zone_perm_table_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_BROADCAST,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_broadcast_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_DISCOVER,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_discover_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_discover_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_PHY_ERROR_LOG,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_phy_error_log_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_report_phy_error_log_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_PHY_SATA,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_phy_sata_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_report_phy_sata_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_ROUTE_INFO,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_route_info_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_report_route_info_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_PHY_EVENT,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_phy_event_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_DISCOVER_LIST,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_discover_list_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_PHY_EVENT_LIST,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_phy_event_list_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_PROVIDES_CHANGE_COUNT,
	.sfd_rq_len = sas2_report_exp_route_table_list_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_GENERAL,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_general_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_ENABLE_DISABLE_ZONING,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_enable_disable_zoning_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_ZONED_BROADCAST,
	.sfd_flags = SMP_FD_F_WRITE,
	.sfd_rq_len = sas2_zoned_broadcast_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_ZONE_LOCK,
	.sfd_flags = SMP_FD_F_READ | SMP_FD_F_WRITE |
	    SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_zone_lock_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_ZONE_ACTIVATE,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_zone_activate_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_ZONE_UNLOCK,
	.sfd_flags = SMP_FD_F_WRITE,
	.sfd_rq_len = sas2_zone_unlock_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_ZONE_MANAGER_PASSWORD,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_zone_manager_password_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_ZONE_PHY_INFO,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_zone_phy_info_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_ZONE_PERM_TABLE,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_zone_perm_table_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_ROUTE_INFO,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_route_info_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_PHY_CONTROL,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_phy_control_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_PHY_TEST_FUNCTION,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_phy_test_function_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = SMP_FUNC_CONFIG_PHY_EVENT,
	.sfd_flags = SMP_FD_F_WRITE | SMP_FD_F_NEEDS_CHANGE_COUNT,
	.sfd_rq_len = sas2_config_phy_event_rq_len,
	.sfd_rq_dataoff = sas2_rq_dataoff,
	.sfd_rq_setframe = sas2_rq_setframe,
	.sfd_rs_datalen = sas2_rs_datalen,
	.sfd_rs_dataoff = sas2_rs_dataoff,
	.sfd_rs_getparams = sas2_rs_getparams
},
{
	.sfd_function = -1
}
};

/*
 * Returns the number of bytes in the request frame, including the header
 * and footer, for the given function and capabilities.  Presently the only
 * relevant capability is long-request, which in some cases increases the
 * size of the request from the SAS-1 spec to that found in SAS-2.
 *
 * Variably-sized request frames have no default size; we return 0 in that
 * case, which will often be interpreted by the caller as an error although
 * in general it is not.
 */
size_t
smp_default_request_len(uint_t cap, smp_function_t fn)
{
	switch (fn) {
	case SMP_FUNC_REPORT_GENERAL:
	case SMP_FUNC_REPORT_MANUFACTURER_INFO:
	case SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD:
		return (SMP_REQ_MINLEN);

	case SMP_FUNC_REPORT_SELF_CONFIG_STATUS:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_self_config_status_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_REPORT_ZONE_PERM_TABLE:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_zone_perm_table_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_REPORT_BROADCAST:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_broadcast_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_DISCOVER:
		return (SMP_REQ_MINLEN + sizeof (smp_discover_req_t));
	case SMP_FUNC_REPORT_PHY_ERROR_LOG:
		return (SMP_REQ_MINLEN +
		    sizeof (smp_report_phy_error_log_req_t));
	case SMP_FUNC_REPORT_PHY_SATA:
		return (SMP_REQ_MINLEN + sizeof (smp_report_phy_sata_req_t));
	case SMP_FUNC_REPORT_ROUTE_INFO:
		return (SMP_REQ_MINLEN + sizeof (smp_report_route_info_req_t));
	case SMP_FUNC_REPORT_PHY_EVENT:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_phy_event_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_DISCOVER_LIST:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_discover_list_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_REPORT_PHY_EVENT_LIST:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_phy_event_list_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_report_exp_route_table_list_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_CONFIG_GENERAL:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_config_general_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_ENABLE_DISABLE_ZONING:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_enable_disable_zoning_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_ZONE_LOCK:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_zone_lock_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_ZONE_ACTIVATE:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_zone_activate_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_ZONE_UNLOCK:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_zone_unlock_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_CONFIG_ZONE_MANAGER_PASSWORD:
		if (cap & SMP_TARGET_C_LONG_RESP)
			return (SMP_REQ_MINLEN +
			    sizeof (smp_config_zone_manager_password_req_t));
		return (SMP_REQ_MINLEN);
	case SMP_FUNC_CONFIG_ROUTE_INFO:
		return (SMP_REQ_MINLEN + sizeof (smp_config_route_info_req_t));
	case SMP_FUNC_PHY_CONTROL:
		return (SMP_REQ_MINLEN + sizeof (smp_phy_control_req_t));
	case SMP_FUNC_PHY_TEST_FUNCTION:
		return (SMP_REQ_MINLEN + sizeof (smp_phy_test_function_req_t));

	case SMP_FUNC_ZONED_BROADCAST:
	case SMP_FUNC_CONFIG_ZONE_PHY_INFO:
	case SMP_FUNC_CONFIG_ZONE_PERM_TABLE:
	case SMP_FUNC_CONFIG_PHY_EVENT:
	default:
		return (0);
	}
}

/*
 * This is slightly different - return the length in bytes, including the
 * header and footer, to be assumed for the response frame type if the
 * length field is zero.  Since the length field will not be zero unless the
 * long response bit is clear or the target is buggy, we always assume that
 * the caller wants the size of the v1 frame.
 */
/*ARGSUSED*/
size_t
smp_default_response_len(uint_t cap, smp_function_t fn)
{
	switch (fn) {
	case SMP_FUNC_REPORT_SELF_CONFIG_STATUS:
	case SMP_FUNC_REPORT_ZONE_PERM_TABLE:
	case SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD:
	case SMP_FUNC_REPORT_BROADCAST:
	case SMP_FUNC_REPORT_PHY_EVENT:
	case SMP_FUNC_DISCOVER_LIST:
	case SMP_FUNC_REPORT_PHY_EVENT_LIST:
	case SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST:
	case SMP_FUNC_CONFIG_GENERAL:
	case SMP_FUNC_ENABLE_DISABLE_ZONING:
	case SMP_FUNC_ZONED_BROADCAST:
	case SMP_FUNC_ZONE_LOCK:
	case SMP_FUNC_ZONE_ACTIVATE:
	case SMP_FUNC_ZONE_UNLOCK:
	case SMP_FUNC_CONFIG_ZONE_MANAGER_PASSWORD:
	case SMP_FUNC_CONFIG_ZONE_PHY_INFO:
	case SMP_FUNC_CONFIG_ZONE_PERM_TABLE:
	case SMP_FUNC_CONFIG_ROUTE_INFO:
	case SMP_FUNC_PHY_CONTROL:
	case SMP_FUNC_PHY_TEST_FUNCTION:
	case SMP_FUNC_CONFIG_PHY_EVENT:
		return (SMP_RESP_MINLEN);

	case SMP_FUNC_REPORT_GENERAL:
		return (SMP_RESP_MINLEN + 24);
	case SMP_FUNC_REPORT_MANUFACTURER_INFO:
		return (SMP_RESP_MINLEN +
		    sizeof (smp_report_manufacturer_info_resp_t));
	case SMP_FUNC_DISCOVER:
		return (SMP_RESP_MINLEN + 48);
	case SMP_FUNC_REPORT_PHY_ERROR_LOG:
		return (SMP_RESP_MINLEN +
		    sizeof (smp_report_phy_error_log_resp_t));
	case SMP_FUNC_REPORT_PHY_SATA:
		return (SMP_RESP_MINLEN + 52);
	case SMP_FUNC_REPORT_ROUTE_INFO:
		return (SMP_RESP_MINLEN +
		    sizeof (smp_report_route_info_resp_t));

	default:
		return (0);
	}
}
