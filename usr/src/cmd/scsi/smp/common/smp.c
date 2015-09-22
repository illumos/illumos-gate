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
 * Copyright 2015 PALO, Richard
 */
#include <sys/types.h>
#include <sys/scsi/generic/smp_frames.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/ccompile.h>
#include <sys/byteorder.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>

static char *yes = "Yes";
static char *no = "No";

static void fatal(int, const char *, ...) __NORETURN;

static smp_target_t *tp = NULL;
static smp_action_t *ap = NULL;
static smp_function_t func;
static smp_result_t result;
static smp_target_def_t tdef;
static uint8_t *smp_resp;
static size_t smp_resp_len;

static void
fatal(int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "\n");
	(void) fflush(stderr);

	_exit(err);
}

static char *
smp_get_result(smp_result_t result)
{
	switch (result) {
	case SMP_RES_FUNCTION_ACCEPTED:
		return ("Function accepted");
		break;
	case SMP_RES_UNKNOWN_FUNCTION:
		return ("Unknown function");
		break;
	case SMP_RES_FUNCTION_FAILED:
		return ("Function failed");
		break;
	case SMP_RES_INVALID_REQUEST_FRAME_LENGTH:
		return ("Invalid request frame length");
		break;
	case SMP_RES_INVALID_EXPANDER_CHANGE_COUNT:
		return ("Invalid expander change count");
		break;
	case SMP_RES_BUSY:
		return ("Busy");
		break;
	case SMP_RES_INCOMPLETE_DESCRIPTOR_LIST:
		return ("Incomplete descriptor list");
		break;
	case SMP_RES_PHY_DOES_NOT_EXIST:
		return ("PHY does not exist");
		break;
	case SMP_RES_INDEX_DOES_NOT_EXIST:
		return ("Index does not exist");
		break;
	case SMP_RES_PHY_DOES_NOT_SUPPORT_SATA:
		return ("PHY does not support SATA");
		break;
	case SMP_RES_UNKNOWN_PHY_OPERATION:
		return ("Unknown PHY operation");
		break;
	case SMP_RES_UNKNOWN_PHY_TEST_FUNCTION:
		return ("Unknown PHY test function");
		break;
	case SMP_RES_PHY_TEST_IN_PROGRESS:
		return ("PHY test in progress");
		break;
	case SMP_RES_PHY_VACANT:
		return ("PHY vacant");
		break;
	case SMP_RES_UNKNOWN_PHY_EVENT_SOURCE:
		return ("Unknown PHY event source");
		break;
	case SMP_RES_UNKNOWN_DESCRIPTOR_TYPE:
		return ("Unknown descriptor type");
		break;
	case SMP_RES_UNKNOWN_PHY_FILTER:
		return ("Unknown PHY filter");
		break;
	case SMP_RES_AFFILIATION_VIOLATION:
		return ("Affiliation violation");
		break;
	case SMP_RES_ZONE_VIOLATION:
		return ("Zone violation");
		break;
	case SMP_RES_NO_MANAGEMENT_ACCESS_RIGHTS:
		return ("No management access rights");
		break;
	case SMP_RES_UNKNOWN_ENABLE_DISABLE_ZONING:
		return ("Unknown enable/disable zoning value");
		break;
	case SMP_RES_ZONE_LOCK_VIOLATION:
		return ("Zone lock violation");
		break;
	case SMP_RES_NOT_ACTIVATED:
		return ("Not activated");
		break;
	case SMP_RES_ZONE_GROUP_OUT_OF_RANGE:
		return ("Zone group out of range");
		break;
	case SMP_RES_NO_PHYSICAL_PRESENCE:
		return ("No physical presence");
		break;
	case SMP_RES_SAVING_NOT_SUPPORTED:
		return ("Saving not supported");
		break;
	case SMP_RES_SOURCE_ZONE_GROUP_DNE:
		return ("Source zone group does not exist");
		break;
	case SMP_RES_DISABLED_PW_NOT_SUPPORTED:
		return ("Disabled password not supported");
		break;
	default:
		break;
	}

	return (NULL);
}

static void
smp_execute()
{
	if (smp_exec(ap, tp) != 0) {
		smp_close(tp);
		smp_action_free(ap);
		smp_fini();
		fatal(-4, "exec failed: %s", smp_errmsg());
	}
}

static void
smp_cmd_failed(smp_result_t result)
{
	char *smp_result_str = smp_get_result(result);

	if (smp_result_str == NULL) {
		fatal(-5, "Command failed: Unknown result (0x%x)",
		    result);
	} else {
		fatal(-5, "Command failed: %s", smp_result_str);
	}
}

static void
smp_get_response(boolean_t close_on_fail)
{
	smp_action_get_response(ap, &result, (void **)&smp_resp, &smp_resp_len);

	if (close_on_fail && (result != SMP_RES_FUNCTION_ACCEPTED)) {
		smp_close(tp);
		smp_action_free(ap);
		smp_fini();
		smp_cmd_failed(result);
	}
}

static void
smp_cleanup()
{
	if (tp) {
		smp_close(tp);
		tp = NULL;
	}
	smp_action_free(ap);
	smp_fini();
}

/* ARGSUSED */
static void
smp_handle_report_route_info(int argc, char *argv[])
{
	smp_report_route_info_req_t *rp;
	smp_report_route_info_resp_t *rirp;
	uint16_t route_indexes = smp_target_get_exp_route_indexes(tp);
	uint8_t num_phys = smp_target_get_number_of_phys(tp);
	uint16_t rt_idx_req, ri_idx, ri_end;
	uint8_t phy_id_req, pi_idx, pi_end;
	boolean_t enabled_entries = B_FALSE;

	/*
	 * Verify the expander supports the PHY-based expander route table
	 */
	if (route_indexes == 0) {
		smp_cleanup();
		fatal(-6, "Expander does not support PHY-based route table\n");
	}

	rt_idx_req = strtol(argv[3], NULL, 0);
	phy_id_req = strtol(argv[4], NULL, 0);

	if (((int16_t)rt_idx_req == -1) && ((int8_t)phy_id_req == -1)) {
		ri_idx = 0;
		ri_end = route_indexes - 1;
		pi_idx = 0;
		pi_end = num_phys - 1;
	} else if (((int16_t)rt_idx_req < 0) || (rt_idx_req >= route_indexes) ||
	    ((int8_t)phy_id_req < 0) || (phy_id_req >= num_phys)) {
		smp_cleanup();
		fatal(-1, "Invalid route index (%d) or PHY ID (%d)\n",
		    rt_idx_req, phy_id_req);
	} else {
		ri_end = ri_idx = rt_idx_req;
		pi_end = pi_idx = phy_id_req;
	}

	(void) printf("%6s %6s %3s %14s\n",
	    "RT Idx", "PHY ID", "DIS", "Routed SASAddr");

	smp_action_get_request(ap, (void **)&rp, NULL);

	while (ri_idx <= ri_end) {
		while (pi_idx <= pi_end) {
			rp->srrir_phy_identifier = pi_idx;
			rp->srrir_exp_route_index = ri_idx;

			smp_execute();
			smp_get_response(B_FALSE);

			if (result != SMP_RES_FUNCTION_ACCEPTED) {
				pi_idx++;
				continue;
			}

			rirp = (smp_report_route_info_resp_t *)smp_resp;

			if (rirp->srrir_exp_route_entry_disabled == 0) {
				enabled_entries = B_TRUE;
				(void) printf("%6d %6d %3d %016llx\n",
				    rirp->srrir_exp_route_index,
				    rirp->srrir_phy_identifier,
				    rirp->srrir_exp_route_entry_disabled,
				    BE_64(rirp->srrir_routed_sas_addr));
			}

			pi_idx++;
		}

		ri_idx++;
		pi_idx = 0;
	}

	if (!enabled_entries) {
		(void) printf("No enabled entries in the table.\n");
	}

	smp_cleanup();
	exit(0);
}

static char *
smp_phy_event_src_str(smp_phy_event_source_t src, boolean_t *peak_detector)
{
	char *src_str;

	*peak_detector = B_FALSE;

	switch (src) {
	case SMP_PHY_EVENT_NO_EVENT:
		src_str = "No event";
		break;
	case SMP_PHY_EVENT_INVALID_DWORD_COUNT:
		src_str = "Invalid DWORD count";
		break;
	case SMP_PHY_EVENT_RUNNING_DISPARITY_ERROR_COUNT:
		src_str = "Running disparity error count";
		break;
	case SMP_PHY_EVENT_LOSS_OF_DWORD_SYNC_COUNT:
		src_str = "Loss of DWORD sync count";
		break;
	case SMP_PHY_EVENT_PHY_RESET_PROBLEM_COUNT:
		src_str = "PHY reset problem count";
		break;
	case SMP_PHY_EVENT_ELASTICITY_BUFFER_OVERFLOW_COUNT:
		src_str = "Elasticity buffer overflow count";
		break;
	case SMP_PHY_EVENT_RX_ERROR_COUNT:
		src_str = "Received ERROR count";
		break;
	case SMP_PHY_EVENT_RX_ADDR_FRAME_ERROR_COUNT:
		src_str = "Received address frame error count";
		break;
	case SMP_PHY_EVENT_TX_ABANDON_CLASS_OPEN_REJ_COUNT:
		src_str = "Transmitted abandon-class OPEN_REJECT count";
		break;
	case SMP_PHY_EVENT_RX_ABANDON_CLASS_OPEN_REJ_COUNT:
		src_str = "Received abandon-class OPEN_REJECT count";
		break;
	case SMP_PHY_EVENT_TX_RETRY_CLASS_OPEN_REJ_COUNT:
		src_str = "Transmitted retry-class OPEN_REJECT count";
		break;
	case SMP_PHY_EVENT_RX_RETRY_CLASS_OPEN_REJ_COUNT:
		src_str = "Received retry-class OPEN_REJECT count";
		break;
	case SMP_PHY_EVENT_RX_AIP_W_O_PARTIAL_COUNT:
		src_str = "Received AIP (WAITING ON PARTIAL) count";
		break;
	case SMP_PHY_EVENT_RX_AIP_W_O_CONN_COUNT:
		src_str = "Received AIP (WAITING ON CONNECTION) count";
		break;
	case SMP_PHY_EVENT_TX_BREAK_COUNT:
		src_str = "Transmitted BREAK count";
		break;
	case SMP_PHY_EVENT_RX_BREAK_COUNT:
		src_str = "Received BREAK count";
		break;
	case SMP_PHY_EVENT_BREAK_TIMEOUT_COUNT:
		src_str = "BREAK timeout count";
		break;
	case SMP_PHY_EVENT_CONNECTION_COUNT:
		src_str = "Connection count";
		break;
	case SMP_PHY_EVENT_PEAK_TX_PATHWAY_BLOCKED_COUNT:
		src_str = "Peak transmitted pathway blocked count";
		*peak_detector = B_TRUE;
		break;
	case SMP_PHY_EVENT_PEAK_TX_ARB_WAIT_TIME:
		src_str = "Peak transmitted arbitration wait time";
		*peak_detector = B_TRUE;
		break;
	case SMP_PHY_EVENT_PEAK_ARB_TIME:
		src_str = "Peak arbitration time";
		*peak_detector = B_TRUE;
		break;
	case SMP_PHY_EVENT_PEAK_CONNECTION_TIME:
		src_str = "Peak connection time";
		*peak_detector = B_TRUE;
		break;
	case SMP_PHY_EVENT_TX_SSP_FRAME_COUNT:
		src_str = "Transmitted SSP frame count";
		break;
	case SMP_PHY_EVENT_RX_SSP_FRAME_COUNT:
		src_str = "Received SSP frame count";
		break;
	case SMP_PHY_EVENT_TX_SSP_FRAME_ERROR_COUNT:
		src_str = "Transmitted SSP frame error count";
		break;
	case SMP_PHY_EVENT_RX_SSP_FRAME_ERROR_COUNT:
		src_str = "Received SSP frame error count";
		break;
	case SMP_PHY_EVENT_TX_CREDIT_BLOCKED_COUNT:
		src_str = "Transmitted CREDIT_BLOCKED count";
		break;
	case SMP_PHY_EVENT_RX_CREDIT_BLOCKED_COUNT:
		src_str = "Received CREDIT_BLOCKED count";
		break;
	case SMP_PHY_EVENT_TX_SATA_FRAME_COUNT:
		src_str = "Transmitted SATA frame count";
		break;
	case SMP_PHY_EVENT_RX_SATA_FRAME_COUNT:
		src_str = "Received SATA frame count";
		break;
	case SMP_PHY_EVENT_SATA_FLOW_CTRL_BUF_OVERFLOW_COUNT:
		src_str = "SATA flow control buffer overflow count";
		break;
	case SMP_PHY_EVENT_TX_SMP_FRAME_COUNT:
		src_str = "Transmitted SMP frame count";
		break;
	case SMP_PHY_EVENT_RX_SMP_FRAME_COUNT:
		src_str = "Received SMP frame count";
		break;
	case SMP_PHY_EVENT_RX_SMP_FRAME_ERROR_COUNT:
		src_str = "Received SMP frame error count";
		break;
	default:
		src_str = "<Unknown>";
		break;
	}

	return (src_str);
}

static void
smp_validate_args(int argc, char *argv[])
{
	errno = 0;

	if (argc < 3)
		fatal(-1, "Usage: %s <device> <function> ...\n", argv[0]);

	func = strtoul(argv[2], NULL, 0);

	if (errno != 0)
		fatal(-1, "Usage: %s <device> <function> ...\n", argv[0]);

	switch (func) {
	case SMP_FUNC_DISCOVER:
	case SMP_FUNC_REPORT_PHY_EVENT:
	case SMP_FUNC_REPORT_PHY_ERROR_LOG: {
		if (argc != 4) {
			fatal(-1,
			    "Usage: %s <device> 0x%x <phy identifier>\n",
			    argv[0], func);
		}
		break;
	}
	case SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST: {
		if (argc < 4) {
			fatal(-1,
			    "Usage: %s <device> 0x%x <SAS Address Index>\n",
			    argv[0], func);
		}
		break;
	}
	case SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD: {
		if (argc < 4) {
			fatal(-1,
			    "Usage: %s <device> 0x%x <report type>\n",
			    argv[0], func);
		}
		break;
	}
	case SMP_FUNC_ENABLE_DISABLE_ZONING: {
		if (argc != 4) {
			fatal(-1,
			    "Usage: %s <device> 0x%x "
			    "[0(no change) | 1(enable)| 2(disable)]\n",
			    argv[0], func);
		}
		break;
	}
	case SMP_FUNC_REPORT_BROADCAST: {
		if (argc != 4) {
			fatal(-1, "Usage: %s <device> 0x%x <bcast type>\n",
			    argv[0], func);
		}
		break;
	}
	case SMP_FUNC_REPORT_ROUTE_INFO: {
		if (argc != 5) {
			fatal(-1,
			    "Usage: %s <device> 0x%x <exp_route_idx> "
			    "<phy_identifier>\n", argv[0], func);
		}
		break;
	}
	case SMP_FUNC_PHY_CONTROL: {
		if (argc != 5) {
			fatal(-1,
			    "Usage: %s <device> 0x%x <phy identifier> "
			    " <phy operation>\n",
			    argv[0], func);
		}
		break;
	}
	default: {
		fatal(-1, "Usage: %s <device> <function> ...\n", argv[0]);
		break;
	}
	}
}

int
main(int argc, char *argv[])
{
	uint_t i, j;
	char *yesorno;
	uint16_t exp_change_count;

	/*
	 * If the arguments are invalid, this function will not return.
	 */
	smp_validate_args(argc, argv);

	if (smp_init(LIBSMP_VERSION) != 0)
		fatal(-1, "libsmp initialization failed: %s", smp_errmsg());

	bzero(&tdef, sizeof (smp_target_def_t));
	tdef.std_def = argv[1];

	if ((tp = smp_open(&tdef)) == NULL) {
		smp_fini();
		fatal(-2, "failed to open %s: %s", argv[1], smp_errmsg());
	}

	exp_change_count = smp_target_get_change_count(tp);

	(void) printf("%s\n", argv[0]);
	(void) printf("\tSAS Address: %016llx\n", smp_target_addr(tp));
	(void) printf("\tVendor/Product/Revision: %s/%s/%s\n",
	    smp_target_vendor(tp), smp_target_product(tp),
	    smp_target_revision(tp));
	(void) printf("\tExp Vendor/ID/Rev: %s/%04x/%02x\n",
	    smp_target_component_vendor(tp), smp_target_component_id(tp),
	    smp_target_component_revision(tp));
	(void) printf("\tExpander change count: 0x%04x\n", exp_change_count);

	ap = smp_action_alloc(func, tp, 0);
	if (ap == NULL) {
		smp_close(tp);
		smp_fini();
		fatal(-3, "failed to allocate action: %s", smp_errmsg());
	}

	switch (func) {
	case SMP_FUNC_DISCOVER: {
		smp_discover_req_t *dp;

		smp_action_get_request(ap, (void **)&dp, NULL);
		dp->sdr_phy_identifier = strtoul(argv[3], NULL, 0);
		break;
	}
	case SMP_FUNC_REPORT_ROUTE_INFO: {
		smp_handle_report_route_info(argc, argv);
		break;
	}
	case SMP_FUNC_ENABLE_DISABLE_ZONING: {
		smp_enable_disable_zoning_req_t *rp;

		smp_action_get_request(ap, (void **)&rp, NULL);
		rp->sedzr_enable_disable_zoning = strtoul(argv[3], NULL, 0);
		break;
	}
	case SMP_FUNC_PHY_CONTROL: {
		smp_phy_control_req_t *rp;

		smp_action_get_request(ap, (void **)&rp, NULL);
		rp->spcr_phy_identifier = strtoul(argv[3], NULL, 0);
		rp->spcr_phy_operation = strtoul(argv[4], NULL, 0);
		break;
	}
	case SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST: {
		smp_report_exp_route_table_list_req_t *rp;

		smp_action_get_request(ap, (void **)&rp, NULL);
		SCSI_WRITE16(&rp->srertlr_max_descrs, 64);
		SCSI_WRITE16(&rp->srertlr_starting_routed_sas_addr_index,
		    strtoull(argv[3], NULL, 0));
		rp->srertlr_starting_phy_identifier = 0;
		break;
	}
	case SMP_FUNC_REPORT_PHY_ERROR_LOG: {
		smp_report_phy_error_log_req_t *pelp;

		smp_action_get_request(ap, (void **)&pelp, NULL);
		pelp->srpelr_phy_identifier = strtoul(argv[3], NULL, 0);
		break;
	}
	case SMP_FUNC_REPORT_PHY_EVENT: {
		smp_report_phy_event_req_t *rpep;

		smp_action_get_request(ap, (void **)&rpep, NULL);
		rpep->srper_phy_identifier = strtoul(argv[3], NULL, 0);
		break;
	}
	case SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD: {
		smp_report_zone_mgr_password_req_t *rzmprp;

		smp_action_get_request(ap, (void **)&rzmprp, NULL);
		rzmprp->srzmpr_rpt_type = strtoul(argv[3], NULL, 0);
		break;
	}
	case SMP_FUNC_REPORT_BROADCAST: {
		smp_report_broadcast_req_t *rbrp;

		smp_action_get_request(ap, (void **)&rbrp, NULL);
		rbrp->srbr_broadcast_type = strtoul(argv[3], NULL, 0);
		break;
	}
	default:
		smp_close(tp);
		smp_action_free(ap);
		smp_fini();
		smp_cmd_failed(result);
	}

	smp_execute();
	smp_get_response(B_TRUE);

	switch (func) {
	case SMP_FUNC_DISCOVER: {
		smp_discover_resp_t *rp = (smp_discover_resp_t *)smp_resp;
		(void) printf("Addr: %016llx Phy: %02x\n",
		    SCSI_READ64(&rp->sdr_sas_addr), rp->sdr_phy_identifier);
		(void) printf("Peer: %016llx Phy: %02x\n",
		    SCSI_READ64(&rp->sdr_attached_sas_addr),
		    rp->sdr_attached_phy_identifier);
		(void) printf("Device type: %01x\n",
		    rp->sdr_attached_device_type);
		break;
	}
	case SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD: {
		smp_report_zone_mgr_password_resp_t *rp =
		    (smp_report_zone_mgr_password_resp_t *)smp_resp;
		char *rpt_type = NULL;
		int idx;
		switch (rp->srzmpr_rpt_type) {
			case SMP_ZMP_TYPE_CURRENT:
				rpt_type = "Current";
				break;
			case SMP_ZMP_TYPE_SAVED:
				rpt_type = "Saved";
				break;
			case SMP_ZMP_TYPE_DEFAULT:
				rpt_type = "Default";
				break;
			default:
				rpt_type = "(Unknown Type)";
				break;
		}
		(void) printf("%s zone manager password: 0x", rpt_type);
		for (idx = 0; idx < 32; idx++) {
			(void) printf("%02x",
			    rp->srzmpr_zone_mgr_password[idx]);
		}
		(void) printf("\n");
		break;
	}
	case SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST: {
		smp_report_exp_route_table_list_resp_t *rtlr =
		    (smp_report_exp_route_table_list_resp_t *)smp_resp;
		smp_route_table_descr_t *descp = &rtlr->srertlr_descrs[0];
		int idx, idxx, ndescrs, zoning, startnum;

		(void) printf("Expander change count: 0x%04x\n",
		    BE_16(rtlr->srertlr_exp_change_count));
		(void) printf("Expander route table change count: 0x%04x\n",
		    BE_16(rtlr->srertlr_route_table_change_count));

		if (rtlr->srertlr_zoning_enabled) {
			yesorno = yes;
			zoning = 1;
		} else {
			yesorno = no;
			zoning = 0;
		}
		(void) printf("Zoning enabled: %s\n", yesorno);

		if (rtlr->srertlr_configuring) {
			yesorno = yes;
		} else {
			yesorno = no;
		}
		(void) printf("Configuring: %s\n", yesorno);

		ndescrs = rtlr->srertlr_n_descrs;
		(void) printf("Number of descriptors: %d\n", ndescrs);
		startnum = BE_16(rtlr->srertlr_first_routed_sas_addr_index);
		(void) printf("First/Last routed SAS address index: %d/%d\n",
		    startnum, BE_16(rtlr->srertlr_last_routed_sas_addr_index));
		(void) printf("Starting PHY identifier: %d\n",
		    rtlr->srertlr_starting_phy_identifier);

		for (idx = 0; idx < ndescrs; idx++, descp++) {
			(void) printf("#%03d: Routed SAS addr: %016llx  ",
			    idx + startnum, BE_64(descp->srtd_routed_sas_addr));
			(void) printf("PHY bitmap: 0x");
			for (idxx = 0; idxx < 6; idxx++) {
				(void) printf("%02x",
				    descp->srtd_phy_bitmap[idxx]);
			}
			(void) printf("\n");
			if (zoning) {
				(void) printf("\tZone group: %d\n",
				    descp->srtd_zone_group);
			}
		}

		(void) printf("\n");
		break;
	}
	case SMP_FUNC_REPORT_PHY_ERROR_LOG: {
		smp_report_phy_error_log_resp_t *pelr =
		    (smp_report_phy_error_log_resp_t *)smp_resp;
		(void) printf("PHY error log for PHY %d:\n",
		    pelr->srpelr_phy_identifier);
		(void) printf("\tInvalid DWORD count: %d\n",
		    BE_32(pelr->srpelr_invalid_dword_count));
		(void) printf("\tRunning disparity error count: %d\n",
		    BE_32(pelr->srpelr_running_disparity_error_count));
		(void) printf("\tLoss of DWORD sync count: %d\n",
		    BE_32(pelr->srpelr_loss_dword_sync_count));
		(void) printf("\tPHY reset problem count: %d\n",
		    BE_32(pelr->srpelr_phy_reset_problem_count));
		break;
	}
	case SMP_FUNC_REPORT_PHY_EVENT: {
		smp_report_phy_event_resp_t *rper =
		    (smp_report_phy_event_resp_t *)smp_resp;
		smp_phy_event_report_descr_t *perd =
		    &rper->srper_phy_event_descrs[0];
		boolean_t peak;
		int idx;

		(void) printf("PHY event for PHY %d:\n",
		    rper->srper_phy_identifier);
		(void) printf("Number of PHY event descriptors: %d\n",
		    rper->srper_n_phy_event_descrs);

		for (idx = 0; idx < rper->srper_n_phy_event_descrs; idx++) {
			(void) printf("%50s : %d\n",
			    smp_phy_event_src_str(perd->sped_phy_event_source,
			    &peak), BE_32(perd->sped_phy_event));
			if (peak) {
				(void) printf("\tPeak value detector "
				    "threshold: %d\n",
				    BE_32(perd->sped_peak_detector_threshold));
			}
			perd++;
		}

		break;
	}
	case SMP_FUNC_REPORT_BROADCAST: {
		smp_report_broadcast_resp_t *brp =
		    (smp_report_broadcast_resp_t *)smp_resp;
		smp_broadcast_descr_t *bdp = &brp->srbr_descrs[0];
		uint16_t bcount, idx;

		bcount = brp->srbr_number_broadcast_descrs;

		(void) printf("\tNumber of broadcast descriptors: %d\n",
		    bcount);
		(void) printf("\t%7s %5s %5s %8s\n",
		    "BCType", "PhyID", "BCRsn", "BC Count");
		for (idx = 0; idx < bcount; idx++) {
			(void) printf("\t%7s %5s %5s %8s\n",
			    bdp->sbd_broadcast_type, bdp->sbd_phy_identifier,
			    bdp->sbd_broadcast_reason,
			    bdp->sbd_broadcast_count);
			bdp++;
		}

		break;
	}
	default:
		(void) printf("Response: (len %d)\n", smp_resp_len);
		for (i = 0; i < smp_resp_len; i += 8) {
			(void) printf("%02x: ", i);
			for (j = i; j < i + 8; j++)
				if (j < smp_resp_len)
					(void) printf("%02x ", smp_resp[j]);
				else
					(void) printf("   ");
			for (j = i; j < i + 8; j++)
				(void) printf("%c",
				    j < smp_resp_len && isprint(smp_resp[j]) ?
				    smp_resp[j] : j < smp_resp_len ? '.' :
				    '\0');
			(void) printf("\n");
		}
		break;
	}

	smp_cleanup();
	return (0);
}
