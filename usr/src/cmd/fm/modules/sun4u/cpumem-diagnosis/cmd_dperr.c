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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ereport-handling routines for Datapath errors
 * - receive datapath ereports and open datapath case
 * - solve datapath case when datapath fault ereports are received
 * - maintain state of datapath error flag
 * - close datapath case when timeout occurs (w/o fault)
 */


#include <strings.h>
#include <string.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#include <sys/time.h>
#include <cmd.h>
#include <cmd_state.h>
#include <cmd_dp.h>
#include <cmd_dp_page.h>
#include <cmd_page.h>
#include <libnvpair.h>
#include <sys/plat_datapath.h>

/*
 * Member Name     Data Type          Comments
 * -----------     ---------          -----------
 * version         uint8              0
 * class           string             "asic"
 * ENA             uint64             ENA Format 1
 * detector        fmri               aggregated ID data for SC-DE
 *
 * Datapath ereport subclasses and data payloads:
 * There will be two types of ereports (error and fault) which will be
 * identified by the "type" member.
 *
 * ereport.asic.*.cds.cds-dp
 * ereport.asic.*.dx.dx-dp
 * ereport.asic.*.sdi.sdi-dp
 * ereport.asic.*.cp.cp-dp
 * ereport.asic.*.rp.rp-dp		// serengeti doesn't use "cp" term
 *
 * Member Name     Data Type          Comments
 * -----------     ---------          -----------
 * erptype         uint16            derived from message type: error or
 *                                   fault
 * t-value         uint32            SC's datapath SERD timeout threshold
 * dp-list-sz      uint8             number of dp-list array elements
 * dp-list         array of uint16   Safari IDs of affected cpus
 */

static char *dperrtype[] = {
	DP_ERROR_CDS,		/* Starcat types */
	DP_ERROR_DX,
	DP_ERROR_EX,
	DP_ERROR_CP,
	DP_ERROR_CDS,		/* Serengeti types */
	DP_ERROR_DX,
	DP_ERROR_RP
};

/*
 * Construct the ASRU(s)/FRU(s) associated with a data path fault,
 * construct the fault(s), and add the suspect(s) to the case
 *
 */
void
cmd_dp_add_suspects(fmd_hdl_t *hdl, cmd_dp_t *dp)
{
	const char	*funcname = "cmd_dp_add_suspects()";
	char		class[DP_MAX_CLASS];
	char		frustr[3][DP_MAX_FRU];
	int		cpuid, numfru, sgpos, xcpos, i, err;
	nvlist_t	*asru, *fru = NULL, *flt, *hcel;

	/* build ASRU, fault event class */
	asru = cmd_dp_setasru(hdl, dp);
	(void) snprintf(class, DP_MAX_CLASS, "fault.asic.%s.%s",
	    dperrtype[dp->dp_err], FM_ERROR_DATAPATH);

	cpuid = dp->dp_cpuid_list[0];

	/* extract fru position */
	sgpos = ((cpuid & 0x1f) / 4);
	xcpos = ((cpuid >> 5) & 0x1f);

	/* build FRU(s) for the particular error */
	numfru = 0;
	switch (dp->dp_err) {
	case SC_DP_CDS_TYPE:
	case SC_DP_DX_TYPE:
		/* check for slot 1 (maxcat) */
		if ((cpuid >> 3) & 0x1)
			(void) snprintf(frustr[0], DP_MAX_FRU, "IO%d", xcpos);
		else
			(void) snprintf(frustr[0], DP_MAX_FRU, "SB%d", xcpos);

		numfru = 1;
		break;

	case SC_DP_EX_TYPE:
		/* check for slot 1 (maxcat) */
		if ((cpuid >> 3) & 0x1)
			(void) snprintf(frustr[0], DP_MAX_FRU, "IO%d", xcpos);
		else
			(void) snprintf(frustr[0], DP_MAX_FRU, "SB%d", xcpos);

		(void) snprintf(frustr[1], DP_MAX_FRU, "EX%d", xcpos);
		numfru = 2;
		break;

	case SC_DP_CP_TYPE:
		/* no way to know which CP half, be generic */
		(void) snprintf(frustr[0], DP_MAX_FRU, "EX%d", xcpos);
		(void) snprintf(frustr[1], DP_MAX_FRU, "CP");
		(void) snprintf(frustr[2], DP_MAX_FRU, "CS");
		numfru = 3;
		break;

	case SG_DP_CDS_TYPE:
	case SG_DP_DX_TYPE:
		(void) snprintf(frustr[0], DP_MAX_FRU, "/N0/SB%d", sgpos);
		numfru = 1;
		break;

	case SG_DP_RP_TYPE:
		/* no way to know which RP, be generic */
		(void) snprintf(frustr[0], DP_MAX_FRU, "/N0/SB%d", sgpos);
		(void) snprintf(frustr[1], DP_MAX_FRU, "RP");
		numfru = 2;
		break;

	default:
		fmd_hdl_debug(hdl, "%s: invalid DP error type %d", funcname,
		    dp->dp_err);
		nvlist_free(asru);
		return;
	}

	/* For each FRU, build an FMRI, create fault, add as suspect */
	for (i = 0; i < numfru; i++) {
		/* build a FRU FMRI */
		if (nvlist_alloc(&hcel, NV_UNIQUE_NAME, 0) != 0) {
			nvlist_free(asru);
			return;
		}
		err = nvlist_add_string(hcel, FM_FMRI_HC_NAME,
		    FM_FMRI_LEGACY_HC);
		err |= nvlist_add_string(hcel, FM_FMRI_HC_ID, frustr[i]);
		if (err != 0) {
			nvlist_free(hcel);
			nvlist_free(asru);
			return;
		}

		/* put it in an HC scheme */
		if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
			nvlist_free(hcel);
			nvlist_free(asru);
			return;
		}
		err = nvlist_add_uint8(fru, FM_VERSION, FM_HC_SCHEME_VERSION);
		err |= nvlist_add_string(fru, FM_FMRI_SCHEME,
		    FM_FMRI_SCHEME_HC);
		err |= nvlist_add_string(fru, FM_FMRI_HC_ROOT, "");
		err |= nvlist_add_uint32(fru, FM_FMRI_HC_LIST_SZ, 1);
		err |= nvlist_add_nvlist_array(fru, FM_FMRI_HC_LIST, &hcel, 1);
		if (err != 0) {
			nvlist_free(fru);
			nvlist_free(hcel);
			nvlist_free(asru);
			return;
		}

		/* create the fault, add to case. */
		flt = cmd_nvl_create_fault(hdl, class, 100/numfru,
		    asru, fru, NULL);
		fmd_case_add_suspect(hdl, dp->dp_case, flt);

		/* free up memory */
		nvlist_free(fru);
		nvlist_free(hcel);
	}

	/* free up ASRU */
	nvlist_free(asru);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_dp_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
	cmd_errcl_t clcode, uint8_t dperr)
{
	const char	*funcname = "cmd_dp_common()";
	const char	*uuidp;
	cmd_dp_t	*dpt, *ept;
	int 		err, i, fltflg;
	uint16_t	*cpuid_list;
	uint64_t	*serid_list;
	uint32_t	ncpuids;

	/* extract common ereport contents */
	dpt = fmd_hdl_zalloc(hdl, sizeof (cmd_dp_t), FMD_SLEEP);
	dpt->dp_nodetype = CMD_NT_DP;
	dpt->dp_version = CMD_DP_VERSION;
	dpt->dp_err = dperr;
	err = nvlist_lookup_pairs(nvl, 0,
	    DP_EREPORT_TYPE, DATA_TYPE_UINT16, &dpt->dp_erpt_type,
	    DP_TVALUE, DATA_TYPE_UINT32, &dpt->dp_t_value,
	    DP_LIST_SIZE, DATA_TYPE_UINT32, &ncpuids, NULL);
	if (err != 0) {
		fmd_hdl_debug(hdl, "%s: unable to verify ereport contents "
		    "(erptype, ena, t_value, dp_list_sz)", funcname);
		fmd_hdl_free(hdl, dpt, sizeof (cmd_dp_t));
		return (CMD_EVD_UNUSED);
	}

	/* extract cpuid list from ereport */
	err = nvlist_lookup_uint16_array(nvl, DP_LIST, &cpuid_list,
	    &ncpuids);
	err |= nvlist_lookup_uint64_array(nvl, SN_LIST, &serid_list,
	    &ncpuids);
	if (err != 0) {
		fmd_hdl_debug(hdl, "%s: unable to verify ereport contents "
		    "(dp_list, sn_list)", funcname);
		fmd_hdl_free(hdl, dpt, sizeof (cmd_dp_t));
		return (CMD_EVD_UNUSED);
	}

	for (i = 0; i < ncpuids; i++) {
		dpt->dp_cpuid_list[i] = cpuid_list[i];
		dpt->dp_serid_list[i] = serid_list[i];
	}

	dpt->dp_ncpus = ncpuids;

	switch (dpt->dp_erpt_type) {

	case DP_ERROR:

		/*
		 * Scan existing faults on cmd.cmd_datapaths. If each
		 * cpuid in the current datapath event already has an
		 * associated DP fault, this is an uninteresting event.
		 */
		fltflg = 0;
		for (i = 0; i < ncpuids; i++)
			if (cmd_dp_lookup_fault(hdl, cpuid_list[i]) != NULL)
				fltflg++;
		if (fltflg == ncpuids) {
			fmd_hdl_debug(hdl, "%s: datapath fault(s) already "
			    "experienced, event uninteresting\n", funcname);
			fmd_hdl_free(hdl, dpt, sizeof (cmd_dp_t));
			return (CMD_EVD_UNUSED);
		}

		/*
		 * Check for an existing datapath error, and if found
		 * add this event to the existing case
		 */
		ept = cmd_dp_lookup_error(dpt);
		if (ept != NULL && !fmd_case_closed(hdl, ept->dp_case)) {
			fmd_hdl_debug(hdl, "%s: found existing datapath error, "
			    "adding event to case\n", funcname);
			fmd_case_add_ereport(hdl, ept->dp_case, ep);
			/* check for t-value change */
			if (dpt->dp_t_value != ept->dp_t_value) {
				fmd_event_t *ep;

				fmd_timer_remove(hdl, ept->dp_id);
				ep = fmd_case_getprincipal(hdl, ept->dp_case);
				ept->dp_id = fmd_timer_install(hdl,
				    (void *)CMD_TIMERTYPE_DP, ep,
				    (hrtime_t)NANOSEC *
				    (dpt->dp_t_value + 120));
			}
			fmd_hdl_free(hdl, dpt, sizeof (cmd_dp_t));
			return (CMD_EVD_OK);
		}

		/*
		 * Didn't find an existing datapath error. Create a new
		 * case, add the event. Also, stash the datapath event on the
		 * cmd.cmd_datapaths list
		 */
		fmd_hdl_debug(hdl, "%s: new datapath error, create case and "
		    "add to cmd.cmd_datapaths\n", funcname);
		++cmd.cmd_dp_flag;

		cmd_bufname(dpt->dp_bufname, sizeof (dpt->dp_bufname),
		    "dp_err_%d_%s", dpt->dp_cpuid_list[0],
		    dperrtype[dpt->dp_err]);

		dp_buf_write(hdl, dpt);

		dpt->dp_case = cmd_case_create(hdl, &dpt->dp_header,
		    CMD_PTR_DP_CASE, &uuidp);
		fmd_case_setprincipal(hdl, dpt->dp_case, ep);
		dpt->dp_id = fmd_timer_install(hdl, (void *)CMD_TIMERTYPE_DP,
		    ep, (hrtime_t)NANOSEC * (dpt->dp_t_value + 120));
		cmd_list_append(&cmd.cmd_datapaths, dpt);
		break;

	case DP_FAULT:
		++cmd.cmd_dp_flag;
		dpt->dp_erpt_type = DP_FAULT;
		dpt->dp_id = 0;

		cmd_bufname(dpt->dp_bufname, sizeof (dpt->dp_bufname),
		    "dp_flt_%d_%s", dpt->dp_cpuid_list[0],
		    dperrtype[dpt->dp_err]);

		dp_buf_write(hdl, dpt);

		/*
		 * Check for an existing DP_ERROR on cmd.cmd_datapaths, and
		 * if found, remove the DP_ERROR and close the case before
		 * creating the DP_FAULT case.
		 */
		ept = cmd_dp_lookup_error(dpt);
		if (ept != NULL && !fmd_case_closed(hdl, ept->dp_case)) {
			fmd_hdl_debug(hdl, "%s: existing datapath error "
			    "overtaken by datapath fault\n", funcname);
			fmd_timer_remove(hdl, ept->dp_id);
			cmd_dp_destroy(hdl, ept);
		}

		dpt->dp_case = cmd_case_create(hdl, &dpt->dp_header,
		    CMD_PTR_DP_CASE, &uuidp);
		fmd_case_setprincipal(hdl, dpt->dp_case, ep);

		/* Add suspect(s) and solve the case. */
		cmd_dp_add_suspects(hdl, dpt);
		fmd_case_solve(hdl, dpt->dp_case);

		/* add it to cmd.cmd_datapaths */
		cmd_list_append(&cmd.cmd_datapaths, dpt);

		--cmd.cmd_dp_flag;
		if (cmd.cmd_dp_flag == 0)
			cmd_dp_page_replay(hdl);

		break;

	default:
		fmd_hdl_debug(hdl, "%s: unknown ereport type", funcname);
		fmd_hdl_free(hdl, dpt, sizeof (cmd_dp_t));
		return (CMD_EVD_UNUSED);
	}

	return (CMD_EVD_OK);
}

cmd_evdisp_t
cmd_dp_cds(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	if (fmd_nvl_class_match(hdl, nvl, "ereport.asic.starcat.*")) {
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SC_DP_CDS_TYPE));
	} else
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SG_DP_CDS_TYPE));
}

cmd_evdisp_t
cmd_dp_dx(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	if (fmd_nvl_class_match(hdl, nvl, "ereport.asic.starcat.*")) {
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SC_DP_DX_TYPE));

	} else
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SG_DP_DX_TYPE));
}

cmd_evdisp_t
cmd_dp_ex(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (cmd_dp_common(hdl, ep, nvl, class, clcode,
	    SC_DP_EX_TYPE));
}

cmd_evdisp_t
cmd_dp_cp(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	if (fmd_nvl_class_match(hdl, nvl, "ereport.asic.starcat.*")) {
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SC_DP_CP_TYPE));
	} else
		return (cmd_dp_common(hdl, ep, nvl, class, clcode,
		    SG_DP_RP_TYPE));
}
