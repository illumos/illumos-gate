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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ereport-handling routines for memory errors
 */

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_cpu.h>
#include <cmd.h>

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/async.h>
#include <sys/cheetahregs.h>
#include <sys/errclassify.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/pci/pcisch.h>

/* Jalapeno-specific values from cheetahregs.h */
#define	USIIIi_AFSR_AID		0x0000000000003e00ull /* AID causing UE/CE */
#define	USIIIi_AFSR_AID_SHIFT	9
#define	USIIIi_AFSR_JREQ	0x0000000007000000ull /* Active JBus req */
#define	USIIIi_AFSR_JREQ_SHIFT	24
#define	TOM_AID_MATCH_MASK	0xe

/*ARGSUSED*/
cmd_evdisp_t
cmd_mem_synd_check(fmd_hdl_t *hdl, uint64_t afar, uint8_t afar_status,
    uint16_t synd, uint8_t synd_status, cmd_cpu_t *cpu)
{
	if (synd == CH_POISON_SYND_FROM_XXU_WRITE ||
	    ((cpu->cpu_type == CPU_ULTRASPARC_IIIi ||
	    cpu->cpu_type == CPU_ULTRASPARC_IIIiplus) &&
	    synd == CH_POISON_SYND_FROM_XXU_WRMERGE)) {
		fmd_hdl_debug(hdl,
		    "discarding UE due to magic syndrome %x\n", synd);
		return (CMD_EVD_UNUSED);
	}
	return (CMD_EVD_OK);
}

static cmd_evdisp_t
xe_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_xe_handler_f *hdlr)
{
	uint64_t afar;
	uint16_t synd;
	uint8_t afar_status, synd_status;
	nvlist_t *rsrc;
	char *typenm;
	uint64_t disp;
	int minorvers = 1;

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_EREPORT_PAYLOAD_NAME_AFAR, DATA_TYPE_UINT64, &afar,
	    FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS, DATA_TYPE_UINT8, &afar_status,
	    FM_EREPORT_PAYLOAD_NAME_SYND, DATA_TYPE_UINT16, &synd,
	    FM_EREPORT_PAYLOAD_NAME_SYND_STATUS, DATA_TYPE_UINT8, &synd_status,
	    FM_EREPORT_PAYLOAD_NAME_ERR_TYPE, DATA_TYPE_STRING, &typenm,
	    FM_EREPORT_PAYLOAD_NAME_RESOURCE, DATA_TYPE_NVLIST, &rsrc,
	    NULL) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_ERR_DISP,
	    &disp) != 0)
		minorvers = 0;

	return (hdlr(hdl, ep, nvl, class, afar, afar_status, synd,
	    synd_status, cmd_mem_name2type(typenm, minorvers), disp, rsrc));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ce(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (xe_common(hdl, ep, nvl, class, cmd_ce_common));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ue(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (xe_common(hdl, ep, nvl, class, cmd_ue_common));
}

cmd_evdisp_t
cmd_frx(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_errcl_t matchmask = (clcode == CMD_ERRCL_FRC ? (CMD_ERRCL_RCE |
	    CMD_ERRCL_IOCE) : (CMD_ERRCL_RUE | CMD_ERRCL_IOUE));

	return (cmd_rxefrx_common(hdl, ep, nvl, class, clcode, matchmask));
}

/*
 * When we complete an IOxE/RxE FRx pair, we have enough information to
 * create either a CE or a UE, as appropriate.  Before dispatching the
 * joined event to the xE handler, we need to generate the FMRI for the
 * named DIMM.  While one of the events may already contain a resource FMRI,
 * said FMRI is incomplete.  The detector didn't have the necessary
 * information (the AFAR, the AFSR, *and* the syndrome) needed to create
 * a DIMM-level FMRI.
 */
static cmd_evdisp_t
iorxefrx_synthesize(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, uint64_t afar, uint8_t afar_status, uint64_t afsr,
    uint16_t synd, uint8_t synd_status, ce_dispact_t type, uint64_t disp,
    cmd_xe_handler_f *hdlr)
{
	nvlist_t *fmri;
	int rc;

	if ((fmri = cmd_dimm_fmri_derive(hdl, afar, synd, afsr)) == NULL)
		return (CMD_EVD_UNUSED);

	rc = hdlr(hdl, ep, nvl, class, afar, afar_status, synd, synd_status,
	    type, disp, fmri);

	nvlist_free(fmri);

	return (rc);
}

static cmd_iorxefrx_t *
iorxefrx_match(fmd_hdl_t *hdl, cmd_errcl_t errcl, cmd_errcl_t matchmask,
    uint_t det_agentid, uint_t afsr_agentid)
{
	cmd_iorxefrx_t *rf;

	for (rf = cmd_list_next(&cmd.cmd_iorxefrx); rf != NULL;
	    rf = cmd_list_next(rf)) {

		fmd_hdl_debug(hdl, "rf->rf_errcl = %llx, matchmask = %llx\n"
		    "rf->rf_det_agentid = %lx, afsr_agentid = %lx\n"
		    "rf->rf_afsr_agentid = %lx, det_agentid = %lx\n",
		    rf->rf_errcl, matchmask, rf->rf_det_agentid, afsr_agentid,
		    rf->rf_afsr_agentid, det_agentid);

		if ((rf->rf_errcl & matchmask) == 0)
			continue;

		/*
		 * For IOxEs we are unable to match based on both the detector
		 * and the captured Agent Id in the AFSR, because the bridge
		 * captures it's own Agent Id instead of the remote CPUs.
		 *
		 * Also, the LSB of Tomatillo's jpid is aliased for each chip
		 * and therefore needs to be factored out of our matching.
		 */
		if ((CMD_ERRCL_ISIOXE(rf->rf_errcl) ||
		    CMD_ERRCL_ISIOXE(errcl)) &&
		    ((rf->rf_afsr_agentid & TOM_AID_MATCH_MASK) ==
		    (afsr_agentid & TOM_AID_MATCH_MASK)))
			return (rf);

		/*
		 * Check for both here since IOxE is not involved
		 */
		if ((rf->rf_afsr_agentid == det_agentid) &&
		    (rf->rf_det_agentid == afsr_agentid))
			return (rf);
	}

	return (NULL);
}

/*
 * Got an RxE or an FRx.  FRx ereports can be matched with RxE ereports and
 * vice versa.  FRx ereports can also be matched with IOxE ereports.
 */
cmd_evdisp_t
cmd_rxefrx_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode, cmd_errcl_t matchmask)
{
	cmd_xe_handler_f *hdlr;
	cmd_iorxefrx_t *rfmatch, *rferr;
	cmd_cpu_t *cpu;
	char *typenm;
	int isrxe = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_RCE | CMD_ERRCL_RUE);
	int isce = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_RCE | CMD_ERRCL_FRC);
	int rc;
	int minorvers = 1;

	rferr = fmd_hdl_zalloc(hdl, sizeof (cmd_iorxefrx_t), FMD_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_EREPORT_PAYLOAD_NAME_SYND, DATA_TYPE_UINT16, &rferr->rf_synd,
	    FM_EREPORT_PAYLOAD_NAME_SYND_STATUS, DATA_TYPE_UINT8,
	    &rferr->rf_synd_status,
	    FM_EREPORT_PAYLOAD_NAME_AFAR, DATA_TYPE_UINT64, &rferr->rf_afar,
	    FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS, DATA_TYPE_UINT8,
	    &rferr->rf_afar_status,
	    FM_EREPORT_PAYLOAD_NAME_AFSR, DATA_TYPE_UINT64, &rferr->rf_afsr,
	    FM_EREPORT_PAYLOAD_NAME_ERR_TYPE, DATA_TYPE_STRING, &typenm,
	    NULL) != 0) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_BAD);
	}
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_ERR_DISP,
	    &rferr->rf_disp) != 0)
		minorvers = 0;

	rferr->rf_type = cmd_mem_name2type(typenm, minorvers);

	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class)) == NULL) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_UNUSED);
	}

	if (!isrxe && rferr->rf_synd_status != AFLT_STAT_VALID) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_UNUSED);
	}

	if (isrxe) {
		rferr->rf_afsr_agentid = (rferr->rf_afsr &
		    USIIIi_AFSR_JREQ) >> USIIIi_AFSR_JREQ_SHIFT;
	} else {
		rferr->rf_afsr_agentid = (rferr->rf_afsr &
		    USIIIi_AFSR_AID) >> USIIIi_AFSR_AID_SHIFT;
	}

	rferr->rf_errcl = clcode;
	rferr->rf_det_agentid = cpu->cpu_cpuid;

	if ((rfmatch = iorxefrx_match(hdl, clcode, matchmask,
	    rferr->rf_det_agentid, rferr->rf_afsr_agentid)) == NULL) {
		cmd_iorxefrx_queue(hdl, rferr);
		return (CMD_EVD_OK);
	}

	/*
	 * Found a match.  Send a synthesized ereport to the appropriate
	 * routine.
	 */
	fmd_hdl_debug(hdl, "matched %cE %llx with %llx", "UC"[isce],
	    rferr->rf_errcl, rfmatch->rf_errcl);

	hdlr = (isce ? cmd_ce_common : cmd_ue_common);
	if (isrxe) {
		rc = iorxefrx_synthesize(hdl, ep, nvl, class, rferr->rf_afar,
		    rferr->rf_afar_status, rfmatch->rf_afsr, rfmatch->rf_synd,
		    rfmatch->rf_synd_status, rferr->rf_type, rferr->rf_disp,
		    hdlr);
	} else {
		rc = iorxefrx_synthesize(hdl, ep, nvl, class, rfmatch->rf_afar,
		    rfmatch->rf_afar_status, rferr->rf_afsr, rferr->rf_synd,
		    rferr->rf_synd_status, rfmatch->rf_type, rferr->rf_disp,
		    hdlr);
	}

	cmd_iorxefrx_free(hdl, rfmatch);
	fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));

	return (rc);
}

/* This IOxE must be matched with an FRx before UE/CE processing is possible */
static cmd_evdisp_t
cmd_ioxefrx_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t errcl, cmd_errcl_t matchmask)
{
	cmd_xe_handler_f *hdlr;
	cmd_iorxefrx_t *rfmatch, *rferr;
	char *typenm;
	int isce = CMD_ERRCL_MATCH(errcl, CMD_ERRCL_IOCE);
	char *portid_str;
	char *path = NULL;
	nvlist_t *det = NULL;
	int rc;
	int minorvers = 1;

	rferr = fmd_hdl_zalloc(hdl, sizeof (cmd_iorxefrx_t), FMD_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    PCI_ECC_AFAR, DATA_TYPE_UINT64, &rferr->rf_afar,
	    PCI_ECC_AFSR, DATA_TYPE_UINT64, &rferr->rf_afsr,
	    PCI_ECC_SYND, DATA_TYPE_UINT16, &rferr->rf_synd,
	    PCI_ECC_TYPE, DATA_TYPE_STRING, &typenm,
	    NULL) != 0) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_BAD);
	}

	if (nvlist_lookup_uint64(nvl, PCI_ECC_DISP, &rferr->rf_disp) != 0)
		minorvers = 0;

	rferr->rf_type = cmd_mem_name2type(typenm, minorvers);
	rferr->rf_errcl = errcl;

	/*
	 * Lookup device path of host bridge.
	 */
	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det);
	(void) nvlist_lookup_string(det, FM_FMRI_DEV_PATH, &path);

	/*
	 * get Jbus port id from the device path
	 */
	portid_str = strrchr(path, '@') + 1;
	rferr->rf_det_agentid = strtol(portid_str, NULL, 16);

	rferr->rf_afsr_agentid = (rferr->rf_afsr &
	    SCHIZO_ECC_UE_AFSR_AGENT_MID) >> SCHIZO_ECC_UE_AFSR_AGENT_MID_SHIFT;

	/*
	 * Only 4 bits of the Jbus AID are sent on the Jbus.  MSB is the one
	 * that is chosen not to make the trip.  This is not in any of the Jbus
	 * or Tomatillo documents and was discovered during testing and verified
	 * by Jalapeno H/W designer.
	 */
	rferr->rf_afsr_agentid &= 0xf;
	rferr->rf_afar_status = AFLT_STAT_VALID;
	rferr->rf_synd_status = AFLT_STAT_VALID;

	/*
	 * Need to send in the io_jpid that we get from the device path above
	 * for both the det_agentid and the afsr_agentid, since the CPU does not
	 * capture the same address as the bridge.  The bridge has the LSB
	 * aliased and the CPU is missing the MSB.
	 */
	if ((rfmatch = iorxefrx_match(hdl, rferr->rf_errcl, matchmask,
	    rferr->rf_det_agentid, rferr->rf_afsr_agentid)) == NULL) {
		cmd_iorxefrx_queue(hdl, rferr);
		return (CMD_EVD_OK);
	}

	/* Found a match.  Synthesize an ereport for UE/CE processing. */
	fmd_hdl_debug(hdl, "matched %cE %llx with %llx\n", "UC"[isce],
	    rferr->rf_errcl, rfmatch->rf_errcl);

	hdlr = (isce ? cmd_ce_common : cmd_ue_common);
	rc = iorxefrx_synthesize(hdl, ep, nvl, class, rferr->rf_afar,
	    rferr->rf_afar_status, rfmatch->rf_afsr, rfmatch->rf_synd,
	    rfmatch->rf_synd_status, rferr->rf_type, rferr->rf_disp, hdlr);

	cmd_iorxefrx_free(hdl, rfmatch);
	fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));

	return (rc);
}

/* IOxE ereports that don't need matching with FRx ereports */
static cmd_evdisp_t
ioxe_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	int isce = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_IOCE);
	cmd_xe_handler_f *hdlr = isce ? cmd_ce_common : cmd_ue_common;
	uint64_t afar;
	uint16_t synd;
	nvlist_t *rsrc;
	char *typenm;
	uint64_t disp;
	int minorvers = 1;

	if (nvlist_lookup_pairs(nvl, 0,
	    PCI_ECC_AFAR, DATA_TYPE_UINT64, &afar,
	    PCI_ECC_SYND, DATA_TYPE_UINT16, &synd,
	    PCI_ECC_TYPE, DATA_TYPE_STRING, &typenm,
	    PCI_ECC_RESOURCE, DATA_TYPE_NVLIST, &rsrc,
	    NULL) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl, PCI_ECC_DISP, &disp) != 0)
		minorvers = 0;

	return (hdlr(hdl, ep, nvl, class, afar, AFLT_STAT_VALID, synd,
	    AFLT_STAT_VALID, cmd_mem_name2type(typenm, minorvers), disp,
	    rsrc));
}

cmd_evdisp_t
cmd_rxe(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_errcl_t matchmask = (clcode == CMD_ERRCL_RCE ? CMD_ERRCL_FRC :
	    CMD_ERRCL_FRU);

	return (cmd_rxefrx_common(hdl, ep, nvl, class, clcode, matchmask));
}

cmd_evdisp_t
cmd_ioxe(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_errcl_t matchmask = (clcode == CMD_ERRCL_IOCE ? CMD_ERRCL_FRC :
	    CMD_ERRCL_FRU);

	if (fmd_nvl_class_match(hdl, nvl, "ereport.io.tom.*")) {
		return (cmd_ioxefrx_common(hdl, ep, nvl, class, clcode,
		    matchmask));
	} else
		return (ioxe_common(hdl, ep, nvl, class, clcode));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ioxe_sec(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	/*
	 * Secondary IOxE's can't be used to identify failed or failing
	 * resources, as they don't contain enough information.  Ignore them.
	 */
	return (CMD_EVD_OK);
}
