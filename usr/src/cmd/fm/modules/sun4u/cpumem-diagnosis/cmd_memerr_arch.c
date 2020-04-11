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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <limits.h>
#include <unistd.h>
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

#define	FIRE_AID		0xe
#define	FIRE_JBC_ADDR_MASK	0x000007ffffffffffull
#define	FIRE_JBC_JITEL1		"jbc-jitel1"

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
	uint8_t level = clcode & CMD_ERRCL_LEVEL_EXTRACT;

	clcode &= CMD_ERRCL_LEVEL_MASK;
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

	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,
	    level)) == NULL) {
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

/*
 * This fire IOxE must be matched with an FRx before UE/CE processing
 * is possible.
 *
 * Note that for fire ereports we don't receive AFSR, AFAR, AFAR-Status
 * and SYND values but we can derive the AFAR from the payload value
 * FIRE_JBC_JITEL1.  We may receive a TYPNM value.
 */
static cmd_evdisp_t
cmd_ioxefrx_fire(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t errcl, cmd_errcl_t matchmask)
{
	cmd_xe_handler_f *hdlr;
	cmd_iorxefrx_t *rfmatch, *rferr;
	uint64_t afar;
	int isce = CMD_ERRCL_MATCH(errcl, CMD_ERRCL_IOCE);
	char *portid_str;
	char *path = NULL;
	char *typenm = NULL;
	nvlist_t *det = NULL;
	int rc;
	int minorvers = 1;

	rferr = fmd_hdl_zalloc(hdl, sizeof (cmd_iorxefrx_t), FMD_SLEEP);

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

	rferr->rf_errcl = errcl;
	rferr->rf_afsr_agentid = FIRE_AID;
	rferr->rf_afar_status = AFLT_STAT_VALID;
	rferr->rf_synd_status = AFLT_STAT_VALID;

	/*
	 * Extract the afar from the payload
	 */
	(void) nvlist_lookup_uint64(nvl, FIRE_JBC_JITEL1, &afar);
	rferr->rf_afar = afar & FIRE_JBC_ADDR_MASK;

	rferr->rf_afsr = 0;
	rferr->rf_synd = 0;

	if (nvlist_lookup_string(nvl, FM_EREPORT_PAYLOAD_NAME_ERR_TYPE,
	    &typenm) == 0)
		rferr->rf_type = cmd_mem_name2type(typenm, minorvers);

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
	} else  if (fmd_nvl_class_match(hdl, nvl, "ereport.io.fire.*")) {
			return (cmd_ioxefrx_fire(hdl, ep, nvl, class, clcode,
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

/*ARGSUSED*/
ulong_t
cmd_mem_get_phys_pages(fmd_hdl_t *hdl)
{
	return (sysconf(_SC_PHYS_PAGES));
}

/*
 * sun4u bit position as function of e_synd,
 * from JPS1 Implementation Supplement table P-7
 * Encode bit positions as follows:
 * 0-127 data bits 0-127
 * 128-136 check bits 0-8 (Cn = 128+n)
 * no error or multibit error = -1 (not valid CE)
 */

int esynd2bit [] = {
	-1, 128, 129, -1, 130, -1, -1, 47,
	131, -1, -1, 53, -1, 41, 29, -1, /* 000-00F */
	132, -1, -1, 50, -1, 38, 25, -1,
	-1, 33, 24, -1, 11, -1, -1, 16, /* 010-01F */
	133, -1, -1, 46, -1, 37, 19, -1,
	-1, 31, 32, -1,  7, -1, -1, 10, /* 020-02F */
	-1, 40, 13, -1, 59, -1, -1, 66,
	-1, -1, -1,  0, -1, 67, 71, -1, /* 030-03F */
	134, -1, -1, 43, -1, 36, 18, -1,
	-1, 49, 15, -1, 63, -1, -1,  6, /* 040-04F */
	-1, 44, 28, -1, -1, -1, -1, 52,
	68, -1, -1, 62, -1, -1, -1, -1, /* 050-05F */
	-1, 26, 106, -1, 64, -1, -1,  2,
	120, -1, -1, -1, -1, -1, -1, -1, /* 060-06F */
	116, -1, -1, -1, -1, -1, -1, -1,
	-1, 58, 54, -1, -1, -1, -1, -1, /* 070-07F */
	135, -1, -1, 42, -1, 35, 17, -1,
	-1, 45, 14, -1, 21, -1, -1,  5, /* 080-08F */
	-1, 27, -1, -1, 99, -1, -1,  3,
	114, -1, -1, 20, -1, -1, -1, -1, /* 090-09F */
	-1, 23, 113, -1, 112, -1, -1, 51,
	95, -1, -1, -1, -1, -1, -1, -1, /* 0A0-0AF */
	103, -1, -1, -1, -1, -1, -1, -1,
	-1, 48, -1, -1, 73, -1, -1, -1, /* 0B0-0BF */
	-1, 22, 110, -1, 109, -1, -1,  9,
	108, -1, -1, -1, -1, -1, -1, -1, /* 0C0-0CF */
	102, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 0D0-0DF */
	98, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 0E0-0EF */
	-1, -1, -1, -1, -1, -1, -1, -1,
	56, -1, -1, -1, -1, -1, -1, -1, /* 0F0-0FF */
	136, -1, -1, 39, -1, 34, 105, -1,
	-1, 30, 104, -1, 101, -1, -1,  4, /* 100-10F */
	-1, -1, 100, -1, 83, -1, -1, 12,
	87, -1, -1, 57, -1, -1, -1, -1, /* 110-11F */
	-1, 97, 82, -1, 78, -1, -1,  1,
	96, -1, -1, -1, -1, -1, -1, -1, /* 120-12F */
	94, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, 79, -1, 69, -1, -1, -1, /* 130-13F */
	-1, 93, 92, -1, 91, -1, -1,  8,
	90, -1, -1, -1, -1, -1, -1, -1, /* 140-14F */
	89, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 150-15F */
	86, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 160-16F */
	-1, -1, -1, -1, -1, -1, -1, -1,
	60, -1, -1, -1, -1, -1, -1, -1, /* 170-17F */
	-1, 88, 85, -1, 84, -1, -1, 55,
	81, -1, -1, -1, -1, -1, -1, -1, /* 180-18F */
	77, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 190-19F */
	74, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, /* 1A0-1AF */
	-1, 70, 107, -1, 65, -1, -1, -1,
	127, -1, -1, -1, -1, -1, -1, -1, /* 1B0-1BF */
	80, -1, -1, 72, -1, 119, 118, -1,
	-1, 126, 76, -1, 125, -1, -1, -1, /* 1C0-1CF */
	-1, 115, 124, -1, 75, -1, -1, -1,
	61, -1, -1, -1, -1, -1, -1, -1, /* 1D0-1DF */
	-1, 123, 122, -1, 121, -1, -1, -1,
	117, -1, -1, -1, -1, -1, -1, -1, /* 1E0-1EF */
	111, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1  /* 1F0-1FF */
};

int msynd2bit [] = {  /* msynd 0-F */
	-1, 140, 141,  -1,
	142, -1,  -1, 137,
	143, -1,  -1, 138,
	-1, 139,  -1,  -1
};

int
cmd_synd2upos(uint16_t syndrome)
{
	return (esynd2bit[syndrome]);
}

const char *fmd_fmri_get_platform();

#define	DP_MAX	25

const char *slotname[] = {
	"Slot A", "Slot B", "Slot C", "Slot D"};

typedef struct fault_info {
	uint32_t id;
	int count;
} fault_info_t;

struct plat2id_map {
	char *platnm;
	int id;
} id_plat[] = {
	{"SUNW,Sun-Fire-15000",		1},
	{"SUNW,Sun-Fire",		2},
	{"SUNW,Netra-T12",		2},
	{"SUNW,Sun-Fire-480R",		3},
	{"SUNW,Sun-Fire-V490",		3},
	{"SUNW,Sun-Fire-V440",		3},
	{"SUNW,Sun-Fire-V445",		3},
	{"SUNW,Netra-440",		3},
	{"SUNW,Sun-Fire-880",		4},
	{"SUNW,Sun-Fire-V890",		4},
	{NULL,				0}
};

/*ARGSUSED*/
void
cmd_to_hashed_addr(uint64_t *addr, uint64_t afar, const char *class)
{
	*addr = afar;
}

/*ARGSUSED*/
int
cmd_same_datapath_dimms(cmd_dimm_t *d1, cmd_dimm_t *d2)
{
	return (1);
}

static int
cmd_get_platform()
{
	const char *platname;
	int id = -1;
	int i;

	platname = fmd_fmri_get_platform();
	for (i = 0; id_plat[i].platnm != NULL; i++) {
		if (strcmp(platname, id_plat[i].platnm) == 0) {
			id = id_plat[i].id;
			break;
		}
	}
	return (id);
}

static int
cmd_get_boardid(uint32_t cpuid)
{
	int boardid;
	int id = cmd_get_platform();

	switch (id) {
	case 1:
		boardid = ((cpuid >> 5) & 0x1f);
		break;
	case 2:
		boardid = ((cpuid & 0x1f) / 4);
		break;

	case 3:
		cpuid = cpuid & 0x07;
		boardid = ((cpuid % 2) == 0) ? 0 : 1;
		break;
	case 4:
		cpuid = cpuid & 0x07;
		if ((cpuid % 2) == 0)
			boardid = (cpuid < 4) ? 0 : 2;
		else
			boardid = (cpuid < 5) ? 1 : 3;
		break;
	default:
		boardid = 5;
		break;
	}

	return (boardid);
}

static void
cmd_get_faulted_comp(fmd_hdl_t *hdl, cmd_dimm_t *d1, cmd_dimm_t *d2,
    uint16_t upos, fault_info_t **fault_list, int cpu)
{
	cmd_mq_t *ip;
	int i, j, k, idj;
	uint32_t id;
	uint32_t *cpuid = NULL;
	int max_rpt;

	max_rpt = 2 * cmd.cmd_nupos;

	cpuid = fmd_hdl_alloc(hdl, max_rpt * sizeof (uint32_t), FMD_SLEEP);

	if (cpuid == NULL)
		return;

	for (i = 0, j = 0; i < CMD_MAX_CKWDS; i++) {
		for (ip = cmd_list_next(&d1->mq_root[i]); ip != NULL;
		    ip = cmd_list_next(ip)) {
			if (upos == ip->mq_unit_position) {
				cpuid[j] = ip->mq_cpuid;
				j++;
			}
			if (j >= cmd.cmd_nupos)
				break;
		}
		if (j >= cmd.cmd_nupos)
			break;
	}

	for (i = 0; i < CMD_MAX_CKWDS; i++) {
		for (ip = cmd_list_next(&d2->mq_root[i]); ip != NULL;
		    ip = cmd_list_next(ip)) {
			if (upos == ip->mq_unit_position) {
				cpuid[j] = ip->mq_cpuid;
				j++;
			}
			if (j >= max_rpt)
				break;
		}
		if (j >= max_rpt)
			break;
	}

	for (i = 0, k = 0; i < max_rpt; i++) {
		if (cpuid[i] == ULONG_MAX)
			continue;
		id = (cpu == 0) ? cmd_get_boardid(cpuid[i]) : cpuid[i];
		fault_list[k] = fmd_hdl_alloc(hdl,
		    sizeof (fault_info_t), FMD_SLEEP);
		if (fault_list[k] == NULL)
			break;
		fault_list[k]->count = 1;
		fault_list[k]->id = id;
		for (j = i + 1; j < max_rpt; j++) {
			if (cpuid[j] == ULONG_MAX)
				continue;
			idj = (cpu == 0) ? cmd_get_boardid(cpuid[j]) : cpuid[j];
			if (id == idj) {
				fault_list[k]->count++;
				cpuid[j] = ULONG_MAX;
			}
		}
		k++;
	}

	fmd_hdl_free(hdl, cpuid, max_rpt * sizeof (uint32_t));
}

/*ARGSUSED*/
static nvlist_t *
cmd_board_mkfru(fmd_hdl_t *hdl, char *frustr)
{
	nvlist_t *hcel, *fru;
	int err;

	if (frustr == NULL)
		return (NULL);

	if (nvlist_alloc(&hcel, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	err = nvlist_add_string(hcel, FM_FMRI_HC_NAME,
	    FM_FMRI_LEGACY_HC);
	err |= nvlist_add_string(hcel, FM_FMRI_HC_ID, frustr);
	if (err != 0) {
		nvlist_free(hcel);
		return (NULL);
	}

	if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(hcel);
		return (NULL);
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
		return (NULL);
	}
	nvlist_free(hcel);
	return (fru);
}

/*
 * Startcat, Serengeti, V4xx, and V8xx: fault the system boards of
 * the detectors in proportion to the number of ereports out of 8
 * Other systems: fault the detectors in proportion to the number of
 * ereports out of 8
 */
void
cmd_gen_datapath_fault(fmd_hdl_t *hdl, cmd_dimm_t *d1, cmd_dimm_t *d2,
    uint16_t upos, nvlist_t *det)
{
	char frustr[DP_MAX];
	fmd_case_t *cp;
	int i, ratio, type, fault_cpu, max_rpt;
	uint32_t id;
	uint8_t cpumask;
	char *cpustr;
	fault_info_t **fault_list = NULL;
	nvlist_t *fru = NULL, *asru = NULL, *flt = NULL;

	max_rpt = cmd.cmd_nupos * 2;
	fault_list = fmd_hdl_alloc(hdl,
	    max_rpt * sizeof (fault_info_t *), FMD_SLEEP);

	if (fault_list == NULL)
		return;

	for (i = 0; i < max_rpt; i++)
		fault_list[i] = NULL;

	type = cmd_get_platform();

	fault_cpu = (type == -1) ? 1 : 0;

	cmd_get_faulted_comp(hdl, d1, d2, upos, fault_list, fault_cpu);

	cp = fmd_case_open(hdl, NULL);

	for (i = 0; i < max_rpt; i++) {
		if (fault_list[i] == NULL)
			continue;
		id = fault_list[i]->id;

		switch (type) {
		case 1:
			(void) snprintf(frustr, DP_MAX, "EX%d", id);
			break;
		case 2:
			(void) snprintf(frustr, DP_MAX, "/N0/SB%d", id);
			break;
		case 3:
		case 4:
			(void) snprintf(frustr, DP_MAX, slotname[id]);
			break;
		default:
			cpustr = cmd_cpu_getfrustr_by_id(hdl, id);
			if (nvlist_lookup_uint8(det, FM_FMRI_CPU_MASK, &cpumask)
			    == 0) {
				asru = cmd_cpu_fmri_create(id, cpumask);
				(void) fmd_nvl_fmri_expand(hdl, asru);
			}
			break;
		}

		ratio = (fault_list[i]->count * 100) / (cmd.cmd_nupos * 2);

		if (fault_cpu) {
			fru = cmd_cpu_mkfru(hdl, cpustr, NULL, NULL);
			fmd_hdl_strfree(hdl, cpustr);
			if (fru == NULL) {
				nvlist_free(asru);
				break;
			}
			flt = cmd_nvl_create_fault(hdl, "fault.memory.datapath",
			    ratio, asru, fru, asru);
			nvlist_free(asru);
		} else {
			fru = cmd_board_mkfru(hdl, frustr);
			if (fru == NULL)
				break;
			flt = cmd_nvl_create_fault(hdl, "fault.memory.datapath",
			    ratio, fru, fru, fru);
		}

		fmd_case_add_suspect(hdl, cp, flt);

		/* free up memory */
		nvlist_free(fru);
	}

	fmd_case_solve(hdl, cp);

	for (i = 0; i < max_rpt; i++) {
		if (fault_list[i] != NULL)
			fmd_hdl_free(hdl, fault_list[i], sizeof (fault_info_t));
	}

	fmd_hdl_free(hdl, fault_list, sizeof (fault_info_t *) * max_rpt);
}
