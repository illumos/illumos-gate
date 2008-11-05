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

	rferr->rf_afsr = NULL;
	rferr->rf_synd = NULL;

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
 * DRAM by bit.  Note that this is independent of check-word or DIMM side.
 * Actual DRAM pin *is* dependent on both check-word and DIMM side.
 * DRAMs are numbered D0 to D35, but that doesn't tell us what DIMM
 * they're on!
 *
 * Data bits are numbers, 0 - 127.
 * ECC bits C0 - C8 => 128-136
 * MTAG bits MT0 - MT2 => 137-139
 * MTAG ECC bits MTC0 - MTC3 => 140-143
 *
 *
 * Uniboard Server Systems.
 */
int unib_upos2dram[] = {
	/* 0 */ 3, /* 1 */ 3, /* 2 */ 3, /* 3 */ 1,
	/* 4 */ 2, /* 5 */ 0, /* 6 */ 1, /* 7 */ 2,
	/* 8 */ 4, /* 9 */ 4, /* 10 */ 4, /* 11 */ 4,
	/* 12 */ 5, /* 13 */ 5, /* 14 */ 5, /* 15 */ 5,
	/* 16 */ 6, /* 17 */ 6, /* 18 */ 6, /* 19 */ 6,
	/* 20 */ 7, /* 21 */ 7, /* 22 */ 7, /* 23 */ 7,
	/* 24 */ 8, /* 25 */ 8, /* 26 */ 8, /* 27 */ 8,
	/* 28 */ 9, /* 29 */ 9, /* 30 */ 9, /* 31 */ 9,
	/* 32 */ 10, /* 33 */ 10, /* 34 */ 10, /* 35 */ 10,
	/* 36 */ 11, /* 37 */ 11, /* 38 */ 11, /* 39 */ 11,
	/* 40 */ 12, /* 41 */ 12, /* 42 */ 12, /* 43 */ 12,
	/* 44 */ 13, /* 45 */ 13, /* 46 */ 13, /* 47 */ 13,
	/* 48 */ 14, /* 49 */ 14, /* 50 */ 14, /* 51 */ 15,
	/* 52 */ 15, /* 53 */ 15, /* 54 */ 16, /* 55 */ 16,
	/* 56 */ 17, /* 57 */ 17, /* 58 */ 17, /* 59 */ 17,
	/* 60 */ 18, /* 61 */ 18, /* 62 */ 18, /* 63 */ 18,
	/* 64 */ 19, /* 65 */ 19, /* 66 */ 19, /* 67 */ 19,
	/* 68 */ 20, /* 69 */ 20, /* 70 */ 20, /* 71 */ 20,
	/* 72 */ 21, /* 73 */ 21, /* 74 */ 22, /* 75 */ 22,
	/* 76 */ 22, /* 77 */ 23, /* 78 */ 23, /* 79 */ 23,
	/* 80 */ 24, /* 81 */ 24, /* 82 */ 24, /* 83 */ 24,
	/* 84 */ 25, /* 85 */ 25, /* 86 */ 25, /* 87 */ 25,
	/* 88 */ 26, /* 89 */ 26, /* 90 */ 26, /* 91 */ 26,
	/* 92 */ 27, /* 93 */ 27, /* 94 */ 27, /* 95 */ 27,
	/* 96 */ 28, /* 97 */ 28, /* 98 */ 28, /* 99 */ 28,
	/* 100 */ 29, /* 101 */ 29, /* 102 */ 29, /* 103 */ 29,
	/* 104 */ 30, /* 105 */ 30, /* 106 */ 30, /* 107 */ 30,
	/* 108 */ 31, /* 109 */ 31, /* 110 */ 31, /* 111 */ 31,
	/* 112 */ 32, /* 113 */ 32, /* 114 */ 32, /* 115 */ 32,
	/* 116 */ 33, /* 117 */ 33, /* 118 */ 33, /* 119 */ 33,
	/* 120 */ 34, /* 121 */ 34, /* 122 */ 34, /* 123 */ 34,
	/* 124 */ 35, /* 125 */ 35, /* 126 */ 35, /* 127 */ 35,
	/* 128 */ 16, /* 129 */ 15, /* 130 */ 14, /* 131 */ 16,
	/* 132 */ 0, /* 133 */ 21, /* 134 */ 23, /* 135 */ 22,
	/* 136 */ 21, /* 137 */ 0, /* 138 */ 1, /* 139 */ 2,
	/* 140 */ 0, /* 141 */ 1, /* 142 */ 2, /* 143 */ 3
};

/*
 * Camelot Server Systems.
 */
int cams_upos2dram[] = {
	/* 0 */ 5, /* 1 */ 5, /* 2 */ 5, /* 3 */ 5,
	/* 4 */ 7, /* 5 */ 7, /* 6 */ 7, /* 7 */ 7,
	/* 8 */ 6, /* 9 */ 6, /* 10 */ 6, /* 11 */ 6,
	/* 12 */ 8, /* 13 */ 8, /* 14 */ 8, /* 15 */ 8,
	/* 16 */ 4, /* 17 */ 4, /* 18 */ 4, /* 19 */ 4,
	/* 20 */ 0, /* 21 */ 0, /* 22 */ 0, /* 23 */ 0,
	/* 24 */ 3, /* 25 */ 3, /* 26 */ 3, /* 27 */ 3,
	/* 28 */ 2, /* 29 */ 2, /* 30 */ 2, /* 31 */ 2,
	/* 32 */ 1, /* 33 */ 1, /* 34 */ 1, /* 35 */ 1,
	/* 36 */ 14, /* 37 */ 14, /* 38 */ 14, /* 39 */ 14,
	/* 40 */ 16, /* 41 */ 16, /* 42 */ 16, /* 43 */ 16,
	/* 44 */ 17, /* 45 */ 17, /* 46 */ 15, /* 47 */ 15,
	/* 48 */ 13, /* 49 */ 13, /* 50 */ 13, /* 51 */ 9,
	/* 52 */ 9, /* 53 */ 9, /* 54 */ 12, /* 55 */ 12,
	/* 56 */ 11, /* 57 */ 11, /* 58 */ 11, /* 59 */ 11,
	/* 60 */ 10, /* 61 */ 10, /* 62 */ 10, /* 63 */ 10,
	/* 64 */ 23, /* 65 */ 23, /* 66 */ 23, /* 67 */ 23,
	/* 68 */ 25, /* 69 */ 25, /* 70 */ 25, /* 71 */ 25,
	/* 72 */ 24, /* 73 */ 24, /* 74 */ 26, /* 75 */ 26,
	/* 76 */ 26, /* 77 */ 22, /* 78 */ 22, /* 79 */ 22,
	/* 80 */ 18, /* 81 */ 21, /* 82 */ 21, /* 83 */ 21,
	/* 84 */ 20, /* 85 */ 20, /* 86 */ 20, /* 87 */ 20,
	/* 88 */ 19, /* 89 */ 19, /* 90 */ 19, /* 91 */ 19,
	/* 92 */ 32, /* 93 */ 32, /* 94 */ 32, /* 95 */ 32,
	/* 96 */ 34, /* 97 */ 34, /* 98 */ 34, /* 99 */ 34,
	/* 100 */ 33, /* 101 */ 33, /* 102 */ 33, /* 103 */ 33,
	/* 104 */ 35, /* 105 */ 35, /* 106 */ 35, /* 107 */ 35,
	/* 108 */ 31, /* 109 */ 31, /* 110 */ 31, /* 111 */ 31,
	/* 112 */ 27, /* 113 */ 27, /* 114 */ 27, /* 115 */ 27,
	/* 116 */ 30, /* 117 */ 30, /* 118 */ 30, /* 119 */ 30,
	/* 120 */ 29, /* 121 */ 29, /* 122 */ 29, /* 123 */ 29,
	/* 124 */ 28, /* 125 */ 28, /* 126 */ 28, /* 127 */ 28,
	/* 128 */ 12, /* 129 */ 9, /* 130 */ 13, /* 131 */ 12,
	/* 132 */  18, /* 133 */ 24, /* 134 */ 22, /* 135 */ 26,
	/* 136 */ 24, /* 137 */ 21, /* 138 */ 18, /* 139 */ 18,
	/* 140 */ 15, /* 141 */ 15, /* 142 */ 17, /* 143 */ 17
};

/*
 * Camelot Tower Systems.
 */
int camt_upos2dram[] = {
	/* 0 */ 18, /* 1 */ 0, /* 2 */ 0, /* 3 */ 0,
	/* 4 */ 9, /* 5 */ 18, /* 6 */ 27, /* 7 */ 9,
	/* 8 */ 28, /* 9 */ 28, /* 10 */ 28, /* 11 */ 28,
	/* 12 */ 29, /* 13 */ 29, /* 14 */ 29, /* 15 */ 29,
	/* 16 */ 30, /* 17 */ 30, /* 18 */ 30, /* 19 */ 30,
	/* 20 */ 21, /* 21 */ 21, /* 22 */ 21, /* 23 */ 21,
	/* 24 */ 12, /* 25 */ 12, /* 26 */ 12, /* 27 */ 12,
	/* 28 */ 22, /* 29 */ 22, /* 30 */ 22, /* 31 */ 22,
	/* 32 */ 31, /* 33 */ 31, /* 34 */ 31, /* 35 */ 31,
	/* 36 */ 32, /* 37 */ 32, /* 38 */ 32, /* 39 */ 32,
	/* 40 */ 33, /* 41 */ 33, /* 42 */ 33, /* 43 */ 33,
	/* 44 */ 24, /* 45 */ 24, /* 46 */ 24, /* 47 */ 24,
	/* 48 */ 15, /* 49 */ 15, /* 50 */ 15, /* 51 */ 25,
	/* 52 */ 25, /* 53 */ 25, /* 54 */ 34, /* 55 */ 34,
	/* 56 */ 35, /* 57 */ 35, /* 58 */ 35, /* 59 */ 35,
	/* 60 */ 19, /* 61 */ 19, /* 62 */ 19, /* 63 */ 19,
	/* 64 */ 10, /* 65 */ 10, /* 66 */ 10, /* 67 */ 10,
	/* 68 */ 1, /* 69 */ 1, /* 70 */ 1, /* 71 */ 1,
	/* 72 */ 20, /* 73 */ 20, /* 74 */ 11, /* 75 */ 11,
	/* 76 */ 11, /* 77 */ 2, /* 78 */ 2, /* 79 */ 2,
	/* 80 */ 3, /* 81 */ 3, /* 82 */ 3, /* 83 */ 3,
	/* 84 */ 4, /* 85 */ 4, /* 86 */ 4, /* 87 */ 4,
	/* 88 */ 13, /* 89 */ 13, /* 90 */ 13, /* 91 */ 13,
	/* 92 */ 23, /* 93 */ 23, /* 94 */ 23, /* 95 */ 23,
	/* 96 */ 14, /* 97 */ 14, /* 98 */ 14, /* 99 */ 14,
	/* 100 */ 5, /* 101 */ 5, /* 102 */ 5, /* 103 */ 5,
	/* 104 */ 6, /* 105 */ 6, /* 106 */ 6, /* 107 */ 6,
	/* 108 */ 7, /* 109 */ 7, /* 110 */ 7, /* 111 */ 7,
	/* 112 */ 16, /* 113 */ 16, /* 114 */ 16, /* 115 */ 16,
	/* 116 */ 26, /* 117 */ 26, /* 118 */ 26, /* 119 */ 26,
	/* 120 */ 17, /* 121 */ 17, /* 122 */ 17, /* 123 */ 17,
	/* 124 */ 8, /* 125 */ 8, /* 126 */ 8, /* 127 */ 8,
	/* 128 */ 34, /* 129 */ 25, /* 130 */ 15, /* 131 */ 34,
	/* 132 */  27, /* 133 */ 20, /* 134 */ 2, /* 135 */ 11,
	/* 136 */ 20, /* 137 */ 9, /* 138 */ 18, /* 139 */ 27,
	/* 140 */ 0, /* 141 */ 9, /* 142 */ 18, /* 143 */ 27
};

/*
 * Fiesta Server Systems.
 */
int fies_upos2dram[] = {
	/* 0 */ 7, /* 1 */ 7, /* 2 */ 7, /* 3 */ 7,
	/* 4 */ 16, /* 5 */ 16, /* 6 */ 16, /* 7 */ 16,
	/* 8 */ 25, /* 9 */ 25, /* 10 */ 25, /* 11 */ 25,
	/* 12 */ 34, /* 13 */ 34, /* 14 */ 34, /* 15 */ 34,
	/* 16 */ 6, /* 17 */ 6, /* 18 */ 6, /* 19 */ 6,
	/* 20 */ 15, /* 21 */ 15, /* 22 */ 15, /* 23 */ 15,
	/* 24 */ 24, /* 25 */ 24, /* 26 */ 24, /* 27 */ 24,
	/* 28 */ 33, /* 29 */ 33, /* 30 */ 33, /* 31 */ 33,
	/* 32 */ 23, /* 33 */ 23, /* 34 */ 23, /* 35 */ 23,
	/* 36 */ 32, /* 37 */ 32, /* 38 */ 32, /* 39 */ 32,
	/* 40 */ 22, /* 41 */ 22, /* 42 */ 22, /* 43 */ 22,
	/* 44 */ 31, /* 45 */ 31, /* 46 */ 31, /* 47 */ 31,
	/* 48 */ 5, /* 49 */ 5, /* 50 */ 5, /* 51 */ 5,
	/* 52 */ 14, /* 53 */ 14, /* 54 */ 14, /* 55 */ 14,
	/* 56 */ 4, /* 57 */ 4, /* 58 */ 4, /* 59 */ 4,
	/* 60 */ 13, /* 61 */ 13, /* 62 */ 13, /* 63 */ 13,
	/* 64 */ 18, /* 65 */ 18, /* 66 */ 18, /* 67 */ 18,
	/* 68 */ 27, /* 69 */ 27, /* 70 */ 27, /* 71 */ 27,
	/* 72 */ 0, /* 73 */ 0, /* 74 */ 0, /* 75 */ 0,
	/* 76 */ 9, /* 77 */ 9, /* 78 */ 9, /* 79 */ 9,
	/* 80 */ 19, /* 81 */ 19, /* 82 */ 19, /* 83 */ 19,
	/* 84 */ 28, /* 85 */ 28, /* 86 */ 28, /* 87 */ 28,
	/* 88 */ 1, /* 89 */ 1, /* 90 */ 1, /* 91 */ 1,
	/* 92 */ 10, /* 93 */ 10, /* 94 */ 10, /* 95 */ 10,
	/* 96 */ 3, /* 97 */ 3, /* 98 */ 3, /* 99 */ 3,
	/* 100 */ 12, /* 101 */ 12, /* 102 */ 12, /* 103 */ 12,
	/* 104 */ 20, /* 105 */ 20, /* 106 */ 20, /* 107 */ 20,
	/* 108 */ 29, /* 109 */ 29, /* 110 */ 29, /* 111 */ 29,
	/* 112 */ 8, /* 113 */ 8, /* 114 */ 8, /* 115 */ 8,
	/* 116 */ 17, /* 117 */ 17, /* 118 */ 17, /* 119 */ 17,
	/* 120 */ 21, /* 121 */ 21, /* 122 */ 21, /* 123 */ 21,
	/* 124 */ 30, /* 125 */ 30, /* 126 */ 30, /* 127 */ 30,
	/* 128 */ 2, /* 129 */ 2, /* 130 */ 2, /* 131 */ 2,
	/* 132 */ 11, /* 133 */ 11, /* 134 */ 11, /* 135 */ 11,
	/* 136 */ 26, /* 137 */ 26, /* 138 */ 26, /* 139 */ 26,
	/* 140 */ 35, /* 141 */ 35, /* 142 */ 35, /* 143 */ 35
};

/*
 * Fiesta Tower Systems.
 */
int fiet_upos2dram[] = {
	/* 0 */ 0, /* 1 */ 0, /* 2 */ 0, /* 3 */ 0,
	/* 4 */ 9, /* 5 */ 9, /* 6 */ 9, /* 7 */ 9,
	/* 8 */ 18, /* 9 */ 18, /* 10 */ 18, /* 11 */ 18,
	/* 12 */ 27, /* 13 */ 27, /* 14 */ 27, /* 15 */ 27,
	/* 16 */ 19, /* 17 */ 19, /* 18 */ 19, /* 19 */ 19,
	/* 20 */ 28, /* 21 */ 28, /* 22 */ 28, /* 23 */ 28,
	/* 24 */ 1, /* 25 */ 1, /* 26 */ 1, /* 27 */ 1,
	/* 28 */ 10, /* 29 */ 10, /* 30 */ 10, /* 31 */ 10,
	/* 32 */ 20, /* 33 */ 20, /* 34 */ 20, /* 35 */ 20,
	/* 36 */ 29, /* 37 */ 29, /* 38 */ 29, /* 39 */ 29,
	/* 40 */ 2, /* 41 */ 2, /* 42 */ 2, /* 43 */ 2,
	/* 44 */ 11, /* 45 */ 11, /* 46 */ 11, /* 47 */ 11,
	/* 48 */ 21, /* 49 */ 21, /* 50 */ 21, /* 51 */ 21,
	/* 52 */ 30, /* 53 */ 30, /* 54 */ 30, /* 55 */ 30,
	/* 56 */ 3, /* 57 */ 3, /* 58 */ 3, /* 59 */ 3,
	/* 60 */ 12, /* 61 */ 12, /* 62 */ 12, /* 63 */ 12,
	/* 64 */ 8, /* 65 */ 8, /* 66 */ 8, /* 67 */ 8,
	/* 68 */ 17, /* 69 */ 17, /* 70 */ 17, /* 71 */ 17,
	/* 72 */ 22, /* 73 */ 22, /* 74 */ 22, /* 75 */ 22,
	/* 76 */ 31, /* 77 */ 31, /* 78 */ 31, /* 79 */ 31,
	/* 80 */ 4, /* 81 */ 4, /* 82 */ 4, /* 83 */ 4,
	/* 84 */ 13, /* 85 */ 13, /* 86 */ 13, /* 87 */ 13,
	/* 88 */ 23, /* 89 */ 23, /* 90 */ 23, /* 91 */ 23,
	/* 92 */ 32, /* 93 */ 32, /* 94 */ 32, /* 95 */ 32,
	/* 96 */ 5, /* 97 */ 5, /* 98 */ 5, /* 99 */ 5,
	/* 100 */ 14, /* 101 */ 14, /* 102 */ 14, /* 103 */ 14,
	/* 104 */ 24, /* 105 */ 24, /* 106 */ 24, /* 107 */ 24,
	/* 108 */ 33, /* 109 */ 33, /* 110 */ 33, /* 111 */ 33,
	/* 112 */ 6, /* 113 */ 6, /* 114 */ 6, /* 115 */ 6,
	/* 116 */ 15, /* 117 */ 15, /* 118 */ 15, /* 119 */ 15,
	/* 120 */ 25, /* 121 */ 25, /* 122 */ 25, /* 123 */ 25,
	/* 124 */ 34, /* 125 */ 34, /* 126 */ 34, /* 127 */ 34,
	/* 128 */ 7, /* 129 */ 7, /* 130 */ 7, /* 131 */ 7,
	/* 132 */ 16, /* 133 */ 16, /* 134 */ 16, /* 135 */ 16,
	/* 136 */ 26, /* 137 */ 26, /* 138 */ 26, /* 139 */ 26,
	/* 140 */ 35, /* 141 */ 35, /* 142 */ 35, /* 143 */ 35
};

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

typedef enum plats2dram {
	UNI_S_PLAT = 0,	/* UniBoard Server Systems */
	CAM_S_PLAT,	/* Camelot Server Systems */
	CAM_T_PLAT,	/* Camelot Tower Systems */
	FIE_S_PLAT,	/* Fiesta Server Systems */
	FIE_T_PLAT,	/* Fiesta Tower Systems */
	NONE
} plats_t;

struct plat2dram_map {
	char	*platnm;
	plats_t	plat;
} dram_plat[] = {
	/* Platform name		DRAM Map	Code Name */
	{"SUNW,Sun-Fire-15000",		UNI_S_PLAT}, /* Starcat */
	{"SUNW,Sun-Fire",		UNI_S_PLAT}, /* Serengeti */
	{"SUNW,Netra-T12",		UNI_S_PLAT}, /* Lightweight 8 */
	{"SUNW,Sun-Fire-480R",		CAM_S_PLAT}, /* Cherrystone */
	{"SUNW,Sun-Fire-880",		CAM_S_PLAT}, /* Daktari */
	{"SUNW,Sun-Fire-V490",		CAM_S_PLAT}, /* Sebring */
	{"SUNW,Sun-Fire-V890",		CAM_S_PLAT}, /* Silverstone */
	{"SUNW,Sun-Blade-1000",		CAM_T_PLAT}, /* Excalibur */
	{"SUNW,Netra-T4",		CAM_T_PLAT}, /* Netra 20 */
	{"SUNW,Sun-Fire-V440",		FIE_S_PLAT}, /* Chalupa */
	{"SUNW,Sun-Fire-V445",		FIE_S_PLAT}, /* Boston */
	{"SUNW,A70",			FIE_S_PLAT}, /* Chicago */
	{"SUNW,Sun-Fire-V215",		FIE_S_PLAT}, /* Seattle 1U */
	{"SUNW,Sun-Fire-V245",		FIE_S_PLAT}, /* Seattle 2U */
	{"SUNW,Netra-440",		FIE_S_PLAT}, /* Netra 440 */
	{"SUNW,Sun-Blade-1500",		FIE_T_PLAT}, /* Taco */
	{"SUNW,Sun-Blade-2500",		FIE_T_PLAT}, /* Enchilada */
	{"SUNW,Sun-Fire-V210",		FIE_T_PLAT}, /* Enchilada 1U */
	{"SUNW,Sun-Fire-V240",		FIE_T_PLAT}, /* Enchilada 2U */
	{"SUNW,Sun-Fire-V250",		FIE_T_PLAT}, /* Enchilada 2P */
	{"SUNW,Netra-210",		FIE_T_PLAT}, /* Netra 210 */
	{"SUNW,Netra-240",		FIE_T_PLAT}, /* Netra 240 */
	{NULL,				NONE}
};

int
cmd_synd2upos(uint16_t syndrome) {
	return (esynd2bit[syndrome]);
}

const char *fmd_fmri_get_platform();

/*
 * Return the DRAM within the DIMM associated with the unit position.
 */
int
cmd_upos2dram(uint16_t unit_position) {

	int		i, dram;
	plats_t		plat = NONE;
	const char 	*plat_name = fmd_fmri_get_platform();
	int		*plat_upos2dram[] = {
		unib_upos2dram,
		cams_upos2dram,
		camt_upos2dram,
		fies_upos2dram,
		fiet_upos2dram
	};

	/* get DRAM map from platform name */
	for (i = 0; dram_plat[i].platnm != NULL; i++) {
		if (strcmp(plat_name, dram_plat[i].platnm) == 0) {
			plat = dram_plat[i].plat;
			break;
		}
	}

	if (plat != NONE) {
		dram = plat_upos2dram[plat][unit_position];
	} else {
		dram = -1;
	}

	return (dram);
}
