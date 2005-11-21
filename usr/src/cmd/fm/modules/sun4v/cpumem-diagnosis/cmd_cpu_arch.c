/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing per-CPU state.
 */

#include <cmd_cpu.h>
#include <cmd_mem.h>
#include <cmd.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <kstat.h>
#include <fm/fmd_api.h>
#include <sys/async.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-T1.h>
#include <sys/niagararegs.h>

int
cmd_xr_fill(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_xr_t *xr, cmd_errcl_t clcode)
{
	uint64_t niagara_l2_afsr = 0;

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_AFSR,
	    &niagara_l2_afsr) != 0)
		return (-1);
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_REAL_AFAR,
	    &xr->xr_afar) != 0)
		return (-1);
	if (nvlist_lookup_uint32(nvl, FM_EREPORT_PAYLOAD_NAME_L2_SYND,
	    &xr->xr_synd) != 0)
		return (-1);

	/*
	 * Set Niagara afar and synd validity.
	 * For a given set of error registers, the payload value is valid iff
	 * no higher priority error status bit is set.  See niagararegs.h
	 * for error status bit values and priority settings.
	 */
	switch (clcode) {
	case CMD_ERRCL_LDAU:
	case CMD_ERRCL_LDSU:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P02) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDWU:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P03) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDRU:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P04) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDAC:
	case CMD_ERRCL_LDSC:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P07) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDWC:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P08) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDRC:
		xr->xr_synd_status =
		    ((niagara_l2_afsr & NI_L2AFSR_P09) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	default:
		fmd_hdl_debug(hdl, "Niagara unrecognized l2cache error\n");
		xr->xr_synd_status = 0;
		return (-1);
	}
	xr->xr_afar_status = xr->xr_synd_status;
	return (0);
}

int
cmd_cpu_synd_check(uint32_t synd)
{
	int i;

	/*
	 * Niagara L2 fetches from a memory location containing a UE
	 * are given a poison syndrome in one or more 7 bit subsyndromes
	 * each covering one of 4 4 byte checkwords.
	 *
	 * 0 is an invalid syndrome because it denotes no error, but
	 * is associated with an ereport -- meaning there WAS an error.
	 */
	if (synd == 0)
		return (-1);

	for (i = 0; i < 4; i++) {
		if (((synd >> i*NI_L2_POISON_SYND_SIZE) &
		    NI_L2_POISON_SYND_MASK) == NI_L2_POISON_SYND_FROM_DAU)
			return (-1);
	}
	return (0);
}
