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
#include <cmd_hc_sun4v.h>

int cmd_afsr_check(fmd_hdl_t *,  uint64_t, cmd_errcl_t, uint8_t *);

int
cmd_xr_fill(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_xr_t *xr, cmd_errcl_t clcode)
{
	uint64_t niagara_l2_afsr = 0;

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_AFSR,
	    &niagara_l2_afsr) != 0 &&
	    nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_ESR,
	    &niagara_l2_afsr) != 0)
		return (-1);
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_AFAR,
	    &xr->xr_afar) != 0 &&
	    nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_EAR,
	    &xr->xr_afar) != 0)
		return (-1);
	if (nvlist_lookup_uint32(nvl, FM_EREPORT_PAYLOAD_NAME_L2_SYND,
	    &xr->xr_synd) != 0) {
		/* Niagara-2 doesn't provide separate (redundant) l2-synd */
		xr->xr_synd = niagara_l2_afsr & NI2_L2AFSR_SYND;
	}

	if (cmd_afsr_check(hdl, niagara_l2_afsr, clcode,
	    &xr->xr_synd_status) != 0)
		return (-1);

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

int
cmd_afsr_check(fmd_hdl_t *hdl, uint64_t afsr,
    cmd_errcl_t clcode, uint8_t *stat_val)
{
	/*
	 * Set Niagara afar and synd validity.
	 * For a given set of error registers, the payload value is valid iff
	 * no higher priority error status bit is set.  See niagararegs.h
	 * for error status bit values and priority settings.
	 */
	switch (clcode) {
	case CMD_ERRCL_LDAU:
	case CMD_ERRCL_LDSU:
		*stat_val =
		    ((afsr & NI_L2AFSR_P02) == 0) ?
		    AFLT_STAT_VALID: AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDWU:
		*stat_val =
		    ((afsr & NI_L2AFSR_P03) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDRU:
		*stat_val =
		    ((afsr & NI_L2AFSR_P04) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDAC:
	case CMD_ERRCL_LDSC:
		*stat_val =
		    ((afsr & NI_L2AFSR_P08) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDWC:
		*stat_val =
		    ((afsr & NI_L2AFSR_P09) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_LDRC:
		*stat_val =
		    ((afsr & NI_L2AFSR_P10) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	default:
		fmd_hdl_debug(hdl, "Niagara unrecognized l2cache error\n");
		return (-1);
	}
	return (0);
}


int
cmd_afar_valid(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_errcl_t clcode,
    uint64_t *afar)
{
	uint64_t niagara_l2_afsr = 0;
	uint8_t stat_val;

	/*
	 * In Niagara-1, we carried forward the register names afsr and afar
	 * in ereports from sun4u, even though the hardware registers were
	 * named esr and ear respectively.  In Niagara-2 we decided to conform
	 * to the hardware names.
	 */

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_AFSR,
	    &niagara_l2_afsr) != 0 &&
	    nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_ESR,
	    &niagara_l2_afsr) != 0)
		return (-1);

	if (cmd_afsr_check(hdl, niagara_l2_afsr, clcode, &stat_val) != 0)
		return (-1);

	if (stat_val == AFLT_STAT_VALID) {
		if (nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L2_AFAR, afar) == 0 ||
		    nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_NAME_L2_EAR, afar) == 0)
			return (0);
	}
	return (-1);
}

/*
 * sun4v cmd_cpu_get_frustr expects a 'cpufru' element in 'detector' FMRI
 * of ereport (which is stored as 'asru' of cmd_cpu_t).  For early sun4v,
 * this was mistakenly spec'ed as "hc://MB" instead of "hc:///component=MB",
 * so this situation must be remediated when found.
 */

char *
cmd_cpu_getfrustr(fmd_hdl_t *hdl, cmd_cpu_t *cp)
{
	char *frustr;
	nvlist_t *asru = cp->cpu_asru_nvl;

	if (nvlist_lookup_string(asru, FM_FMRI_CPU_CPUFRU, &frustr) == 0) {
		fmd_hdl_debug(hdl, "cmd_cpu_getfrustr: cpufru=%s\n", frustr);
		if (strncmp(frustr, CPU_FRU_FMRI,
		    sizeof (CPU_FRU_FMRI) -1) == 0)
			return (fmd_hdl_strdup(hdl, frustr, FMD_SLEEP));
		else {
			char *s1, *s2;
			size_t frustrlen;

			s2 = strstr(frustr, "MB");
			if ((s2 == NULL) || strcmp(s2, EMPTY_STR) == 0) {
				fmd_hdl_debug(hdl,
				    "cmd_cpu_getfrustr: no cpufru");
				return (NULL);
			}
			frustrlen = strlen(s2) + sizeof (CPU_FRU_FMRI);
			s1 = fmd_hdl_alloc(hdl, frustrlen, FMD_SLEEP);
			s1 = strcpy(s1, CPU_FRU_FMRI);
			s1 = strcat(s1, s2);
			fmd_hdl_debug(hdl, "cmd_cpu_getfrustr frustr=%s\n", s1);
			return (s1);
		}
	}
	(void) cmd_set_errno(ENOENT);
	return (NULL);
}

char *
cmd_cpu_getpartstr(fmd_hdl_t *hdl, cmd_cpu_t *cp) {
	char *partstr;
	nvlist_t *asru = cp->cpu_asru_nvl;

	if (nvlist_lookup_string(asru, FM_FMRI_HC_PART, &partstr) == 0)
		return (fmd_hdl_strdup(hdl, partstr, FMD_SLEEP));
	else
		return (NULL);
}

char *
cmd_cpu_getserialstr(fmd_hdl_t *hdl, cmd_cpu_t *cp) {
	char *serialstr;
	nvlist_t *asru = cp->cpu_asru_nvl;

	if (nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &serialstr) == 0)
		return (fmd_hdl_strdup(hdl, serialstr, FMD_SLEEP));
	else
		return (NULL);
}

nvlist_t *
cmd_cpu_mkfru(fmd_hdl_t *hdl, char *frustr, char *serialstr, char *partstr)
{

	nvlist_t *fru;
	if (strncmp(frustr, CPU_FRU_FMRI, sizeof (CPU_FRU_FMRI) - 1) != 0)
		return (NULL);
	fru = cmd_mkboard_fru(hdl, frustr, serialstr, partstr);
	return (fru);
}
