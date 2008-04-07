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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing per-CPU state.
 */

#include <cmd_cpu.h>
#include <cmd_ecache.h>
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
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/cheetahregs.h>

/*
 * The unused argument 'clcode' is needed for our sun4v sibling.
 */

/*ARGSUSED*/
int
cmd_xr_fill(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_xr_t *xr, cmd_errcl_t clcode)
{
	if (nvlist_lookup_uint16(nvl, FM_EREPORT_PAYLOAD_NAME_SYND,
	    &xr->xr_synd) != 0)
		return (-1);
	if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_SYND_STATUS,
	    &xr->xr_synd_status) != 0)
		return (-1);
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_AFAR,
	    &xr->xr_afar) != 0)
		return (-1);
	if (nvlist_lookup_uint8(nvl, FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS,
	    &xr->xr_afar_status) != 0)
		return (-1);
	return (0);
}

/*
 * Search for the entry that matches the ena and the AFAR
 * if we have a valid AFAR, otherwise just match the ENA
 */
cmd_xxcu_trw_t *
cmd_trw_lookup(uint64_t ena, uint8_t afar_status, uint64_t afar)
{
	int i;

	if (afar_status == AFLT_STAT_VALID) {
		for (i = 0; i < cmd.cmd_xxcu_ntrw; i++) {
			if (cmd.cmd_xxcu_trw[i].trw_ena == ena &&
			    cmd.cmd_xxcu_trw[i].trw_afar == afar)
				return (&cmd.cmd_xxcu_trw[i]);
		}
	} else  {
		for (i = 0; i < cmd.cmd_xxcu_ntrw; i++) {
		if (cmd.cmd_xxcu_trw[i].trw_ena == ena)
			return (&cmd.cmd_xxcu_trw[i]);
		}
	}
	return (NULL);
}

/*ARGSUSED*/
cmd_errcl_t
cmd_train_match(cmd_errcl_t trw_mask, cmd_errcl_t resolved_err)
{
	return (cmd_xxcu_train_match(trw_mask));
}

/*ARGSUSED*/
int
cmd_afar_status_check(uint8_t afar_status, cmd_errcl_t clcode)
{
	if (afar_status == AFLT_STAT_VALID)
		return (0);
	return (-1);
}

const errdata_t l3errdata =
	{ &cmd.cmd_l3data_serd, "l3cachedata", CMD_PTR_CPU_L3DATA  };
const errdata_t l2errdata =
	{ &cmd.cmd_l2data_serd, "l2cachedata", CMD_PTR_CPU_L2DATA };

void
cmd_fill_errdata(cmd_errcl_t clcode, cmd_cpu_t *cpu, cmd_case_t **cc,
    const errdata_t **ed)
{
	if (CMD_ERRCL_ISL2XXCU(clcode)) {
		*ed = &l2errdata;
		*cc = &cpu->cpu_l2data;
	} else {
		*ed = &l3errdata;
		*cc = &cpu->cpu_l3data;
	}
}

/*ARGSUSED*/
int
cmd_cpu_synd_check(uint16_t synd, cmd_errcl_t clcode)
{
	if (synd == CH_POISON_SYND_FROM_XXU_WRITE ||
	    synd == CH_POISON_SYND_FROM_XXU_WRMERGE ||
	    synd == CH_POISON_SYND_FROM_DSTAT23)
		return (-1);
	else
		return (0);
}
/*ARGSUSED*/
int
cmd_afar_valid(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_errcl_t clcode,
    uint64_t *afar)
{
	uint8_t afar_status;

	if (nvlist_lookup_uint8(nvl,
	    FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS, &afar_status) == 0) {
		if (afar_status == AFLT_STAT_VALID) {
			(void) nvlist_lookup_uint64(nvl,
			    FM_EREPORT_PAYLOAD_NAME_AFAR, afar);
			return (0);
		} else
			return (-1);
	} else
		return (-1);
}

char *
cmd_cpu_getfrustr_by_id(fmd_hdl_t *hdl, uint32_t cpuid)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL)
		return (NULL); /* errno is set for us */

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL ||
	    kstat_read(kc, ksp, NULL) == -1) {
		int oserr = errno;
		(void) kstat_close(kc);
		(void) cmd_set_errno(oserr);
		return (NULL);
	}

	for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
		if (strcmp(kn->name, "cpu_fru") == 0) {
			char *str = fmd_hdl_strdup(hdl,
			    KSTAT_NAMED_STR_PTR(kn), FMD_SLEEP);
			(void) kstat_close(kc);
			return (str);
		}
	}

	(void) kstat_close(kc);
	(void) cmd_set_errno(ENOENT);
	return (NULL);
}

char *
cmd_cpu_getfrustr(fmd_hdl_t *hdl, cmd_cpu_t *cp)
{
	return (cmd_cpu_getfrustr_by_id(hdl, cp->cpu_cpuid));
}

/*ARGSUSED*/
char *
cmd_cpu_getpartstr(fmd_hdl_t *hdl, cmd_cpu_t *cp) {
	return (NULL);
}

/*ARGSUSED*/
char *
cmd_cpu_getserialstr(fmd_hdl_t *hdl, cmd_cpu_t *cp) {
	return (NULL);
}

/*ARGSUSED*/
nvlist_t *
cmd_cpu_mkfru(fmd_hdl_t *hdl, char *frustr, char *serialstr, char *partstr)
{
	char *comp;
	nvlist_t *fru, *hcelem;

	if (strncmp(frustr, CPU_FRU_FMRI, sizeof (CPU_FRU_FMRI) - 1) != 0)
		return (NULL);

	comp = frustr + sizeof (CPU_FRU_FMRI) - 1;

	if (nvlist_alloc(&hcelem, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	if (nvlist_add_string(hcelem, FM_FMRI_HC_NAME,
	    FM_FMRI_LEGACY_HC) != 0 ||
	    nvlist_add_string(hcelem, FM_FMRI_HC_ID, comp) != 0) {
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_add_uint8(fru, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0 ||
	    (partstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_PART, partstr) != 0) ||
	    (serialstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_SERIAL_ID,
	    serialstr) != 0) ||
	    nvlist_add_string(fru, FM_FMRI_HC_ROOT, "") != 0 ||
	    nvlist_add_uint32(fru, FM_FMRI_HC_LIST_SZ, 1) != 0 ||
	    nvlist_add_nvlist_array(fru, FM_FMRI_HC_LIST, &hcelem, 1) != 0) {
		nvlist_free(hcelem);
		nvlist_free(fru);
		return (NULL);
	}

	nvlist_free(hcelem);
	return (fru);
}
