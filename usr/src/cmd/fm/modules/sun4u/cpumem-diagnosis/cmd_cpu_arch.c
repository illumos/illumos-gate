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

int
cmd_cpu_synd_check(uint16_t synd)
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
