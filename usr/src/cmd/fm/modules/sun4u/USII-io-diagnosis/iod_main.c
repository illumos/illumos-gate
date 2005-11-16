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

#include <stdarg.h>
#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <kstat.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>

#define	IOD_STAT_BUMP(name)		iod.iod_stats->name.fmds_value.ui64++

/*
 * USII-io-diagnosis:
 *
 * This diagnosis engine consumes the Psycho based IO UEs and CEs
 * which are generated due to DMA Reads or Writes.
 *
 * When a UE is received it will generate the appropriate fault
 * (defect.ultraSPARC-II.memory.nodiag). This is because we do not plan
 * to currently add greater diagnosis capabilities for USII systems.
 *
 * When a CE is received we allow the legacy in kernel SERD do it's job
 * and we just bump a counter here. The legacy SERD algorithm will print
 * out a message and retire pages when the SERD threshold is reached.
 *
 */
static void iod_recv(fmd_hdl_t *, fmd_event_t *, nvlist_t *, const char *);

typedef struct iod_stat {
	fmd_stat_t ue;	/* # of UEs received */
	fmd_stat_t ce;	/* # of CEs received */
} iod_stat_t;

typedef struct iod {
	iod_stat_t *iod_stats;	/* Module statistics */
} iod_t;

static const fmd_hdl_ops_t fmd_ops = {
	iod_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL		/* fmdo_gc */
};

static const fmd_hdl_info_t fmd_info = {
	"UltraSPARC-II I/O Diagnosis", IOD_VERSION, &fmd_ops, NULL
};

static const iod_stat_t iod_stat = {
	{ "ue", FMD_TYPE_UINT64, "number of received IO UEs" },
	{ "ce", FMD_TYPE_UINT64, "number of received IO CEs" }
};

iod_t iod;

/*ARGSUSED*/
static void
iod_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	fmd_case_t *cp;
	nvlist_t *fault;
	char flt[] = "defect.ultraSPARC-II.memory.nodiag";

	if (fmd_nvl_class_match(hdl, nvl, "*ue")) {
		IOD_STAT_BUMP(ue);
		cp = fmd_case_open(hdl, NULL);
		fault = fmd_nvl_create_fault(hdl, flt, 100, NULL, NULL, NULL);
		fmd_case_add_ereport(hdl, cp, ep);
		fmd_case_add_suspect(hdl, cp, fault);
		fmd_case_solve(hdl, cp);
	} else if (fmd_nvl_class_match(hdl, nvl, "*ce")) {
		IOD_STAT_BUMP(ce);
	}
}

int
iod_cpu_check_support(void)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL)
		return (0);

	for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_info") != 0)
			continue;

		if (kstat_read(kc, ksp, NULL) == -1) {
			(void) kstat_close(kc);
			return (0);
		}

		for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
			if (strcmp(kn->name, "implementation") != 0)
				continue;

			if (strncmp(KSTAT_NAMED_STR_PTR(kn), "UltraSPARC-II",
			    sizeof ("UltraSPARC-II") - 1) == 0 &&
			    strncmp(KSTAT_NAMED_STR_PTR(kn), "UltraSPARC-III",
			    sizeof ("UltraSPARC-III") - 1) != 0) {
				(void) kstat_close(kc);
				return (1);
			}
		}
	}

	(void) kstat_close(kc);
	return (0);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* error in configuration file or fmd_info */

	if (!iod_cpu_check_support()) {
		fmd_hdl_debug(hdl, "no supported CPUs found");
		fmd_hdl_unregister(hdl);
		return;
	}

	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.drue");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.s-drue");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.s-dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.drce");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.s-drce");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.psy.ecc.s-dwce");

	bzero(&iod, sizeof (iod_t));

	iod.iod_stats = (iod_stat_t *)fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (iod_stat) / sizeof (fmd_stat_t), (fmd_stat_t *)&iod_stat);
}
