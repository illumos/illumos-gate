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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/n2rng.h>

/*
 * Kernel statistics.
 */
static int n2rng_ksupdate(kstat_t *, int);

/*
 * Initialize Kstats.
 */
void
n2rng_ksinit(n2rng_t *n2rng)
{
	int	instance;

	if (ddi_getprop(DDI_DEV_T_ANY, n2rng->n_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "nostats", 0) != 0) {
		/*
		 * sysadmin has explicity disabled stats to prevent
		 * covert channel.
		 */
		return;
	}

	instance = ddi_get_instance(n2rng->n_dip);


	/*
	 * Named kstats.
	 */
	n2rng->n_ksp = kstat_create(DRIVER, instance, NULL, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (n2rng_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE);
	if (n2rng->n_ksp == NULL) {
		n2rng_error(n2rng, "unable to create kstats");
	} else {
		n2rng_stat_t *dkp = (n2rng_stat_t *)n2rng->n_ksp->ks_data;

		kstat_named_init(&dkp->ns_status, "status", KSTAT_DATA_CHAR);

		kstat_named_init(&dkp->ns_algs[DS_RNGJOBS], "rngjobs",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ns_algs[DS_RNGBYTES], "rngbytes",
		    KSTAT_DATA_ULONGLONG);

		n2rng->n_ksp->ks_update = n2rng_ksupdate;
		n2rng->n_ksp->ks_private = n2rng;

		kstat_install(n2rng->n_ksp);
	}
}

/*
 * Deinitialize Kstats.
 */
void
n2rng_ksdeinit(n2rng_t *n2rng)
{

	if (n2rng->n_ksp != NULL) {
		kstat_delete(n2rng->n_ksp);
		n2rng->n_ksp = NULL;
	}
}

/*
 * Update Kstats.
 */
int
n2rng_ksupdate(kstat_t *ksp, int rw)
{
	n2rng_t		*n2rng;
	n2rng_stat_t	*dkp;
	int		i;

	n2rng = (n2rng_t *)ksp->ks_private;
	dkp = (n2rng_stat_t *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		for (i = 0; i < DS_MAX; i++) {
			n2rng->n_stats[i] = dkp->ns_algs[i].value.ull;
		}
	} else {
		/* handy status value */
		if (n2rng->n_flags & N2RNG_FAILED) {
			/* device has failed */
			(void) strcpy(dkp->ns_status.value.c, "fail");
		} else {
			/* everything looks good */
			(void) strcpy(dkp->ns_status.value.c, "online");
		}

		for (i = 0; i < DS_MAX; i++) {
			dkp->ns_algs[i].value.ull = n2rng->n_stats[i];
		}
	}

	return (0);
}
