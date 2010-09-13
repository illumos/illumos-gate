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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>
#include <sys/crypto/dca.h>

/*
 * Kernel statistics.
 */
static int dca_ksupdate(kstat_t *, int);

/*
 * Initialize Kstats.
 */
void
dca_ksinit(dca_t *dca)
{
	char	buf[64];
	int	instance;

	if (ddi_getprop(DDI_DEV_T_ANY, dca->dca_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "nostats", 0) != 0) {
		/*
		 * sysadmin has explicity disabled stats to prevent
		 * covert channel.
		 */
		return;
	}

	instance = ddi_get_instance(dca->dca_dip);

	/*
	 * Interrupt kstats.
	 */
	(void) sprintf(buf, "%sc%d", DRIVER, instance);
	if ((dca->dca_intrstats = kstat_create(DRIVER, instance, buf,
	    "controller", KSTAT_TYPE_INTR, 1, 0)) == NULL) {
		dca_error(dca, "unable to create interrupt kstat");
	} else {
		kstat_install(dca->dca_intrstats);
	}

	/*
	 * Named kstats.
	 */
	if ((dca->dca_ksp = kstat_create(DRIVER, instance, NULL, "misc",
	    KSTAT_TYPE_NAMED, sizeof (dca_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		dca_error(dca, "unable to create kstats");
	} else {
		dca_stat_t *dkp = (dca_stat_t *)dca->dca_ksp->ks_data;
		kstat_named_init(&dkp->ds_status, "status", KSTAT_DATA_CHAR);
		kstat_named_init(&dkp->ds_mcr[0].ds_submit, "mcr1submit",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[0].ds_flowctl, "mcr1flowctl",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[0].ds_lowater, "mcr1lowater",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[0].ds_hiwater, "mcr1hiwater",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[0].ds_maxreqs, "mcr1maxreqs",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[1].ds_submit, "mcr2submit",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[1].ds_flowctl, "mcr2flowctl",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[1].ds_lowater, "mcr2lowater",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[1].ds_hiwater, "mcr2hiwater",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_mcr[1].ds_maxreqs, "mcr2maxreqs",
		    KSTAT_DATA_ULONGLONG);
#ifdef	DS_RC4JOBS
		/* rc4 */
		kstat_named_init(&dkp->ds_algs[DS_RC4JOBS], "rc4jobs",
		    KSTAT_DATA_ULONGLONG);
#endif
#ifdef	DS_RC4BYTES
		kstat_named_init(&dkp->ds_algs[DS_RC4BYTES], "rc4bytes",
		    KSTAT_DATA_ULONGLONG);
#endif
		/* 3des */
		kstat_named_init(&dkp->ds_algs[DS_3DESJOBS], "3desjobs",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_3DESBYTES], "3desbytes",
		    KSTAT_DATA_ULONGLONG);
		/* rsa */
		kstat_named_init(&dkp->ds_algs[DS_RSAPUBLIC], "rsapublic",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_RSAPRIVATE], "rsaprivate",
		    KSTAT_DATA_ULONGLONG);
		/* dsa */
		kstat_named_init(&dkp->ds_algs[DS_DSASIGN], "dsasign",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_DSAVERIFY], "dsaverify",
		    KSTAT_DATA_ULONGLONG);
#ifdef	DS_DHPUBLIC
		/* diffie-hellman */
		kstat_named_init(&dkp->ds_algs[DS_DHPUBLIC], "dhpublic",
		    KSTAT_DATA_ULONGLONG);
#endif
#ifdef	DS_DHSECRET
		kstat_named_init(&dkp->ds_algs[DS_DHSECRET], "dhsecret",
		    KSTAT_DATA_ULONGLONG);
#endif
		/* random number jobs */
		kstat_named_init(&dkp->ds_algs[DS_RNGJOBS], "rngjobs",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_RNGBYTES], "rngbytes",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_RNGSHA1JOBS], "rngsha1jobs",
		    KSTAT_DATA_ULONGLONG);
		kstat_named_init(&dkp->ds_algs[DS_RNGSHA1BYTES],
		    "rngsha1bytes", KSTAT_DATA_ULONGLONG);
		dca->dca_ksp->ks_update = dca_ksupdate;
		dca->dca_ksp->ks_private = dca;
		kstat_install(dca->dca_ksp);
	}
}

/*
 * Update Kstats.
 */
int
dca_ksupdate(kstat_t *ksp, int rw)
{
	dca_t		*dca;
	dca_stat_t	*dkp;
	int		i;

	dca = (dca_t *)ksp->ks_private;
	dkp = (dca_stat_t *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		for (i = 0; i < DS_MAX; i++) {
			dca->dca_stats[i] = dkp->ds_algs[i].value.ull;
		}
		for (i = MCR1; i <= MCR2; i++) {
			WORKLIST(dca, i)->dwl_submit =
			    dkp->ds_mcr[i - 1].ds_submit.value.ull;
			WORKLIST(dca, i)->dwl_flowctl =
			    dkp->ds_mcr[i - 1].ds_flowctl.value.ull;
			/* hiwater, lowater, and maxreqs are read only */
		}
	} else {
		/* handy status value */
		if (dca->dca_flags & DCA_FAILED) {
			/* device has failed */
			(void) strcpy(dkp->ds_status.value.c, "fail");
		} else if ((WORKLIST(dca, MCR1)->dwl_drain) ||
		    (WORKLIST(dca, MCR2)->dwl_drain)) {
			/* device is draining for DR */
			(void) strcpy(dkp->ds_status.value.c, "drain");
		} else {
			/* everything looks good */
			(void) strcpy(dkp->ds_status.value.c, "online");
		}

		for (i = 0; i < DS_MAX; i++) {
			dkp->ds_algs[i].value.ull = dca->dca_stats[i];
		}
		for (i = MCR1; i <= MCR2; i++) {
			dkp->ds_mcr[i - 1].ds_submit.value.ull =
			    WORKLIST(dca, i)->dwl_submit;
			dkp->ds_mcr[i - 1].ds_flowctl.value.ull =
			    WORKLIST(dca, i)->dwl_flowctl;
			dkp->ds_mcr[i - 1].ds_lowater.value.ull =
			    WORKLIST(dca, i)->dwl_lowater;
			dkp->ds_mcr[i - 1].ds_hiwater.value.ull =
			    WORKLIST(dca, i)->dwl_hiwater;
			dkp->ds_mcr[i - 1].ds_maxreqs.value.ull =
			    WORKLIST(dca, i)->dwl_reqspermcr;
		}
	}
	return (0);
}
