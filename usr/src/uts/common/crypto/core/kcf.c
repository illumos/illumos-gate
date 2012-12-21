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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Core KCF (Kernel Cryptographic Framework). This file implements
 * the loadable module entry points and module verification routines.
 */

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/rwlock.h>
#include <sys/kmem.h>
#include <sys/door.h>
#include <sys/kobj.h>

#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/crypto/elfsign.h>
#include <sys/crypto/ioctladmin.h>

#ifdef DEBUG
int kcf_frmwrk_debug = 0;

#define	KCF_FRMWRK_DEBUG(l, x)	if (kcf_frmwrk_debug >= l) printf x
#else	/* DEBUG */
#define	KCF_FRMWRK_DEBUG(l, x)
#endif	/* DEBUG */

static struct modlmisc modlmisc = {
	&mod_miscops, "Kernel Crypto Framework"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

extern int sys_shutdown;

int
_init()
{
	/* initialize the mechanisms tables supported out-of-the-box */
	kcf_init_mech_tabs();

	/* initialize the providers tables */
	kcf_prov_tab_init();

	/* initialize the policy table */
	kcf_policy_tab_init();

	/* initialize soft_config_list */
	kcf_soft_config_init();

	/*
	 * Initialize scheduling structures. Note that this does NOT
	 * start any threads since it might not be safe to do so.
	 */
	kcf_sched_init();

	/* initialize the RNG support structures */
	kcf_rnd_init();

	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * We do not allow kcf to unload.
 */
int
_fini(void)
{
	return (EBUSY);
}


/*
 * Return a pointer to the modctl structure of the
 * provider's module.
 */
struct modctl *
kcf_get_modctl(crypto_provider_info_t *pinfo)
{
	struct modctl *mctlp;

	/* Get the modctl struct for this module */
	if (pinfo->pi_provider_type == CRYPTO_SW_PROVIDER)
		mctlp = mod_getctl(pinfo->pi_provider_dev.pd_sw);
	else {
		major_t major;
		char *drvmod;

		if ((major = ddi_driver_major(pinfo->pi_provider_dev.pd_hw))
		    != DDI_MAJOR_T_NONE) {
			drvmod = ddi_major_to_name(major);
			mctlp = mod_find_by_filename("drv", drvmod);
		} else
			return (NULL);
	}

	return (mctlp);
}
