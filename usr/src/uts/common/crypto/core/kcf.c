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

#ifdef DEBUG
int kcf_frmwrk_debug = 0;

#define	KCF_FRMWRK_DEBUG(l, x)	if (kcf_frmwrk_debug >= l) printf x
#else	/* DEBUG */
#define	KCF_FRMWRK_DEBUG(l, x)
#endif	/* DEBUG */

/*
 * Door to make upcalls to kcfd. kcfd will send us this
 * handle when it is coming up.
 */
kmutex_t kcf_dh_lock;
door_handle_t kcf_dh = NULL;


static struct modlmisc modlmisc = {
	&mod_miscops, "Kernel Crypto Framework %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static int rngtimer_started;


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
	rngtimer_started = 0;
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

		if ((major =
		    ddi_driver_major(pinfo->pi_provider_dev.pd_hw)) != -1) {
			drvmod = ddi_major_to_name(major);
			mctlp = mod_find_by_filename("drv", drvmod);
		} else
			return (NULL);
	}

	return (mctlp);
}

/*
 * Verify the signature of the module of the passed in provider.
 *
 * Returns 0 if the signature is verified successfully. Returns -1,
 * if the signature can not be verified now since kcfd is not up.
 * In this case, we delay the verification till kcfd is up. Returns
 * CRYPTO_MODVERIFICATION_FAILED if the verification has failed.
 *
 * This function can be called from process context only.
 *
 * We call kcfd with the full pathname of the module to be
 * verified. kcfd will return success/restricted/fail, signature length
 * and the actual signature in the ELF section of the module. If kcfd
 * returns success or restricted, we compare the signature and the length
 * with the values that krtld stored in the module structure. We log an
 * error message in case of a failure.
 */
int
kcf_verify_signature(kcf_provider_desc_t *pd)
{
	int rv;
	int error = CRYPTO_MODVERIFICATION_FAILED;
	door_arg_t darg;
	kcf_door_arg_t *kda;
	char *filename;
	struct module *mp;
	struct modctl *mctlp = pd->pd_mctlp;
	crypto_ops_t *prov_ops = pd->pd_ops_vector;

	/*
	 * mctlp->mod_filename does not give us the full pathname.
	 * So, we have to access the module structure to get it.
	 */
	if (mctlp == NULL || mctlp->mod_mp == NULL)
		return (error);

	mp = (struct module *)mctlp->mod_mp;
	filename = mp->filename;

	KCF_FRMWRK_DEBUG(2, ("Verifying module: %s\n", filename));

	/*
	 * Check if this provider needs to be verified. We always verify
	 * the module if it carries a signature. Any operation set which has
	 * a encryption/decryption component is a candidate for verification.
	 */
	if (prov_ops->co_cipher_ops == NULL && prov_ops->co_dual_ops == NULL &&
	    prov_ops->co_dual_cipher_mac_ops == NULL &&
	    prov_ops->co_key_ops == NULL && prov_ops->co_sign_ops == NULL &&
	    prov_ops->co_verify_ops == NULL && mp->sigdata == NULL) {
		return (0);
	}

	/*
	 * See if this module has a proper signature section.
	 */
	if (mp->sigdata == NULL) {
		return (error);
	}

	/*
	 * Check if the door is set up yet. This will be set when kcfd
	 * comes up. If not, we return -1 to indicate unverified. This
	 * will trigger the verification of the module later when kcfd
	 * is up. This is safe as we NEVER use a provider that has not
	 * been verified yet (assuming the provider needs to be verified).
	 */
	mutex_enter(&kcf_dh_lock);
	if (kcf_dh == NULL) {
		mutex_exit(&kcf_dh_lock);
		return (-1);
	}
	mutex_exit(&kcf_dh_lock);

	kda = kmem_alloc(sizeof (kcf_door_arg_t) + mp->sigsize, KM_SLEEP);
	kda->da_version = KCF_KCFD_VERSION1;
	kda->da_iskernel = B_TRUE;
	bcopy(filename, kda->da_u.filename, strlen(filename) + 1);

	darg.data_ptr = (char *)kda;
	darg.data_size = sizeof (kcf_door_arg_t) + mp->sigsize;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)kda;
	darg.rsize = sizeof (kcf_door_arg_t);

	/*
	 * Make door upcall. door_ki_upcall() checks for validity of the handle.
	 */
	rv = door_ki_upcall(kcf_dh, &darg);

	if (rv == 0) {
		kcf_door_arg_t *rkda =  (kcf_door_arg_t *)darg.rbuf;

		KCF_FRMWRK_DEBUG(2,
		    ("passed: %d\n", rkda->da_u.result.status));
		KCF_FRMWRK_DEBUG(2,
		    ("signature length: %d\n", rkda->da_u.result.siglen));
		KCF_FRMWRK_DEBUG(2,
		    ("signature: %p\n", (void*)rkda->da_u.result.signature));


		/* Check kcfd result and compare against module struct fields */
		if (((rkda->da_u.result.status != ELFSIGN_SUCCESS) &&
			(rkda->da_u.result.status != ELFSIGN_RESTRICTED)) ||
		    !(rkda->da_u.result.siglen == mp->sigsize) ||
		    (bcmp(rkda->da_u.result.signature, mp->sigdata,
			mp->sigsize))) {
			cmn_err(CE_WARN, "Module verification failed for %s.",
			    mp->filename);
		} else {
			error = 0;
		}

		pd->pd_restricted =
		    (rkda->da_u.result.status == ELFSIGN_RESTRICTED);

		if (pd->pd_restricted) {
			KCF_FRMWRK_DEBUG(2,
			    ("provider is restricted\n"));
		}

		if (rkda != kda)
			kmem_free(rkda, darg.rsize);

	} else {
		cmn_err(CE_WARN, "Module verification failed for %s.",
		    mp->filename);
	}

	kmem_free(kda, sizeof (kcf_door_arg_t) + mp->sigsize);
	return (error);
}

/* called from the CRYPTO_LOAD_DOOR ioctl */
int
crypto_load_door(uint_t did)
{
	mutex_enter(&kcf_dh_lock);
	kcf_dh = door_ki_lookup(did);
	mutex_exit(&kcf_dh_lock);

	verify_unverified_providers();

	/* Start the timeout handler to get random numbers */
	if (rngtimer_started == 0) {
		kcf_rnd_schedule_timeout(B_TRUE);
		rngtimer_started = 1;
	}

	return (0);
}
