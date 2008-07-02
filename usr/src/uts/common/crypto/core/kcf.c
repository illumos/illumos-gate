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
	&mod_miscops, "Kernel Crypto Framework"
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
 * Check if signature verification is needed for a provider.
 *
 * Returns 0, if no verification is needed. Returns 1, if
 * verification is needed. Returns -1, if there is an
 * error.
 */
int
kcf_need_signature_verification(kcf_provider_desc_t *pd)
{
	struct module *mp;
	struct modctl *mctlp = pd->pd_mctlp;
	crypto_ops_t *prov_ops = pd->pd_ops_vector;

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		return (0);

	if (mctlp == NULL || mctlp->mod_mp == NULL)
		return (-1);

	mp = (struct module *)mctlp->mod_mp;

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
		return (-1);
	}

	mutex_enter(&pd->pd_lock);
	pd->pd_state = KCF_PROV_UNVERIFIED;
	mutex_exit(&pd->pd_lock);

	return (1);
}

/*
 * Do the signature verification on the given module. This function can
 * be called from user context or kernel context.
 *
 * We call kcfd with the full pathname of the module to be
 * verified. kcfd will return success/restricted/fail, signature length
 * and the actual signature in the ELF section of the module. If kcfd
 * returns success or restricted, we compare the signature and the length
 * with the values that krtld stored in the module structure. We log an
 * error message in case of a failure.
 *
 * The provider state is changed to KCF_PROV_READY on success.
 */
void
kcf_verify_signature(void *arg)
{
	int rv;
	int error = CRYPTO_MODVERIFICATION_FAILED;
	door_arg_t darg;
	door_handle_t ldh;
	kcf_door_arg_t *kda;
	char *filename;
	kcf_provider_desc_t *pd = arg;
	struct module *mp;
	boolean_t do_notify = B_FALSE;
	boolean_t modhold_done = B_FALSE;
	struct modctl *mctlp = pd->pd_mctlp;

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);
	ASSERT(mctlp != NULL);

	for (;;) {
		mutex_enter(&pd->pd_lock);
		/* No need to do verification */
		if (pd->pd_state != KCF_PROV_UNVERIFIED) {
			mutex_exit(&pd->pd_lock);
			goto out;
		}
		mutex_exit(&pd->pd_lock);

		mutex_enter(&mod_lock);
		if (mctlp->mod_mp == NULL) {
			mutex_exit(&mod_lock);
			goto out;
		}

		/*
		 * This check is needed since a software provider can call
		 * us directly from the _init->crypto_register_provider path.
		 */
		if (pd->pd_prov_type == CRYPTO_SW_PROVIDER &&
		    mctlp->mod_inprogress_thread == curthread) {
			mutex_exit(&mod_lock);
			modhold_done = B_FALSE;
			break;
		}

		/*
		 * We could be in a race with the register thread or
		 * the unregister thread. So, retry if register or
		 * unregister is in progress. Note that we can't do
		 * mod_hold_by_modctl without this check since that
		 * could result in a deadlock with the other threads.
		 */
		if (mctlp->mod_busy) {
			mutex_exit(&mod_lock);
			/* delay for 10ms and try again */
			delay(drv_usectohz(10000));
			continue;
		}

		(void) mod_hold_by_modctl(mctlp,
		    MOD_WAIT_FOREVER | MOD_LOCK_HELD);
		mutex_exit(&mod_lock);
		modhold_done = B_TRUE;
		break;
	}

	/*
	 * Check if the door is set up yet. This will be set when kcfd
	 * comes up. If not, we return and leave the provider state unchanged
	 * at KCF_PROV_UNVERIFIED. This will trigger the verification of
	 * the module later when kcfd is up. This is safe as we NEVER use
	 * a provider that has not been verified yet.
	 */
	mutex_enter(&kcf_dh_lock);
	if (kcf_dh == NULL) {
		mutex_exit(&kcf_dh_lock);
		goto out;
	}

	ldh = kcf_dh;
	door_ki_hold(ldh);
	mutex_exit(&kcf_dh_lock);

	mp = (struct module *)mctlp->mod_mp;
	filename = mp->filename;
	KCF_FRMWRK_DEBUG(2, ("Verifying module: %s\n", filename));

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
	rv = door_ki_upcall_limited(ldh, &darg, NULL, SIZE_MAX, 0);

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
			    filename);
		} else {
			error = 0;
		}

		if (rkda->da_u.result.status == ELFSIGN_RESTRICTED) {
			pd->pd_flags |= KCF_PROV_RESTRICTED;
			KCF_FRMWRK_DEBUG(2, ("provider is restricted\n"));
		}

		if (rkda != kda)
			kmem_free(rkda, darg.rsize);

	} else {
		cmn_err(CE_WARN, "Module verification door upcall failed "
		    "for %s. errno = %d", filename, rv);
	}

	kmem_free(kda, sizeof (kcf_door_arg_t) + mp->sigsize);
	door_ki_rele(ldh);

	mutex_enter(&pd->pd_lock);
	/* change state only if the original state is unchanged */
	if (pd->pd_state == KCF_PROV_UNVERIFIED) {
		if (error == 0) {
			pd->pd_state = KCF_PROV_READY;
			do_notify = B_TRUE;
		} else {
			pd->pd_state = KCF_PROV_VERIFICATION_FAILED;
		}
	}
	mutex_exit(&pd->pd_lock);

	if (do_notify) {
		/* Dispatch events for this new provider */
		kcf_do_notify(pd, B_TRUE);
	}

out:
	if (modhold_done)
		mod_release_mod(mctlp);
	KCF_PROV_IREFRELE(pd);
	KCF_PROV_REFRELE(pd);
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
