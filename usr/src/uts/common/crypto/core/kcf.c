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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

/*
 * Door to make upcalls to kcfd. kcfd will send us this
 * handle when it is coming up.
 */
kmutex_t kcf_dh_lock;
door_handle_t kcf_dh = NULL;

/* Setup FIPS 140 support variables */
uint32_t global_fips140_mode = FIPS140_MODE_UNSET;
kmutex_t fips140_mode_lock;
kcondvar_t cv_fips140;

/*
 * Kernel FIPS140 boundary module list
 * NOTE: "swrand" must be the last entry.  FIPS 140 shutdown functions stop
 *       before getting to swrand as it is used for non-FIPS 140
 *       operations to.  The FIPS 140 random API separately controls access.
 */
#define	FIPS140_MODULES_MAX 7
static char *fips140_module_list[FIPS140_MODULES_MAX] = {
	"aes", "des", "ecc", "sha1", "sha2", "rsa", "swrand"
};

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
	mutex_init(&fips140_mode_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv_fips140, NULL, CV_DEFAULT, NULL);

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


/* Returns the value of global_fips140_mode */
int
kcf_get_fips140_mode(void)
{
	return (global_fips140_mode);
}

/*
 * If FIPS 140 has failed its tests.  The providers must be disabled from the
 * framework.
 */
void
kcf_fips140_shutdown()
{
	kcf_provider_desc_t *pd;
	int i;

	cmn_err(CE_WARN,
	    "Shutting down FIPS 140 boundary as verification failed.");

	/* Disable FIPS 140 modules, but leave swrand alone */
	for (i = 0; i < (FIPS140_MODULES_MAX - 1); i++) {
		/*
		 * Remove the predefined entries from the soft_config_list
		 * so the framework does not report the providers.
		 */
		remove_soft_config(fips140_module_list[i]);

		pd = kcf_prov_tab_lookup_by_name(fips140_module_list[i]);
		if (pd == NULL)
			continue;

		/* Allow the unneeded providers to be unloaded */
		pd->pd_mctlp->mod_loadflags &= ~(MOD_NOAUTOUNLOAD);

		/* Invalidate the FIPS 140 providers */
		mutex_enter(&pd->pd_lock);
		pd->pd_state = KCF_PROV_VERIFICATION_FAILED;
		mutex_exit(&pd->pd_lock);
		KCF_PROV_REFRELE(pd);
		undo_register_provider(pd, B_FALSE);

	}
}

/*
 * Activates the kernel providers
 *
 * If we are getting ready to enable FIPS 140 mode, then all providers should
 * be loaded and ready.
 *
 * If FIPS 140 is disabled, then we can skip any errors because some crypto
 * modules may not have been loaded.
 */
void
kcf_activate()
{
	kcf_provider_desc_t *pd;
	int i;

	for (i = 0; i < (FIPS140_MODULES_MAX - 1); i++) {
		pd = kcf_prov_tab_lookup_by_name(fips140_module_list[i]);
		if (pd == NULL) {
			if (global_fips140_mode == FIPS140_MODE_DISABLED)
				continue;

			/* There should never be a NULL value in FIPS 140 */
			cmn_err(CE_WARN, "FIPS 140 activation: %s not in "
			    "kernel provider table", fips140_module_list[i]);
			kcf_fips140_shutdown();
			break;
		}

		/*
		 * Change the provider state so the verification functions
		 * can signature verify, if necessary, and ready it.
		 */
		if (pd->pd_state == KCF_PROV_UNVERIFIED_FIPS140) {
			mutex_enter(&pd->pd_lock);
			pd->pd_state = KCF_PROV_UNVERIFIED;
			mutex_exit(&pd->pd_lock);
		}

		KCF_PROV_REFRELE(pd);
	}

	/* If we in the process of validating FIPS 140, enable it */
	if (global_fips140_mode != FIPS140_MODE_DISABLED) {
		mutex_enter(&fips140_mode_lock);
		global_fips140_mode = FIPS140_MODE_ENABLED;
		cv_signal(&cv_fips140);
		mutex_exit(&fips140_mode_lock);
	}

	verify_unverified_providers();
}


/*
 * Perform a door call to kcfd to have it check the integrity of the
 * kernel boundary.  Failure of the boundary will cause a FIPS 140
 * configuration to fail
 */
int
kcf_fips140_integrity_check()
{
	door_arg_t darg;
	door_handle_t ldh;
	kcf_door_arg_t *kda = { 0 }, *rkda;
	int ret = 0;

	KCF_FRMWRK_DEBUG(1, ("Starting IC check"));

	mutex_enter(&kcf_dh_lock);
	if (kcf_dh == NULL) {
		mutex_exit(&kcf_dh_lock);
		cmn_err(CE_WARN, "FIPS 140 Integrity Check failed, Door not "
		    "available\n");
		return (1);
	}

	ldh = kcf_dh;
	door_ki_hold(ldh);
	mutex_exit(&kcf_dh_lock);

	kda = kmem_alloc(sizeof (kcf_door_arg_t), KM_SLEEP);
	kda->da_version = KCFD_FIPS140_INTCHECK;
	kda->da_iskernel = B_TRUE;

	darg.data_ptr = (char *)kda;
	darg.data_size = sizeof (kcf_door_arg_t);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)kda;
	darg.rsize = sizeof (kcf_door_arg_t);

	ret = door_ki_upcall_limited(ldh, &darg, NULL, SIZE_MAX, 0);
	if (ret != 0) {
		ret = 1;
		goto exit;
	}

	KCF_FRMWRK_DEBUG(1, ("Integrity Check door returned = %d\n", ret));

	rkda = (kcf_door_arg_t *)darg.rbuf;
	if (rkda->da_u.result.status != ELFSIGN_SUCCESS) {
		ret = 1;
		KCF_FRMWRK_DEBUG(1, ("Integrity Check failed = %d\n",
		    rkda->da_u.result.status));
		goto exit;
	}

	KCF_FRMWRK_DEBUG(1, ("Integrity Check succeeds.\n"));

exit:
	if (rkda != kda)
		kmem_free(rkda, darg.rsize);

	kmem_free(kda, sizeof (kcf_door_arg_t));
	door_ki_rele(ldh);
	if (ret)
		cmn_err(CE_WARN, "FIPS 140 Integrity Check failed.\n");
	return (ret);
}

/*
 * If FIPS 140 is configured to be enabled, before it can be turned on, the
 * providers must run their Power On Self Test (POST) and we must wait to sure
 * userland has performed its validation tests.
 */
void
kcf_fips140_validate()
{
	kcf_provider_desc_t *pd;
	kthread_t *post_thr;
	int post_rv[FIPS140_MODULES_MAX];
	kt_did_t post_t_did[FIPS140_MODULES_MAX];
	int ret = 0;
	int i;

	/*
	 * Run POST tests for FIPS 140 modules, if they aren't loaded, load them
	 */
	for (i = 0; i < FIPS140_MODULES_MAX; i++) {
		pd = kcf_prov_tab_lookup_by_name(fips140_module_list[i]);
		if (pd == NULL) {
			/* If the module isn't loaded, load it */
			ret = modload("crypto", fips140_module_list[i]);
			if (ret == -1) {
				cmn_err(CE_WARN, "FIPS 140 validation failed: "
				    "error modloading module %s.",
				    fips140_module_list[i]);
				goto error;
			}

			/* Try again to get provider desc */
			pd = kcf_prov_tab_lookup_by_name(
			    fips140_module_list[i]);
			if (pd == NULL) {
				cmn_err(CE_WARN, "FIPS 140 validation failed: "
				    "Could not find module %s.",
				    fips140_module_list[i]);
				goto error;
			}
		}

		/* Make sure there are FIPS 140 entry points */
		if (KCF_PROV_FIPS140_OPS(pd) == NULL) {
			cmn_err(CE_WARN, "FIPS 140 validation failed: "
			    "No POST function entry point in %s.",
			    fips140_module_list[i]);
			goto error;
		}

		/* Make sure the module is not unloaded */
		pd->pd_mctlp->mod_loadflags |= MOD_NOAUTOUNLOAD;

		/*
		 * With the FIPS 140 POST function provided by the module in
		 * SPI v4, start a thread to run the function.
		 */
		post_rv[i] = CRYPTO_OPERATION_NOT_INITIALIZED;
		post_thr = thread_create(NULL, 0,
		    (*(KCF_PROV_FIPS140_OPS(pd)->fips140_post)), &post_rv[i],
		    0, &p0, TS_RUN, MAXCLSYSPRI);
		post_thr->t_did = post_t_did[i];
		KCF_FRMWRK_DEBUG(1, ("kcf_fips140_validate: started POST "
		    "for %s\n", fips140_module_list[i]));
		KCF_PROV_REFRELE(pd);
	}

	/* Do integrity check of kernel boundary */
	ret = kcf_fips140_integrity_check();
	if (ret == 1)
		goto error;

	/* Wait for POST threads to come back and verify results */
	for (i = 0; i < FIPS140_MODULES_MAX; i++) {
		if (post_t_did[i] != NULL)
			thread_join(post_t_did[i]);

		if (post_rv[i] != 0) {
			cmn_err(CE_WARN, "FIPS 140 POST failed for %s. "
			    "Error = %d", fips140_module_list[i], post_rv[i]);
			goto error;
		}
	}

	kcf_activate();
	return;

error:
	mutex_enter(&fips140_mode_lock);
	global_fips140_mode = FIPS140_MODE_SHUTDOWN;
	kcf_fips140_shutdown();
	cv_signal(&cv_fips140);
	mutex_exit(&fips140_mode_lock);

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

/* Check if this provider requires to be verified. */
int
verifiable_provider(crypto_ops_t *prov_ops)
{

	if (prov_ops->co_cipher_ops == NULL && prov_ops->co_dual_ops == NULL &&
	    prov_ops->co_dual_cipher_mac_ops == NULL &&
	    prov_ops->co_key_ops == NULL && prov_ops->co_sign_ops == NULL &&
	    prov_ops->co_verify_ops == NULL)
		return (0);

	return (1);
}

/*
 * With a given provider being registered, this looks through the FIPS 140
 * modules list and returns a 1 if it's part of the FIPS 140 boundary and
 * the framework registration must be delayed until we know the FIPS 140 mode
 * status.  A zero mean the provider does not need to wait for the FIPS 140
 * boundary.
 *
 * If the provider in the boundary only provides random (like swrand), we
 * can let it register as the random API will block operations.
 */
int
kcf_need_fips140_verification(kcf_provider_desc_t *pd)
{
	int i, ret = 0;

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		return (0);

	mutex_enter(&fips140_mode_lock);

	if (global_fips140_mode >= FIPS140_MODE_ENABLED)
		goto exit;

	for (i = 0; i < FIPS140_MODULES_MAX; i++) {
		if (strcmp(fips140_module_list[i], pd->pd_name) != 0)
			continue;

		/* If this module is only random, we can let it register */
		if (KCF_PROV_RANDOM_OPS(pd) &&
		    !verifiable_provider(pd->pd_ops_vector))
			break;

		if (global_fips140_mode == FIPS140_MODE_SHUTDOWN) {
			ret = -1;
			break;
		}

		ret = 1;
		break;
	}

exit:
	mutex_exit(&fips140_mode_lock);
	return (ret);
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

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		return (0);

	if (mctlp == NULL || mctlp->mod_mp == NULL)
		return (-1);

	mp = (struct module *)mctlp->mod_mp;

	/*
	 * Check if we need to verify this provider signature and if so,
	 * make sure it has a signature section.
	 */
	if (verifiable_provider(pd->pd_ops_vector) == 0)
		return (0);

	/* See if this module has its required signature section. */
	if (mp->sigdata == NULL)
		return (-1);

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

	/*
	 * Because of FIPS 140 delays module loading, we may be running through
	 * this code with a non-crypto signed module; therefore, another
	 * check is necessary
	 */
	if (verifiable_provider(pd->pd_ops_vector) == 0) {
		error = 0;
		goto setverify;
	}

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

setverify:
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
