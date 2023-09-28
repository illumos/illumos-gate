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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This file is part of the core Kernel Cryptographic Framework.
 * It implements the SPI functions exported to cryptographic
 * providers.
 */

#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/kstat.h>
#include <sys/policy.h>
#include <sys/cpuvar.h>

/*
 * minalloc and maxalloc values to be used for taskq_create().
 */
int crypto_taskq_threads = CRYPTO_TASKQ_THREADS;
int crypto_taskq_minalloc = CYRPTO_TASKQ_MIN;
int crypto_taskq_maxalloc = CRYPTO_TASKQ_MAX;

static void remove_provider(kcf_provider_desc_t *);
static void process_logical_providers(crypto_provider_info_t *,
    kcf_provider_desc_t *);
static int init_prov_mechs(crypto_provider_info_t *, kcf_provider_desc_t *);
static int kcf_prov_kstat_update(kstat_t *, int);
static void delete_kstat(kcf_provider_desc_t *);

static kcf_prov_stats_t kcf_stats_ks_data_template = {
	{ "kcf_ops_total",		KSTAT_DATA_UINT64 },
	{ "kcf_ops_passed",		KSTAT_DATA_UINT64 },
	{ "kcf_ops_failed",		KSTAT_DATA_UINT64 },
	{ "kcf_ops_returned_busy",	KSTAT_DATA_UINT64 }
};

#define	KCF_SPI_COPY_OPS(src, dst, ops) if ((src)->ops != NULL) \
	*((dst)->ops) = *((src)->ops);

extern int sys_shutdown;

/*
 * Copy an ops vector from src to dst. Used during provider registration
 * to copy the ops vector from the provider info structure to the
 * provider descriptor maintained by KCF.
 * Copying the ops vector specified by the provider is needed since the
 * framework does not require the provider info structure to be
 * persistent.
 */
static void
copy_ops_vector_v1(crypto_ops_t *src_ops, crypto_ops_t *dst_ops)
{
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_control_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_digest_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_cipher_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_mac_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_sign_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_verify_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_dual_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_dual_cipher_mac_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_random_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_session_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_object_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_key_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_provider_ops);
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_ctx_ops);
}

static void
copy_ops_vector_v2(crypto_ops_t *src_ops, crypto_ops_t *dst_ops)
{
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_mech_ops);
}

static void
copy_ops_vector_v3(crypto_ops_t *src_ops, crypto_ops_t *dst_ops)
{
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_nostore_key_ops);
}

static void
copy_ops_vector_v4(crypto_ops_t *src_ops, crypto_ops_t *dst_ops)
{
	KCF_SPI_COPY_OPS(src_ops, dst_ops, co_fips140_ops);
}

/*
 * This routine is used to add cryptographic providers to the KEF framework.
 * Providers pass a crypto_provider_info structure to crypto_register_provider()
 * and get back a handle.  The crypto_provider_info structure contains a
 * list of mechanisms supported by the provider and an ops vector containing
 * provider entry points.  Hardware providers call this routine in their attach
 * routines.  Software providers call this routine in their _init() routine.
 */
int
crypto_register_provider(crypto_provider_info_t *info,
    crypto_kcf_provider_handle_t *handle)
{
	struct modctl *mcp;
	char *name;
	char ks_name[KSTAT_STRLEN];
	kcf_provider_desc_t *prov_desc = NULL;
	int ret = CRYPTO_ARGUMENTS_BAD;

	if (info->pi_interface_version > CRYPTO_SPI_VERSION_4) {
		ret = CRYPTO_VERSION_MISMATCH;
		goto errormsg;
	}

	/*
	 * Check provider type, must be software, hardware, or logical.
	 */
	if (info->pi_provider_type != CRYPTO_HW_PROVIDER &&
	    info->pi_provider_type != CRYPTO_SW_PROVIDER &&
	    info->pi_provider_type != CRYPTO_LOGICAL_PROVIDER)
		goto errormsg;

	/*
	 * Allocate and initialize a new provider descriptor. We also
	 * hold it and release it when done.
	 */
	prov_desc = kcf_alloc_provider_desc(info);
	KCF_PROV_REFHOLD(prov_desc);

	prov_desc->pd_prov_type = info->pi_provider_type;

	/* provider-private handle, opaque to KCF */
	prov_desc->pd_prov_handle = info->pi_provider_handle;

	/* copy provider description string */
	if (info->pi_provider_description != NULL) {
		/*
		 * pi_provider_descriptor is a string that can contain
		 * up to CRYPTO_PROVIDER_DESCR_MAX_LEN + 1 characters
		 * INCLUDING the terminating null character. A bcopy()
		 * is necessary here as pd_description should not have
		 * a null character. See comments in kcf_alloc_provider_desc()
		 * for details on pd_description field.
		 */
		bcopy(info->pi_provider_description, prov_desc->pd_description,
		    min(strlen(info->pi_provider_description),
		    CRYPTO_PROVIDER_DESCR_MAX_LEN));
	}

	if (info->pi_provider_type != CRYPTO_LOGICAL_PROVIDER) {
		if (info->pi_ops_vector == NULL) {
			goto bail;
		}
		copy_ops_vector_v1(info->pi_ops_vector,
		    prov_desc->pd_ops_vector);
		if (info->pi_interface_version >= CRYPTO_SPI_VERSION_2) {
			copy_ops_vector_v2(info->pi_ops_vector,
			    prov_desc->pd_ops_vector);
			prov_desc->pd_flags = info->pi_flags;
		}
		if (info->pi_interface_version >= CRYPTO_SPI_VERSION_3) {
			copy_ops_vector_v3(info->pi_ops_vector,
			    prov_desc->pd_ops_vector);
		}
		if (info->pi_interface_version == CRYPTO_SPI_VERSION_4) {
			copy_ops_vector_v4(info->pi_ops_vector,
			    prov_desc->pd_ops_vector);
		}
	}

	/* object_ops and nostore_key_ops are mutually exclusive */
	if (prov_desc->pd_ops_vector->co_object_ops &&
	    prov_desc->pd_ops_vector->co_nostore_key_ops) {
		goto bail;
	}
	/*
	 * For software providers, copy the module name and module ID.
	 * For hardware providers, copy the driver name and instance.
	 */
	switch (info->pi_provider_type) {
	case  CRYPTO_SW_PROVIDER:
		if (info->pi_provider_dev.pd_sw == NULL)
			goto bail;

		if ((mcp = mod_getctl(info->pi_provider_dev.pd_sw)) == NULL)
			goto bail;

		prov_desc->pd_module_id = mcp->mod_id;
		name = mcp->mod_modname;
		break;

	case CRYPTO_HW_PROVIDER:
	case CRYPTO_LOGICAL_PROVIDER:
		if (info->pi_provider_dev.pd_hw == NULL)
			goto bail;

		prov_desc->pd_instance =
		    ddi_get_instance(info->pi_provider_dev.pd_hw);
		name = (char *)ddi_driver_name(info->pi_provider_dev.pd_hw);
		break;
	}
	if (name == NULL)
		goto bail;

	prov_desc->pd_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(prov_desc->pd_name, name);

	if ((prov_desc->pd_mctlp = kcf_get_modctl(info)) == NULL)
		goto bail;

	/* process the mechanisms supported by the provider */
	if ((ret = init_prov_mechs(info, prov_desc)) != CRYPTO_SUCCESS)
		goto bail;

	/*
	 * Add provider to providers tables, also sets the descriptor
	 * pd_prov_id field.
	 */
	if ((ret = kcf_prov_tab_add_provider(prov_desc)) != CRYPTO_SUCCESS) {
		undo_register_provider(prov_desc, B_FALSE);
		goto bail;
	}

	/*
	 * We create a taskq only for a hardware provider. The global
	 * software queue is used for software providers. We handle ordering
	 * of multi-part requests in the taskq routine. So, it is safe to
	 * have multiple threads for the taskq. We pass TASKQ_PREPOPULATE flag
	 * to keep some entries cached to improve performance.
	 */
	if (prov_desc->pd_prov_type == CRYPTO_HW_PROVIDER)
		prov_desc->pd_taskq = taskq_create("kcf_taskq",
		    crypto_taskq_threads, minclsyspri,
		    crypto_taskq_minalloc, crypto_taskq_maxalloc,
		    TASKQ_PREPOPULATE);
	else
		prov_desc->pd_taskq = NULL;

	/* no kernel session to logical providers and no pd_flags  */
	if (prov_desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		/*
		 * Open a session for session-oriented providers. This session
		 * is used for all kernel consumers. This is fine as a provider
		 * is required to support multiple thread access to a session.
		 * We can do this only after the taskq has been created as we
		 * do a kcf_submit_request() to open the session.
		 */
		if (KCF_PROV_SESSION_OPS(prov_desc) != NULL) {
			kcf_req_params_t params;

			KCF_WRAP_SESSION_OPS_PARAMS(&params,
			    KCF_OP_SESSION_OPEN, &prov_desc->pd_sid, 0,
			    CRYPTO_USER, NULL, 0, prov_desc);
			ret = kcf_submit_request(prov_desc, NULL, NULL, &params,
			    B_FALSE);
			if (ret != CRYPTO_SUCCESS)
				goto undo_then_bail;
		}

		/*
		 * Get the value for the maximum input length allowed if
		 * CRYPTO_HASH_NO_UPDATE or CRYPTO_HASH_NO_UPDATE is specified.
		 */
		if (prov_desc->pd_flags &
		    (CRYPTO_HASH_NO_UPDATE | CRYPTO_HMAC_NO_UPDATE)) {
			kcf_req_params_t params;
			crypto_provider_ext_info_t ext_info;

			if (KCF_PROV_PROVMGMT_OPS(prov_desc) == NULL)
				goto undo_then_bail;

			bzero(&ext_info, sizeof (ext_info));
			KCF_WRAP_PROVMGMT_OPS_PARAMS(&params,
			    KCF_OP_MGMT_EXTINFO,
			    0, NULL, 0, NULL, 0, NULL, &ext_info, prov_desc);
			ret = kcf_submit_request(prov_desc, NULL, NULL,
			    &params, B_FALSE);
			if (ret != CRYPTO_SUCCESS)
				goto undo_then_bail;

			if (prov_desc->pd_flags & CRYPTO_HASH_NO_UPDATE) {
				prov_desc->pd_hash_limit =
				    ext_info.ei_hash_max_input_len;
			}
			if (prov_desc->pd_flags & CRYPTO_HMAC_NO_UPDATE) {
				prov_desc->pd_hmac_limit =
				    ext_info.ei_hmac_max_input_len;
			}
		}
	}

	if (prov_desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		/*
		 * Create the kstat for this provider. There is a kstat
		 * installed for each successfully registered provider.
		 * This kstat is deleted, when the provider unregisters.
		 */
		if (prov_desc->pd_prov_type == CRYPTO_SW_PROVIDER) {
			(void) snprintf(ks_name, KSTAT_STRLEN, "%s_%s",
			    prov_desc->pd_name, "provider_stats");
		} else {
			(void) snprintf(ks_name, KSTAT_STRLEN, "%s_%d_%u_%s",
			    prov_desc->pd_name, prov_desc->pd_instance,
			    prov_desc->pd_prov_id, "provider_stats");
		}

		prov_desc->pd_kstat = kstat_create("kcf", 0, ks_name, "crypto",
		    KSTAT_TYPE_NAMED, sizeof (kcf_prov_stats_t) /
		    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);

		if (prov_desc->pd_kstat != NULL) {
			bcopy(&kcf_stats_ks_data_template,
			    &prov_desc->pd_ks_data,
			    sizeof (kcf_stats_ks_data_template));
			prov_desc->pd_kstat->ks_data = &prov_desc->pd_ks_data;
			KCF_PROV_REFHOLD(prov_desc);
			prov_desc->pd_kstat->ks_private = prov_desc;
			prov_desc->pd_kstat->ks_update = kcf_prov_kstat_update;
			kstat_install(prov_desc->pd_kstat);
		}
	}

	if (prov_desc->pd_prov_type == CRYPTO_HW_PROVIDER)
		process_logical_providers(info, prov_desc);

	mutex_enter(&prov_desc->pd_lock);
	prov_desc->pd_state = KCF_PROV_READY;
	mutex_exit(&prov_desc->pd_lock);
	kcf_do_notify(prov_desc, B_TRUE);

	*handle = prov_desc->pd_kcf_prov_handle;
	KCF_PROV_REFRELE(prov_desc);
	return (CRYPTO_SUCCESS);

undo_then_bail:
	undo_register_provider(prov_desc, B_TRUE);
	ret = CRYPTO_FAILED;
bail:
	KCF_PROV_REFRELE(prov_desc);

errormsg:
	if (ret != CRYPTO_SUCCESS && sys_shutdown == 0) {
		switch (ret) {
		case CRYPTO_FAILED:
			cmn_err(CE_WARN, "%s failed when registering with the "
			    "Cryptographic Framework.",
			    info->pi_provider_description);
			break;

		case CRYPTO_MODVERIFICATION_FAILED:
			cmn_err(CE_WARN, "%s failed module verification when "
			    "registering with the Cryptographic Framework.",
			    info->pi_provider_description);
			break;

		case CRYPTO_ARGUMENTS_BAD:
			cmn_err(CE_WARN, "%s provided bad arguments and was "
			    "not registered with the Cryptographic Framework.",
			    info->pi_provider_description);
			break;

		case CRYPTO_VERSION_MISMATCH:
			cmn_err(CE_WARN, "%s was not registered with the "
			    "Cryptographic Framework as there is a SPI version "
			    "mismatch (%d) error.",
			    info->pi_provider_description,
			    info->pi_interface_version);
			break;

		case CRYPTO_FIPS140_ERROR:
			cmn_err(CE_WARN, "%s was not registered with the "
			    "Cryptographic Framework as there was a FIPS 140 "
			    "validation error.", info->pi_provider_description);
			break;

		default:
			cmn_err(CE_WARN, "%s did not register with the "
			    "Cryptographic Framework. (0x%x)",
			    info->pi_provider_description, ret);
		};
	}

	return (ret);
}

/* Return the number of holds on a provider. */
int
kcf_get_refcnt(kcf_provider_desc_t *pd, boolean_t do_lock)
{
	int i;
	int refcnt = 0;

	if (do_lock)
		for (i = 0; i < pd->pd_nbins; i++)
			mutex_enter(&(pd->pd_percpu_bins[i].kp_lock));

	for (i = 0; i < pd->pd_nbins; i++)
		refcnt += pd->pd_percpu_bins[i].kp_holdcnt;

	if (do_lock)
		for (i = 0; i < pd->pd_nbins; i++)
			mutex_exit(&(pd->pd_percpu_bins[i].kp_lock));

	return (refcnt);
}

/*
 * This routine is used to notify the framework when a provider is being
 * removed.  Hardware providers call this routine in their detach routines.
 * Software providers call this routine in their _fini() routine.
 */
int
crypto_unregister_provider(crypto_kcf_provider_handle_t handle)
{
	uint_t mech_idx;
	kcf_provider_desc_t *desc;
	kcf_prov_state_t saved_state;
	int ret = CRYPTO_SUCCESS;

	/* lookup provider descriptor */
	if ((desc = kcf_prov_tab_lookup((crypto_provider_id_t)handle)) ==
	    NULL) {
		ret = CRYPTO_UNKNOWN_PROVIDER;
		goto errormsg;
	}

	mutex_enter(&desc->pd_lock);
	/*
	 * Check if any other thread is disabling or removing
	 * this provider. We return if this is the case.
	 */
	if (desc->pd_state >= KCF_PROV_DISABLED) {
		mutex_exit(&desc->pd_lock);
		/* Release reference held by kcf_prov_tab_lookup(). */
		KCF_PROV_REFRELE(desc);
		ret = CRYPTO_BUSY;
		goto errormsg;
	}

	saved_state = desc->pd_state;
	desc->pd_state = KCF_PROV_UNREGISTERING;

	if (saved_state == KCF_PROV_BUSY) {
		/*
		 * The per-provider taskq threads may be waiting. We
		 * signal them so that they can start failing requests.
		 */
		cv_broadcast(&desc->pd_resume_cv);
	}

	mutex_exit(&desc->pd_lock);

	if (desc->pd_prov_type != CRYPTO_SW_PROVIDER) {
		remove_provider(desc);
	}

	if (desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		/* remove the provider from the mechanisms tables */
		for (mech_idx = 0; mech_idx < desc->pd_mech_list_count;
		    mech_idx++) {
			kcf_remove_mech_provider(
			    desc->pd_mechanisms[mech_idx].cm_mech_name, desc);
		}
	}

	/* remove provider from providers table */
	if (kcf_prov_tab_rem_provider((crypto_provider_id_t)handle) !=
	    CRYPTO_SUCCESS) {
		/* Release reference held by kcf_prov_tab_lookup(). */
		KCF_PROV_REFRELE(desc);
		ret = CRYPTO_UNKNOWN_PROVIDER;
		goto errormsg;
	}

	delete_kstat(desc);

	if (desc->pd_prov_type == CRYPTO_SW_PROVIDER) {
		/*
		 * Wait till the existing requests with the provider complete
		 * and all the holds are released. All the holds on a software
		 * provider are from kernel clients and the hold time
		 * is expected to be short. So, we won't be stuck here forever.
		 */
		while (kcf_get_refcnt(desc, B_TRUE) > 1) {
			/* wait 1 second and try again. */
			delay(1 * drv_usectohz(1000000));
		}
	} else {
		int i;
		kcf_prov_cpu_t *mp;

		/*
		 * Wait until requests that have been sent to the provider
		 * complete.
		 */
		for (i = 0; i < desc->pd_nbins; i++) {
			mp = &(desc->pd_percpu_bins[i]);

			mutex_enter(&mp->kp_lock);
			while (mp->kp_jobcnt > 0) {
				cv_wait(&mp->kp_cv, &mp->kp_lock);
			}
			mutex_exit(&mp->kp_lock);
		}
	}

	mutex_enter(&desc->pd_lock);
	desc->pd_state = KCF_PROV_UNREGISTERED;
	mutex_exit(&desc->pd_lock);

	kcf_do_notify(desc, B_FALSE);

	mutex_enter(&prov_tab_mutex);
	/* Release reference held by kcf_prov_tab_lookup(). */
	KCF_PROV_REFRELE(desc);

	if (kcf_get_refcnt(desc, B_TRUE) == 0) {
		/* kcf_free_provider_desc drops prov_tab_mutex */
		kcf_free_provider_desc(desc);
	} else {
		ASSERT(desc->pd_prov_type != CRYPTO_SW_PROVIDER);
		/*
		 * We could avoid this if /dev/crypto can proactively
		 * remove any holds on us from a dormant PKCS #11 app.
		 * For now, we check the provider table for
		 * KCF_PROV_UNREGISTERED entries when a provider is
		 * added to the table or when a provider is removed from it
		 * and free them when refcnt reaches zero.
		 */
		kcf_need_provtab_walk = B_TRUE;
		mutex_exit(&prov_tab_mutex);
	}

errormsg:
	if (ret != CRYPTO_SUCCESS && sys_shutdown == 0) {
		switch (ret) {
		case CRYPTO_UNKNOWN_PROVIDER:
			cmn_err(CE_WARN, "Unknown provider \"%s\" was "
			    "requested to unregister from the cryptographic "
			    "framework.", desc->pd_description);
			break;

		case CRYPTO_BUSY:
			cmn_err(CE_WARN, "%s could not be unregistered from "
			    "the Cryptographic Framework as it is busy.",
			    desc->pd_description);
			break;

		default:
			cmn_err(CE_WARN, "%s did not unregister with the "
			    "Cryptographic Framework. (0x%x)",
			    desc->pd_description, ret);
		};
	}

	return (ret);
}

/*
 * This routine is used to notify the framework that the state of
 * a cryptographic provider has changed. Valid state codes are:
 *
 * CRYPTO_PROVIDER_READY
 * 	The provider indicates that it can process more requests. A provider
 *	will notify with this event if it previously has notified us with a
 *	CRYPTO_PROVIDER_BUSY.
 *
 * CRYPTO_PROVIDER_BUSY
 * 	The provider can not take more requests.
 *
 * CRYPTO_PROVIDER_FAILED
 *	The provider encountered an internal error. The framework will not
 * 	be sending any more requests to the provider. The provider may notify
 *	with a CRYPTO_PROVIDER_READY, if it is able to recover from the error.
 *
 * This routine can be called from user or interrupt context.
 */
void
crypto_provider_notification(crypto_kcf_provider_handle_t handle, uint_t state)
{
	kcf_provider_desc_t *pd;

	/* lookup the provider from the given handle */
	if ((pd = kcf_prov_tab_lookup((crypto_provider_id_t)handle)) == NULL)
		return;

	mutex_enter(&pd->pd_lock);

	if (pd->pd_state <= KCF_PROV_VERIFICATION_FAILED)
		goto out;

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		cmn_err(CE_WARN, "crypto_provider_notification: "
		    "logical provider (%x) ignored\n", handle);
		goto out;
	}
	switch (state) {
	case CRYPTO_PROVIDER_READY:
		switch (pd->pd_state) {
		case KCF_PROV_BUSY:
			pd->pd_state = KCF_PROV_READY;
			/*
			 * Signal the per-provider taskq threads that they
			 * can start submitting requests.
			 */
			cv_broadcast(&pd->pd_resume_cv);
			break;

		case KCF_PROV_FAILED:
			/*
			 * The provider recovered from the error. Let us
			 * use it now.
			 */
			pd->pd_state = KCF_PROV_READY;
			break;
		}
		break;

	case CRYPTO_PROVIDER_BUSY:
		switch (pd->pd_state) {
		case KCF_PROV_READY:
			pd->pd_state = KCF_PROV_BUSY;
			break;
		}
		break;

	case CRYPTO_PROVIDER_FAILED:
		/*
		 * We note the failure and return. The per-provider taskq
		 * threads check this flag and start failing the
		 * requests, if it is set. See process_req_hwp() for details.
		 */
		switch (pd->pd_state) {
		case KCF_PROV_READY:
			pd->pd_state = KCF_PROV_FAILED;
			break;

		case KCF_PROV_BUSY:
			pd->pd_state = KCF_PROV_FAILED;
			/*
			 * The per-provider taskq threads may be waiting. We
			 * signal them so that they can start failing requests.
			 */
			cv_broadcast(&pd->pd_resume_cv);
			break;
		}
		break;
	}
out:
	mutex_exit(&pd->pd_lock);
	KCF_PROV_REFRELE(pd);
}

/*
 * This routine is used to notify the framework the result of
 * an asynchronous request handled by a provider. Valid error
 * codes are the same as the CRYPTO_* errors defined in common.h.
 *
 * This routine can be called from user or interrupt context.
 */
void
crypto_op_notification(crypto_req_handle_t handle, int error)
{
	kcf_call_type_t ctype;

	if (handle == NULL)
		return;

	if ((ctype = GET_REQ_TYPE(handle)) == CRYPTO_SYNCH) {
		kcf_sreq_node_t *sreq = (kcf_sreq_node_t *)handle;

		KCF_PROV_JOB_RELE_STAT(sreq->sn_mp, (error != CRYPTO_SUCCESS));
		kcf_sop_done(sreq, error);
	} else {
		kcf_areq_node_t *areq = (kcf_areq_node_t *)handle;

		ASSERT(ctype == CRYPTO_ASYNCH);
		KCF_PROV_JOB_RELE_STAT(areq->an_mp, (error != CRYPTO_SUCCESS));
		kcf_aop_done(areq, error);
	}
}

/*
 * This routine is used by software providers to determine
 * whether to use KM_SLEEP or KM_NOSLEEP during memory allocation.
 * Note that hardware providers can always use KM_SLEEP. So,
 * they do not need to call this routine.
 *
 * This routine can be called from user or interrupt context.
 */
int
crypto_kmflag(crypto_req_handle_t handle)
{
	return (REQHNDL2_KMFLAG(handle));
}

/*
 * Process the mechanism info structures specified by the provider
 * during registration. A NULL crypto_provider_info_t indicates
 * an already initialized provider descriptor.
 *
 * Mechanisms are not added to the kernel's mechanism table if the
 * provider is a logical provider.
 *
 * Returns CRYPTO_SUCCESS on success, CRYPTO_ARGUMENTS if one
 * of the specified mechanisms was malformed, or CRYPTO_HOST_MEMORY
 * if the table of mechanisms is full.
 */
static int
init_prov_mechs(crypto_provider_info_t *info, kcf_provider_desc_t *desc)
{
	uint_t mech_idx;
	uint_t cleanup_idx;
	int err = CRYPTO_SUCCESS;
	kcf_prov_mech_desc_t *pmd;
	int desc_use_count = 0;
	int mcount = desc->pd_mech_list_count;

	if (desc->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		if (info != NULL) {
			ASSERT(info->pi_mechanisms != NULL);
			bcopy(info->pi_mechanisms, desc->pd_mechanisms,
			    sizeof (crypto_mech_info_t) * mcount);
		}
		return (CRYPTO_SUCCESS);
	}

	/*
	 * Copy the mechanism list from the provider info to the provider
	 * descriptor. desc->pd_mechanisms has an extra crypto_mech_info_t
	 * element if the provider has random_ops since we keep an internal
	 * mechanism, SUN_RANDOM, in this case.
	 */
	if (info != NULL) {
		if (info->pi_ops_vector->co_random_ops != NULL) {
			crypto_mech_info_t *rand_mi;

			/*
			 * Need the following check as it is possible to have
			 * a provider that implements just random_ops and has
			 * pi_mechanisms == NULL.
			 */
			if (info->pi_mechanisms != NULL) {
				bcopy(info->pi_mechanisms, desc->pd_mechanisms,
				    sizeof (crypto_mech_info_t) * (mcount - 1));
			}
			rand_mi = &desc->pd_mechanisms[mcount - 1];

			bzero(rand_mi, sizeof (crypto_mech_info_t));
			(void) strncpy(rand_mi->cm_mech_name, SUN_RANDOM,
			    CRYPTO_MAX_MECH_NAME);
			rand_mi->cm_func_group_mask = CRYPTO_FG_RANDOM;
		} else {
			ASSERT(info->pi_mechanisms != NULL);
			bcopy(info->pi_mechanisms, desc->pd_mechanisms,
			    sizeof (crypto_mech_info_t) * mcount);
		}
	}

	/*
	 * For each mechanism support by the provider, add the provider
	 * to the corresponding KCF mechanism mech_entry chain.
	 */
	for (mech_idx = 0; mech_idx < desc->pd_mech_list_count; mech_idx++) {
		crypto_mech_info_t *mi = &desc->pd_mechanisms[mech_idx];

		if ((mi->cm_mech_flags & CRYPTO_KEYSIZE_UNIT_IN_BITS) &&
		    (mi->cm_mech_flags & CRYPTO_KEYSIZE_UNIT_IN_BYTES)) {
			err = CRYPTO_ARGUMENTS_BAD;
			break;
		}

		if ((err = kcf_add_mech_provider(mech_idx, desc, &pmd)) !=
		    KCF_SUCCESS)
			break;

		if (pmd == NULL)
			continue;

		/* The provider will be used for this mechanism */
		desc_use_count++;
	}

	/*
	 * Don't allow multiple software providers with disabled mechanisms
	 * to register. Subsequent enabling of mechanisms will result in
	 * an unsupported configuration, i.e. multiple software providers
	 * per mechanism.
	 */
	if (desc_use_count == 0 && desc->pd_prov_type == CRYPTO_SW_PROVIDER)
		return (CRYPTO_ARGUMENTS_BAD);

	if (err == KCF_SUCCESS)
		return (CRYPTO_SUCCESS);

	/*
	 * An error occurred while adding the mechanism, cleanup
	 * and bail.
	 */
	for (cleanup_idx = 0; cleanup_idx < mech_idx; cleanup_idx++) {
		kcf_remove_mech_provider(
		    desc->pd_mechanisms[cleanup_idx].cm_mech_name, desc);
	}

	if (err == KCF_MECH_TAB_FULL)
		return (CRYPTO_HOST_MEMORY);

	return (CRYPTO_ARGUMENTS_BAD);
}

/*
 * Update routine for kstat. Only privileged users are allowed to
 * access this information, since this information is sensitive.
 * There are some cryptographic attacks (e.g. traffic analysis)
 * which can use this information.
 */
static int
kcf_prov_kstat_update(kstat_t *ksp, int rw)
{
	kcf_prov_stats_t *ks_data;
	kcf_provider_desc_t *pd = (kcf_provider_desc_t *)ksp->ks_private;
	int i;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ks_data = ksp->ks_data;

	if (secpolicy_sys_config(CRED(), B_TRUE) != 0) {
		ks_data->ps_ops_total.value.ui64 = 0;
		ks_data->ps_ops_passed.value.ui64 = 0;
		ks_data->ps_ops_failed.value.ui64 = 0;
		ks_data->ps_ops_busy_rval.value.ui64 = 0;
	} else {
		uint64_t dtotal, ftotal, btotal;

		dtotal = ftotal = btotal = 0;
		/* No locking done since an exact count is not required. */
		for (i = 0; i < pd->pd_nbins; i++) {
			dtotal += pd->pd_percpu_bins[i].kp_ndispatches;
			ftotal += pd->pd_percpu_bins[i].kp_nfails;
			btotal += pd->pd_percpu_bins[i].kp_nbusy_rval;
		}

		ks_data->ps_ops_total.value.ui64 = dtotal;
		ks_data->ps_ops_failed.value.ui64 = ftotal;
		ks_data->ps_ops_busy_rval.value.ui64 = btotal;
		ks_data->ps_ops_passed.value.ui64 = dtotal - ftotal - btotal;
	}

	return (0);
}


/*
 * Utility routine called from failure paths in crypto_register_provider()
 * and from crypto_load_soft_disabled().
 */
void
undo_register_provider(kcf_provider_desc_t *desc, boolean_t remove_prov)
{
	uint_t mech_idx;

	/* remove the provider from the mechanisms tables */
	for (mech_idx = 0; mech_idx < desc->pd_mech_list_count;
	    mech_idx++) {
		kcf_remove_mech_provider(
		    desc->pd_mechanisms[mech_idx].cm_mech_name, desc);
	}

	/* remove provider from providers table */
	if (remove_prov)
		(void) kcf_prov_tab_rem_provider(desc->pd_prov_id);
}

/*
 * Utility routine called from crypto_load_soft_disabled(). Callers
 * should have done a prior undo_register_provider().
 */
void
redo_register_provider(kcf_provider_desc_t *pd)
{
	/* process the mechanisms supported by the provider */
	(void) init_prov_mechs(NULL, pd);

	/*
	 * Hold provider in providers table. We should not call
	 * kcf_prov_tab_add_provider() here as the provider descriptor
	 * is still valid which means it has an entry in the provider
	 * table.
	 */
	KCF_PROV_REFHOLD(pd);
}

/*
 * Add provider (p1) to another provider's array of providers (p2).
 * Hardware and logical providers use this array to cross-reference
 * each other.
 */
static void
add_provider_to_array(kcf_provider_desc_t *p1, kcf_provider_desc_t *p2)
{
	kcf_provider_list_t *new;

	new = kmem_alloc(sizeof (kcf_provider_list_t), KM_SLEEP);
	mutex_enter(&p2->pd_lock);
	new->pl_next = p2->pd_provider_list;
	p2->pd_provider_list = new;
	new->pl_provider = p1;
	mutex_exit(&p2->pd_lock);
}

/*
 * Remove provider (p1) from another provider's array of providers (p2).
 * Hardware and logical providers use this array to cross-reference
 * each other.
 */
static void
remove_provider_from_array(kcf_provider_desc_t *p1, kcf_provider_desc_t *p2)
{

	kcf_provider_list_t *pl = NULL, **prev;

	mutex_enter(&p2->pd_lock);
	for (pl = p2->pd_provider_list, prev = &p2->pd_provider_list;
	    pl != NULL; prev = &pl->pl_next, pl = pl->pl_next) {
		if (pl->pl_provider == p1) {
			break;
		}
	}

	if (p1 == NULL) {
		mutex_exit(&p2->pd_lock);
		return;
	}

	/* detach and free kcf_provider_list structure */
	*prev = pl->pl_next;
	kmem_free(pl, sizeof (*pl));
	mutex_exit(&p2->pd_lock);
}

/*
 * Convert an array of logical provider handles (crypto_provider_id)
 * stored in a crypto_provider_info structure into an array of provider
 * descriptors (kcf_provider_desc_t) attached to a logical provider.
 */
static void
process_logical_providers(crypto_provider_info_t *info, kcf_provider_desc_t *hp)
{
	kcf_provider_desc_t *lp;
	crypto_provider_id_t handle;
	int count = info->pi_logical_provider_count;
	int i;

	/* add hardware provider to each logical provider */
	for (i = 0; i < count; i++) {
		handle = info->pi_logical_providers[i];
		lp = kcf_prov_tab_lookup((crypto_provider_id_t)handle);
		if (lp == NULL) {
			continue;
		}
		add_provider_to_array(hp, lp);
		hp->pd_flags |= KCF_LPROV_MEMBER;

		/*
		 * A hardware provider has to have the provider descriptor of
		 * every logical provider it belongs to, so it can be removed
		 * from the logical provider if the hardware provider
		 * unregisters from the framework.
		 */
		add_provider_to_array(lp, hp);
		KCF_PROV_REFRELE(lp);
	}
}

/*
 * This routine removes a provider from all of the logical or
 * hardware providers it belongs to, and frees the provider's
 * array of pointers to providers.
 */
static void
remove_provider(kcf_provider_desc_t *pp)
{
	kcf_provider_desc_t *p;
	kcf_provider_list_t *e, *next;

	mutex_enter(&pp->pd_lock);
	for (e = pp->pd_provider_list; e != NULL; e = next) {
		p = e->pl_provider;
		remove_provider_from_array(pp, p);
		if (p->pd_prov_type == CRYPTO_HW_PROVIDER &&
		    p->pd_provider_list == NULL)
			p->pd_flags &= ~KCF_LPROV_MEMBER;
		next = e->pl_next;
		kmem_free(e, sizeof (*e));
	}
	pp->pd_provider_list = NULL;
	mutex_exit(&pp->pd_lock);
}

/*
 * Dispatch events as needed for a provider. is_added flag tells
 * whether the provider is registering or unregistering.
 */
void
kcf_do_notify(kcf_provider_desc_t *prov_desc, boolean_t is_added)
{
	int i;
	crypto_notify_event_change_t ec;

	ASSERT(prov_desc->pd_state > KCF_PROV_VERIFICATION_FAILED);

	/*
	 * Inform interested clients of the mechanisms becoming
	 * available/unavailable. We skip this for logical providers
	 * as they do not affect mechanisms.
	 */
	if (prov_desc->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		ec.ec_provider_type = prov_desc->pd_prov_type;
		ec.ec_change = is_added ? CRYPTO_MECH_ADDED :
		    CRYPTO_MECH_REMOVED;
		for (i = 0; i < prov_desc->pd_mech_list_count; i++) {
			/* Skip any mechanisms not allowed by the policy */
			if (is_mech_disabled(prov_desc,
			    prov_desc->pd_mechanisms[i].cm_mech_name))
				continue;

			(void) strncpy(ec.ec_mech_name,
			    prov_desc->pd_mechanisms[i].cm_mech_name,
			    CRYPTO_MAX_MECH_NAME);
			kcf_walk_ntfylist(CRYPTO_EVENT_MECHS_CHANGED, &ec);
		}

	}

	/*
	 * Inform interested clients about the new or departing provider.
	 * In case of a logical provider, we need to notify the event only
	 * for the logical provider and not for the underlying
	 * providers which are known by the KCF_LPROV_MEMBER bit.
	 */
	if (prov_desc->pd_prov_type == CRYPTO_LOGICAL_PROVIDER ||
	    (prov_desc->pd_flags & KCF_LPROV_MEMBER) == 0) {
		kcf_walk_ntfylist(is_added ? CRYPTO_EVENT_PROVIDER_REGISTERED :
		    CRYPTO_EVENT_PROVIDER_UNREGISTERED, prov_desc);
	}
}

static void
delete_kstat(kcf_provider_desc_t *desc)
{
	/* destroy the kstat created for this provider */
	if (desc->pd_kstat != NULL) {
		kcf_provider_desc_t *kspd = desc->pd_kstat->ks_private;

		/* release reference held by desc->pd_kstat->ks_private */
		ASSERT(desc == kspd);
		kstat_delete(kspd->pd_kstat);
		desc->pd_kstat = NULL;
		KCF_PROV_REFRELE(kspd);
	}
}
