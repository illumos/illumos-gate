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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/api.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/sched_impl.h>

#define	CRYPTO_OPS_OFFSET(f)		offsetof(crypto_ops_t, co_##f)
#define	CRYPTO_CIPHER_MAC_OFFSET(f) offsetof(crypto_dual_cipher_mac_ops_t, f)

static int crypto_mac_decrypt_common(crypto_mechanism_t *,
    crypto_mechanism_t *, crypto_dual_data_t *, crypto_key_t *, crypto_key_t *,
    crypto_ctx_template_t, crypto_ctx_template_t, crypto_data_t *,
    crypto_data_t *, crypto_call_req_t *, boolean_t);

static int crypto_mac_decrypt_common_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *, crypto_mechanism_t *,
    crypto_dual_data_t *, crypto_key_t *, crypto_key_t *,
    crypto_ctx_template_t, crypto_ctx_template_t, crypto_data_t *,
    crypto_data_t *, crypto_call_req_t *, boolean_t);

int
crypto_encrypt_mac_prov(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *encr_mech, crypto_mechanism_t *mac_mech,
    crypto_data_t *pt, crypto_key_t *encr_key, crypto_key_t *mac_key,
    crypto_ctx_template_t encr_tmpl, crypto_ctx_template_t mac_tmpl,
    crypto_dual_data_t *ct, crypto_data_t *mac, crypto_call_req_t *crq)
{
	/*
	 * First try to find a provider for the encryption mechanism, that
	 * is also capable of the MAC mechanism.
	 */
	int rv;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	kcf_ctx_template_t *ctx_encr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_encrypt_mac_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_encr_tmpl = NULL, spi_mac_tmpl = NULL;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(encr_mech->cm_type, encr_key,
		    mac_mech->cm_type, mac_key, pd, &real_provider,
		    CRYPTO_FG_ENCRYPT_MAC_ATOMIC);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if (real_provider->pd_prov_type == CRYPTO_SW_PROVIDER) {
		if (encr_tmpl != NULL) {
			if (kcf_get_mech_entry(encr_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_encr_tmpl = (kcf_ctx_template_t *)encr_tmpl;
			if (ctx_encr_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_encr_tmpl = ctx_encr_tmpl->ct_prov_tmpl;
		}

		if (mac_tmpl != NULL) {
			if (kcf_get_mech_entry(mac_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(crq, real_provider)) {
		crypto_mechanism_t lencr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		lencr_mech = *encr_mech;
		KCF_SET_PROVIDER_MECHNUM(encr_mech->cm_type, real_provider,
		    &lencr_mech);

		lmac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &lmac_mech);

		rv = KCF_PROV_ENCRYPT_MAC_ATOMIC(real_provider, sid,
		    &lencr_mech, encr_key, &lmac_mech, mac_key, pt, ct,
		    mac, spi_encr_tmpl, spi_mac_tmpl, KCF_SWFP_RHNDL(crq));

		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_ATOMIC,
		    sid, encr_key, mac_key, pt, ct, mac, spi_encr_tmpl,
		    spi_mac_tmpl);

		cmops = &(params.rp_u.encrypt_mac_params);

		/* careful! structs assignments */
		cmops->em_encr_mech = *encr_mech;
		KCF_SET_PROVIDER_MECHNUM(encr_mech->cm_type, real_provider,
		    &cmops->em_encr_mech);
		cmops->em_framework_encr_mechtype = encr_mech->cm_type;

		cmops->em_mac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &cmops->em_mac_mech);
		cmops->em_framework_mac_mechtype = mac_mech->cm_type;

		rv = kcf_submit_request(real_provider, NULL, crq, &params,
		    B_FALSE);
	}

out:
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);
	return (rv);
}

/*
 * Performs a dual encrypt/mac atomic operation. The provider and session
 * to use are determined by the KCF dispatcher.
 */
int
crypto_encrypt_mac(crypto_mechanism_t *encr_mech,
    crypto_mechanism_t *mac_mech, crypto_data_t *pt,
    crypto_key_t *encr_key, crypto_key_t *mac_key,
    crypto_ctx_template_t encr_tmpl, crypto_ctx_template_t mac_tmpl,
    crypto_dual_data_t *ct, crypto_data_t *mac, crypto_call_req_t *crq)
{
	/*
	 * First try to find a provider for the encryption mechanism, that
	 * is also capable of the MAC mechanism.
	 */
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_ctx_template_t *ctx_encr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_encrypt_mac_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_encr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_mech_type_t prov_encr_mechid, prov_mac_mechid;
	kcf_prov_tried_t *list = NULL;
	boolean_t encr_tmpl_checked = B_FALSE;
	boolean_t mac_tmpl_checked = B_FALSE;
	kcf_dual_req_t *next_req = NULL;

retry:
	/* pd is returned held on success */
	pd = kcf_get_dual_provider(encr_mech, encr_key, mac_mech, mac_key,
	    &me, &prov_encr_mechid,
	    &prov_mac_mechid, &error, list,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC,
	    CRYPTO_FG_MAC_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC,
	    ct->dd_len1);
	if (pd == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		if (next_req != NULL)
			kmem_free(next_req, sizeof (kcf_dual_req_t));
		return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if ((!encr_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if (encr_tmpl != NULL) {
			ctx_encr_tmpl = (kcf_ctx_template_t *)encr_tmpl;
			if (ctx_encr_tmpl->ct_generation != me->me_gen_swprov) {

				if (next_req != NULL)
					kmem_free(next_req,
					    sizeof (kcf_dual_req_t));
				if (list != NULL)
					kcf_free_triedlist(list);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_encr_tmpl = ctx_encr_tmpl->ct_prov_tmpl;
		}
		encr_tmpl_checked = B_TRUE;
	}

	if (prov_mac_mechid == CRYPTO_MECH_INVALID) {
		crypto_call_req_t encr_req;

		/* Need to emulate with 2 internal calls */
		/* Allocate and initialize the MAC req for the callback */

		if (crq != NULL) {
			if (next_req == NULL) {
				next_req = kcf_alloc_req(crq);

				if (next_req == NULL) {
					KCF_PROV_REFRELE(pd);
					if (list != NULL)
						kcf_free_triedlist(list);
					return (CRYPTO_HOST_MEMORY);
				}
				/*
				 * Careful! we're wrapping-in mac_tmpl instead
				 * of an spi_mac_tmpl. The callback routine will
				 * have to validate mac_tmpl, and use the
				 * mac_ctx_tmpl, once it picks a MAC provider.
				 */
				KCF_WRAP_MAC_OPS_PARAMS(&(next_req->kr_params),
				    KCF_OP_ATOMIC, 0, mac_mech, mac_key,
				    (crypto_data_t *)ct, mac, mac_tmpl);
			}

			encr_req.cr_flag = crq->cr_flag;
			encr_req.cr_callback_func = kcf_next_req;
			encr_req.cr_callback_arg = next_req;
		}

		if (pt == NULL) {
			KCF_WRAP_ENCRYPT_OPS_PARAMS(&params, KCF_OP_ATOMIC,
			    pd->pd_sid, encr_mech, encr_key,
			    (crypto_data_t *)ct, NULL, spi_encr_tmpl);
		} else {
			KCF_WRAP_ENCRYPT_OPS_PARAMS(&params, KCF_OP_ATOMIC,
			    pd->pd_sid, encr_mech, encr_key, pt,
			    (crypto_data_t *)ct, spi_encr_tmpl);
		}

		error = kcf_submit_request(pd, NULL, (crq == NULL) ? NULL :
		    &encr_req, &params, B_TRUE);

		switch (error) {
		case CRYPTO_SUCCESS: {
			off_t saveoffset;
			size_t savelen;

			/*
			 * The encryption step is done. Reuse the encr_req
			 * for submitting the MAC step.
			 */
			if (next_req == NULL) {
				saveoffset = ct->dd_offset1;
				savelen = ct->dd_len1;
			} else {
				saveoffset = next_req->kr_saveoffset =
				    ct->dd_offset1;
				savelen = next_req->kr_savelen = ct->dd_len1;
				encr_req.cr_callback_func = kcf_last_req;
			}

			ct->dd_offset1 = ct->dd_offset2;
			ct->dd_len1 = ct->dd_len2;

			error = crypto_mac(mac_mech, (crypto_data_t *)ct,
			    mac_key, mac_tmpl, mac, (crq == NULL) ? NULL :
			    &encr_req);

			if (error != CRYPTO_QUEUED) {
				ct->dd_offset1 = saveoffset;
				ct->dd_len1 = savelen;
			}
			break;
		}

		case CRYPTO_QUEUED:
			if ((crq != NULL) &&
			    !(crq->cr_flag & CRYPTO_SKIP_REQID))
				crq->cr_reqid = encr_req.cr_reqid;
			break;

		default:

			/* Add pd to the linked list of providers tried. */
			if (IS_RECOVERABLE(error)) {
				if (kcf_insert_triedlist(&list, pd,
				    KCF_KMFLAG(crq)) != NULL)
					goto retry;
			}
		}
		if (error != CRYPTO_QUEUED && next_req != NULL)
			kmem_free(next_req, sizeof (kcf_dual_req_t));
		if (list != NULL)
			kcf_free_triedlist(list);
		KCF_PROV_REFRELE(pd);
		return (error);
	}
	if ((!mac_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if ((mac_tmpl != NULL) &&
		    (prov_mac_mechid != CRYPTO_MECH_INVALID)) {
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {

				if (next_req != NULL)
					kmem_free(next_req,
					    sizeof (kcf_dual_req_t));
				if (list != NULL)
					kcf_free_triedlist(list);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
		mac_tmpl_checked = B_TRUE;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(crq, pd)) {
		crypto_mechanism_t lencr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		lencr_mech = *encr_mech;
		lencr_mech.cm_type = prov_encr_mechid;
		lmac_mech = *mac_mech;
		lmac_mech.cm_type = prov_mac_mechid;

		error = KCF_PROV_ENCRYPT_MAC_ATOMIC(pd, pd->pd_sid,
		    &lencr_mech, encr_key, &lmac_mech, mac_key, pt, ct,
		    mac, spi_encr_tmpl, spi_mac_tmpl, KCF_SWFP_RHNDL(crq));

		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_ATOMIC,
		    pd->pd_sid, encr_key, mac_key, pt, ct, mac, spi_encr_tmpl,
		    spi_mac_tmpl);

		cmops = &(params.rp_u.encrypt_mac_params);

		/* careful! structs assignments */
		cmops->em_encr_mech = *encr_mech;
		cmops->em_encr_mech.cm_type = prov_encr_mechid;
		cmops->em_framework_encr_mechtype = encr_mech->cm_type;
		cmops->em_mac_mech = *mac_mech;
		cmops->em_mac_mech.cm_type = prov_mac_mechid;
		cmops->em_framework_mac_mechtype = mac_mech->cm_type;

		error = kcf_submit_request(pd, NULL, crq, &params, B_FALSE);
	}

	if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED &&
	    IS_RECOVERABLE(error)) {
		/* Add pd to the linked list of providers tried. */
		if (kcf_insert_triedlist(&list, pd, KCF_KMFLAG(crq)) != NULL)
			goto retry;
	}

	if (next_req != NULL)
		kmem_free(next_req, sizeof (kcf_dual_req_t));

	if (list != NULL)
		kcf_free_triedlist(list);

	KCF_PROV_REFRELE(pd);
	return (error);
}

int
crypto_encrypt_mac_init_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *encr_mech,
    crypto_mechanism_t *mac_mech, crypto_key_t *encr_key,
    crypto_key_t *mac_key, crypto_ctx_template_t encr_tmpl,
    crypto_ctx_template_t mac_tmpl, crypto_context_t *ctxp,
    crypto_call_req_t *cr)
{
	/*
	 * First try to find a provider for the encryption mechanism, that
	 * is also capable of the MAC mechanism.
	 */
	int rv;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	kcf_ctx_template_t *ctx_encr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_encrypt_mac_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_encr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_ctx_t *ctx;
	kcf_context_t *encr_kcf_context = NULL;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(encr_mech->cm_type, encr_key,
		    mac_mech->cm_type, mac_key, pd, &real_provider,
		    CRYPTO_FG_ENCRYPT_MAC);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if (real_provider->pd_prov_type == CRYPTO_SW_PROVIDER) {
		if (encr_tmpl != NULL) {
			if (kcf_get_mech_entry(encr_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_encr_tmpl = (kcf_ctx_template_t *)encr_tmpl;
			if (ctx_encr_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_encr_tmpl = ctx_encr_tmpl->ct_prov_tmpl;
		}

		if (mac_tmpl != NULL) {
			if (kcf_get_mech_entry(mac_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
	}

	ctx = kcf_new_ctx(cr, real_provider, sid);
	if (ctx == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto out;
	}
	encr_kcf_context = (kcf_context_t *)ctx->cc_framework_private;

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, real_provider)) {
		crypto_mechanism_t lencr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		lencr_mech = *encr_mech;
		KCF_SET_PROVIDER_MECHNUM(encr_mech->cm_type, real_provider,
		    &lencr_mech);

		lmac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &lmac_mech);

		rv = KCF_PROV_ENCRYPT_MAC_INIT(real_provider, ctx, &lencr_mech,
		    encr_key, &lmac_mech, mac_key, spi_encr_tmpl, spi_mac_tmpl,
		    KCF_SWFP_RHNDL(cr));

		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_INIT,
		    sid, encr_key, mac_key, NULL, NULL, NULL,
		    spi_encr_tmpl, spi_mac_tmpl);

		cmops = &(params.rp_u.encrypt_mac_params);

		/* careful! structs assignments */
		cmops->em_encr_mech = *encr_mech;
		KCF_SET_PROVIDER_MECHNUM(encr_mech->cm_type, real_provider,
		    &cmops->em_encr_mech);
		cmops->em_framework_encr_mechtype = encr_mech->cm_type;

		cmops->em_mac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &cmops->em_mac_mech);
		cmops->em_framework_mac_mechtype = mac_mech->cm_type;

		rv = kcf_submit_request(real_provider, ctx, cr, &params,
		    B_FALSE);
	}

	if (rv != CRYPTO_SUCCESS && rv != CRYPTO_QUEUED) {
		KCF_CONTEXT_REFRELE(encr_kcf_context);
	} else
		*ctxp = (crypto_context_t)ctx;

out:
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);
	return (rv);
}

/*
 * Starts a multi-part dual encrypt/mac operation. The provider and session
 * to use are determined by the KCF dispatcher.
 */
/* ARGSUSED */
int
crypto_encrypt_mac_init(crypto_mechanism_t *encr_mech,
    crypto_mechanism_t *mac_mech, crypto_key_t *encr_key,
    crypto_key_t *mac_key, crypto_ctx_template_t encr_tmpl,
    crypto_ctx_template_t mac_tmpl, crypto_context_t *ctxp,
    crypto_call_req_t *cr)
{
	/*
	 * First try to find a provider for the encryption mechanism, that
	 * is also capable of the MAC mechanism.
	 */
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_ctx_template_t *ctx_encr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_encrypt_mac_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_encr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_mech_type_t prov_encr_mechid, prov_mac_mechid;
	kcf_prov_tried_t *list = NULL;
	boolean_t encr_tmpl_checked = B_FALSE;
	boolean_t mac_tmpl_checked = B_FALSE;
	crypto_ctx_t *ctx = NULL;
	kcf_context_t *encr_kcf_context = NULL, *mac_kcf_context;
	crypto_call_flag_t save_flag;

retry:
	/* pd is returned held on success */
	pd = kcf_get_dual_provider(encr_mech, encr_key, mac_mech, mac_key,
	    &me, &prov_encr_mechid,
	    &prov_mac_mechid, &error, list,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_MAC, CRYPTO_FG_MAC, 0);
	if (pd == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if ((!encr_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if (encr_tmpl != NULL) {
			ctx_encr_tmpl = (kcf_ctx_template_t *)encr_tmpl;
			if (ctx_encr_tmpl->ct_generation != me->me_gen_swprov) {

				if (list != NULL)
					kcf_free_triedlist(list);
				if (encr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(encr_kcf_context);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_encr_tmpl = ctx_encr_tmpl->ct_prov_tmpl;
		}
		encr_tmpl_checked = B_TRUE;
	}

	if (prov_mac_mechid == CRYPTO_MECH_INVALID) {
		/* Need to emulate with 2 internal calls */

		/*
		 * We avoid code complexity by limiting the pure async.
		 * case to be done using only a SW provider.
		 * XXX - Redo the emulation code below so that we can
		 * remove this limitation.
		 */
		if (cr != NULL && pd->pd_prov_type == CRYPTO_HW_PROVIDER) {
			if ((kcf_insert_triedlist(&list, pd, KCF_KMFLAG(cr))
			    != NULL))
				goto retry;
			if (list != NULL)
				kcf_free_triedlist(list);
			if (encr_kcf_context != NULL)
				KCF_CONTEXT_REFRELE(encr_kcf_context);
			KCF_PROV_REFRELE(pd);
			return (CRYPTO_HOST_MEMORY);
		}

		if (ctx == NULL && pd->pd_prov_type == CRYPTO_SW_PROVIDER) {
			ctx = kcf_new_ctx(cr, pd, pd->pd_sid);
			if (ctx == NULL) {
				if (list != NULL)
					kcf_free_triedlist(list);
				if (encr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(encr_kcf_context);
				KCF_PROV_REFRELE(pd);
				return (CRYPTO_HOST_MEMORY);
			}
			encr_kcf_context = (kcf_context_t *)
			    ctx->cc_framework_private;
		}
		/*
		 * Trade-off speed vs avoidance of code complexity and
		 * duplication:
		 * Could do all the combinations of fastpath / synch / asynch
		 * for the encryption and the mac steps. Early attempts
		 * showed the code grew wild and bug-prone, for little gain.
		 * Therefore, the adaptative asynch case is not implemented.
		 * It's either pure synchronous, or pure asynchronous.
		 * We still preserve a fastpath for the pure synchronous
		 * requests to SW providers.
		 */
		if (cr == NULL) {
			crypto_context_t mac_context;

			if (pd->pd_prov_type == CRYPTO_SW_PROVIDER) {
				crypto_mechanism_t lmech = *encr_mech;

				lmech.cm_type = prov_encr_mechid;

				error = KCF_PROV_ENCRYPT_INIT(pd, ctx, &lmech,
				    encr_key, spi_encr_tmpl,
				    KCF_RHNDL(KM_SLEEP));
			} else {
				/*
				 * If we did the 'goto retry' then ctx may not
				 * be NULL.  In general, we can't reuse another
				 * provider's context, so we free it now so
				 * we don't leak it.
				 */
				if (ctx != NULL) {
					KCF_CONTEXT_REFRELE((kcf_context_t *)
					    ctx->cc_framework_private);
					encr_kcf_context = NULL;
				}
				error = crypto_encrypt_init_prov(pd, pd->pd_sid,
				    encr_mech, encr_key, &encr_tmpl,
				    (crypto_context_t *)&ctx, NULL);

				if (error == CRYPTO_SUCCESS) {
					encr_kcf_context = (kcf_context_t *)
					    ctx->cc_framework_private;
				}
			}
			KCF_PROV_INCRSTATS(pd, error);

			KCF_PROV_REFRELE(pd);

			if (error != CRYPTO_SUCCESS) {
				/* Can't be CRYPTO_QUEUED. return the failure */
				if (list != NULL)
					kcf_free_triedlist(list);
				if (encr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(encr_kcf_context);

				return (error);
			}
			error = crypto_mac_init(mac_mech, mac_key, mac_tmpl,
			    &mac_context, NULL);

			if (list != NULL)
				kcf_free_triedlist(list);

			if (error != CRYPTO_SUCCESS) {
				/* Should this be an ASSERT() ? */

				KCF_CONTEXT_REFRELE(encr_kcf_context);
			} else {
				encr_kcf_context = (kcf_context_t *)
				    ctx->cc_framework_private;
				mac_kcf_context = (kcf_context_t *)
				    ((crypto_ctx_t *)mac_context)->
				    cc_framework_private;

				encr_kcf_context->kc_secondctx =
				    mac_kcf_context;
				KCF_CONTEXT_REFHOLD(mac_kcf_context);

				*ctxp = (crypto_context_t)ctx;
			}

			return (error);
		}

		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_INIT,
		    pd->pd_sid, encr_key, mac_key, NULL, NULL, NULL,
		    spi_encr_tmpl, spi_mac_tmpl);

		cmops = &(params.rp_u.encrypt_mac_params);

		/* careful! structs assignments */
		cmops->em_encr_mech = *encr_mech;
		/*
		 * cmops->em_encr_mech.cm_type will be set when we get to
		 * kcf_emulate_dual() routine.
		 */
		cmops->em_framework_encr_mechtype = encr_mech->cm_type;
		cmops->em_mac_mech = *mac_mech;

		/*
		 * cmops->em_mac_mech.cm_type will be set when we know the
		 * MAC provider.
		 */
		cmops->em_framework_mac_mechtype = mac_mech->cm_type;

		/*
		 * non-NULL ctx->kc_secondctx tells common_submit_request
		 * that this request uses separate cipher and MAC contexts.
		 * That function will set ctx->kc_secondctx to the new
		 * MAC context, once it gets one.
		 */
		encr_kcf_context->kc_secondctx = encr_kcf_context;

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;

		if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED) {
			KCF_CONTEXT_REFRELE(encr_kcf_context);
		}
		if (list != NULL)
			kcf_free_triedlist(list);
		*ctxp = (crypto_context_t)ctx;
		KCF_PROV_REFRELE(pd);
		return (error);
	}

	if ((!mac_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if ((mac_tmpl != NULL) &&
		    (prov_mac_mechid != CRYPTO_MECH_INVALID)) {
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {

				if (list != NULL)
					kcf_free_triedlist(list);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
		mac_tmpl_checked = B_TRUE;
	}

	if (ctx == NULL) {
		ctx = kcf_new_ctx(cr, pd, pd->pd_sid);
		if (ctx == NULL) {
			if (list != NULL)
				kcf_free_triedlist(list);

			KCF_PROV_REFRELE(pd);
			return (CRYPTO_HOST_MEMORY);
		}
		encr_kcf_context = (kcf_context_t *)ctx->cc_framework_private;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		crypto_mechanism_t lencr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		lencr_mech = *encr_mech;
		lencr_mech.cm_type = prov_encr_mechid;
		lmac_mech = *mac_mech;
		lmac_mech.cm_type = prov_mac_mechid;

		error = KCF_PROV_ENCRYPT_MAC_INIT(pd, ctx, &lencr_mech,
		    encr_key, &lmac_mech, mac_key, spi_encr_tmpl, spi_mac_tmpl,
		    KCF_SWFP_RHNDL(cr));

		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_INIT,
		    pd->pd_sid, encr_key, mac_key, NULL, NULL, NULL,
		    spi_encr_tmpl, spi_mac_tmpl);

		cmops = &(params.rp_u.encrypt_mac_params);

		/* careful! structs assignments */
		cmops->em_encr_mech = *encr_mech;
		cmops->em_encr_mech.cm_type = prov_encr_mechid;
		cmops->em_framework_encr_mechtype = encr_mech->cm_type;
		cmops->em_mac_mech = *mac_mech;
		cmops->em_mac_mech.cm_type = prov_mac_mechid;
		cmops->em_framework_mac_mechtype = mac_mech->cm_type;

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}

	if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED) {
		if ((IS_RECOVERABLE(error)) &&
		    (kcf_insert_triedlist(&list, pd, KCF_KMFLAG(cr)) != NULL))
			goto retry;

		KCF_CONTEXT_REFRELE(encr_kcf_context);
	} else
		*ctxp = (crypto_context_t)ctx;

	if (list != NULL)
		kcf_free_triedlist(list);

	KCF_PROV_REFRELE(pd);
	return (error);
}

/*
 * Continues a multi-part dual encrypt/mac operation.
 */
/* ARGSUSED */
int
crypto_encrypt_mac_update(crypto_context_t context,
    crypto_data_t *pt, crypto_dual_data_t *ct, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context, *mac_ctx;
	kcf_context_t *kcf_ctx, *kcf_mac_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	if ((kcf_mac_ctx = kcf_ctx->kc_secondctx) != NULL) {
		off_t save_offset;
		size_t save_len;
		crypto_call_flag_t save_flag;

		if (kcf_mac_ctx->kc_prov_desc == NULL) {
			error = CRYPTO_INVALID_CONTEXT;
			goto out;
		}
		mac_ctx = &kcf_mac_ctx->kc_glbl_ctx;

		/* First we submit the encryption request */
		if (cr == NULL) {
			/*
			 * 'ct' is always not NULL.
			 * A NULL 'pt' means in-place.
			 */
			if (pt == NULL)
				error = crypto_encrypt_update(context,
				    (crypto_data_t *)ct, NULL, NULL);
			else
				error = crypto_encrypt_update(context, pt,
				    (crypto_data_t *)ct, NULL);

			if (error != CRYPTO_SUCCESS)
				goto out;

			/*
			 * call  mac_update when there is data to throw in
			 * the mix. Either an explicitly non-zero ct->dd_len2,
			 * or the last ciphertext portion.
			 */
			save_offset = ct->dd_offset1;
			save_len = ct->dd_len1;
			if (ct->dd_len2 == 0) {
				/*
				 * The previous encrypt step was an
				 * accumulation only and didn't produce any
				 * partial output
				 */
				if (ct->dd_len1 == 0)
					goto out;
			} else {
				ct->dd_offset1 = ct->dd_offset2;
				ct->dd_len1 = ct->dd_len2;
			}
			error = crypto_mac_update((crypto_context_t)mac_ctx,
			    (crypto_data_t *)ct, NULL);

			ct->dd_offset1 = save_offset;
			ct->dd_len1 = save_len;

			goto out;
		}
		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_UPDATE,
		    pd->pd_sid, NULL, NULL, pt, ct, NULL, NULL, NULL)


		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;
		goto out;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		error = KCF_PROV_ENCRYPT_MAC_UPDATE(pd, ctx, pt, ct, NULL);
		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_UPDATE,
		    ctx->cc_session, NULL, NULL, pt, ct, NULL, NULL, NULL);

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}
out:
	return (error);
}

/*
 * Terminates a multi-part dual encrypt/mac operation.
 */
/* ARGSUSED */
int crypto_encrypt_mac_final(crypto_context_t context, crypto_dual_data_t *ct,
    crypto_data_t *mac, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context, *mac_ctx;
	kcf_context_t *kcf_ctx, *kcf_mac_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	if ((kcf_mac_ctx = kcf_ctx->kc_secondctx) != NULL) {
		off_t save_offset;
		size_t save_len;
		crypto_context_t mac_context;
		crypto_call_flag_t save_flag;

		if (kcf_mac_ctx->kc_prov_desc == NULL) {
			return (CRYPTO_INVALID_CONTEXT);
		}
		mac_ctx = &kcf_mac_ctx->kc_glbl_ctx;
		mac_context = (crypto_context_t)mac_ctx;

		if (cr == NULL) {
			/* Get the last chunk of ciphertext */
			error = crypto_encrypt_final(context,
			    (crypto_data_t *)ct, NULL);

			if (error != CRYPTO_SUCCESS)  {
				/*
				 * Needed here, because the caller of
				 * crypto_encrypt_mac_final() lost all
				 * refs to the mac_ctx.
				 */
				crypto_cancel_ctx(mac_context);
				return (error);
			}
			if (ct->dd_len2 > 0) {
				save_offset = ct->dd_offset1;
				save_len = ct->dd_len1;
				ct->dd_offset1 = ct->dd_offset2;
				ct->dd_len1 = ct->dd_len2;

				error = crypto_mac_update(mac_context,
				    (crypto_data_t *)ct, NULL);

				ct->dd_offset1 = save_offset;
				ct->dd_len1 = save_len;

				if (error != CRYPTO_SUCCESS)  {
					crypto_cancel_ctx(mac_context);
					return (error);
				}
			}

			/* and finally, collect the MAC */
			error = crypto_mac_final(mac_context, mac, NULL);

			return (error);
		}
		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_FINAL,
		    pd->pd_sid, NULL, NULL, NULL, ct, mac, NULL, NULL)


		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;
		return (error);
	}
	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		error = KCF_PROV_ENCRYPT_MAC_FINAL(pd, ctx, ct, mac, NULL);
		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_ENCRYPT_MAC_OPS_PARAMS(&params, KCF_OP_FINAL,
		    ctx->cc_session, NULL, NULL, NULL, ct, mac, NULL, NULL);
		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}
out:
	/* Release the hold done in kcf_new_ctx() during init step. */
	KCF_CONTEXT_COND_RELEASE(error, kcf_ctx);
	return (error);
}

/*
 * Performs an atomic dual mac/decrypt operation. The provider to use
 * is determined by the KCF dispatcher.
 */
int
crypto_mac_decrypt(crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_dual_data_t *ct,
    crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq)
{
	return (crypto_mac_decrypt_common(mac_mech, decr_mech, ct, mac_key,
	    decr_key, mac_tmpl, decr_tmpl, mac, pt, crq, B_FALSE));
}

int
crypto_mac_decrypt_prov(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mac_mech, crypto_mechanism_t *decr_mech,
    crypto_dual_data_t *ct, crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq)
{
	return (crypto_mac_decrypt_common_prov(provider, sid, mac_mech,
	    decr_mech, ct, mac_key, decr_key, mac_tmpl, decr_tmpl, mac, pt,
	    crq, B_FALSE));
}

/*
 * Performs an atomic dual mac/decrypt operation. The provider to use
 * is determined by the KCF dispatcher. 'mac' specifies the expected
 * value for the MAC. The decryption is not performed if the computed
 * MAC does not match the expected MAC.
 */
int
crypto_mac_verify_decrypt(crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_dual_data_t *ct,
    crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq)
{
	return (crypto_mac_decrypt_common(mac_mech, decr_mech, ct, mac_key,
	    decr_key, mac_tmpl, decr_tmpl, mac, pt, crq, B_TRUE));
}

int
crypto_mac_verify_decrypt_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_dual_data_t *ct,
    crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq)
{
	return (crypto_mac_decrypt_common_prov(provider, sid, mac_mech,
	    decr_mech, ct, mac_key, decr_key, mac_tmpl, decr_tmpl, mac, pt,
	    crq, B_TRUE));
}

/*
 * Called by both crypto_mac_decrypt() and crypto_mac_verify_decrypt().
 * optionally verified if the MACs match before calling the decryption step.
 */
static int
crypto_mac_decrypt_common(crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_dual_data_t *ct,
    crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq,
    boolean_t do_verify)
{
	/*
	 * First try to find a provider for the decryption mechanism, that
	 * is also capable of the MAC mechanism.
	 * We still favor optimizing the costlier decryption.
	 */
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_ctx_template_t *ctx_decr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_mac_decrypt_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_decr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_mech_type_t prov_decr_mechid, prov_mac_mechid;
	kcf_prov_tried_t *list = NULL;
	boolean_t decr_tmpl_checked = B_FALSE;
	boolean_t mac_tmpl_checked = B_FALSE;
	kcf_dual_req_t *next_req = NULL;
	crypto_call_req_t mac_req, *mac_reqp = NULL;

retry:
	/* pd is returned held on success */
	pd = kcf_get_dual_provider(decr_mech, decr_key, mac_mech, mac_key,
	    &me, &prov_decr_mechid,
	    &prov_mac_mechid, &error, list,
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    CRYPTO_FG_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC, ct->dd_len2);
	if (pd == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		if (next_req != NULL)
			kmem_free(next_req, sizeof (kcf_dual_req_t));
		return (CRYPTO_MECH_NOT_SUPPORTED);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 */

	if ((!decr_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if (decr_tmpl != NULL) {
			ctx_decr_tmpl = (kcf_ctx_template_t *)decr_tmpl;
			if (ctx_decr_tmpl->ct_generation != me->me_gen_swprov) {
				if (next_req != NULL)
					kmem_free(next_req,
					    sizeof (kcf_dual_req_t));
				if (list != NULL)
					kcf_free_triedlist(list);
				KCF_PROV_REFRELE(pd);

				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_decr_tmpl = ctx_decr_tmpl->ct_prov_tmpl;
		}
		decr_tmpl_checked = B_TRUE;
	}
	if (prov_mac_mechid == CRYPTO_MECH_INVALID) {
		/* Need to emulate with 2 internal calls */

		/* Prepare the call_req to be submitted for the MAC step */

		if (crq != NULL) {

			if (next_req == NULL) {
				/*
				 * allocate, initialize and prepare the
				 * params for the next step only in the
				 * first pass (not on every retry).
				 */
				next_req = kcf_alloc_req(crq);

				if (next_req == NULL) {
					KCF_PROV_REFRELE(pd);
					if (list != NULL)
						kcf_free_triedlist(list);
					return (CRYPTO_HOST_MEMORY);
				}
				KCF_WRAP_DECRYPT_OPS_PARAMS(
				    &(next_req->kr_params), KCF_OP_ATOMIC,
				    0, decr_mech, decr_key,
				    (crypto_data_t *)ct, pt, spi_decr_tmpl);
			}

			mac_req.cr_flag = (crq != NULL) ? crq->cr_flag : 0;
			mac_req.cr_flag |= CRYPTO_SETDUAL;
			mac_req.cr_callback_func = kcf_next_req;
			mac_req.cr_callback_arg = next_req;
			mac_reqp = &mac_req;
		}

		/* 'pd' is the decryption provider. */

		if (do_verify)
			error = crypto_mac_verify(mac_mech, (crypto_data_t *)ct,
			    mac_key, mac_tmpl, mac,
			    (crq == NULL) ? NULL : mac_reqp);
		else
			error = crypto_mac(mac_mech, (crypto_data_t *)ct,
			    mac_key, mac_tmpl, mac,
			    (crq == NULL) ? NULL : mac_reqp);

		switch (error) {
		case CRYPTO_SUCCESS: {
			off_t saveoffset;
			size_t savelen;

			if (next_req == NULL) {
				saveoffset = ct->dd_offset1;
				savelen = ct->dd_len1;
			} else {
				saveoffset = next_req->kr_saveoffset =
				    ct->dd_offset1;
				savelen = next_req->kr_savelen = ct->dd_len1;

				ASSERT(mac_reqp != NULL);
				mac_req.cr_flag &= ~CRYPTO_SETDUAL;
				mac_req.cr_callback_func = kcf_last_req;
			}
			ct->dd_offset1 = ct->dd_offset2;
			ct->dd_len1 = ct->dd_len2;

			if (CHECK_FASTPATH(crq, pd)) {
				crypto_mechanism_t lmech;

				lmech = *decr_mech;
				KCF_SET_PROVIDER_MECHNUM(decr_mech->cm_type,
				    pd, &lmech);

				error = KCF_PROV_DECRYPT_ATOMIC(pd, pd->pd_sid,
				    &lmech, decr_key, (crypto_data_t *)ct,
				    (crypto_data_t *)pt, spi_decr_tmpl,
				    KCF_SWFP_RHNDL(mac_reqp));

				KCF_PROV_INCRSTATS(pd, error);
			} else {
				KCF_WRAP_DECRYPT_OPS_PARAMS(&params,
				    KCF_OP_ATOMIC, pd->pd_sid, decr_mech,
				    decr_key, (crypto_data_t *)ct, pt,
				    spi_decr_tmpl);

				error = kcf_submit_request(pd, NULL,
				    (crq == NULL) ? NULL : mac_reqp,
				    &params, B_FALSE);
			}
			if (error != CRYPTO_QUEUED) {
				KCF_PROV_INCRSTATS(pd, error);
				ct->dd_offset1 = saveoffset;
				ct->dd_len1 = savelen;
			}
			break;
		}

		case CRYPTO_QUEUED:
			if ((crq != NULL) && (crq->cr_flag & CRYPTO_SKIP_REQID))
				crq->cr_reqid = mac_req.cr_reqid;
			break;

		default:
			if (IS_RECOVERABLE(error)) {
				if (kcf_insert_triedlist(&list, pd,
				    KCF_KMFLAG(crq)) != NULL)
					goto retry;
			}
		}
		if (error != CRYPTO_QUEUED && next_req != NULL)
			kmem_free(next_req, sizeof (kcf_dual_req_t));
		if (list != NULL)
			kcf_free_triedlist(list);
		KCF_PROV_REFRELE(pd);
		return (error);
	}

	if ((!mac_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if ((mac_tmpl != NULL) &&
		    (prov_mac_mechid != CRYPTO_MECH_INVALID)) {
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {
				if (next_req != NULL)
					kmem_free(next_req,
					    sizeof (kcf_dual_req_t));
				if (list != NULL)
					kcf_free_triedlist(list);
				KCF_PROV_REFRELE(pd);

				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
		mac_tmpl_checked = B_TRUE;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(crq, pd)) {
		crypto_mechanism_t lmac_mech;
		crypto_mechanism_t ldecr_mech;

		/* careful! structs assignments */
		ldecr_mech = *decr_mech;
		ldecr_mech.cm_type = prov_decr_mechid;
		lmac_mech = *mac_mech;
		lmac_mech.cm_type = prov_mac_mechid;

		if (do_verify)
			error = KCF_PROV_MAC_VERIFY_DECRYPT_ATOMIC(pd,
			    pd->pd_sid, &lmac_mech, mac_key, &ldecr_mech,
			    decr_key, ct, mac, pt, spi_mac_tmpl, spi_decr_tmpl,
			    KCF_SWFP_RHNDL(crq));
		else
			error = KCF_PROV_MAC_DECRYPT_ATOMIC(pd, pd->pd_sid,
			    &lmac_mech, mac_key, &ldecr_mech, decr_key,
			    ct, mac, pt, spi_mac_tmpl, spi_decr_tmpl,
			    KCF_SWFP_RHNDL(crq));

		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params,
		    (do_verify) ? KCF_OP_MAC_VERIFY_DECRYPT_ATOMIC :
		    KCF_OP_ATOMIC, pd->pd_sid, mac_key, decr_key, ct, mac, pt,
		    spi_mac_tmpl, spi_decr_tmpl);

		cmops = &(params.rp_u.mac_decrypt_params);

		/* careful! structs assignments */
		cmops->md_decr_mech = *decr_mech;
		cmops->md_decr_mech.cm_type = prov_decr_mechid;
		cmops->md_framework_decr_mechtype = decr_mech->cm_type;
		cmops->md_mac_mech = *mac_mech;
		cmops->md_mac_mech.cm_type = prov_mac_mechid;
		cmops->md_framework_mac_mechtype = mac_mech->cm_type;

		error = kcf_submit_request(pd, NULL, crq, &params, B_FALSE);
	}

	if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED &&
	    IS_RECOVERABLE(error)) {
		/* Add pd to the linked list of providers tried. */
		if (kcf_insert_triedlist(&list, pd, KCF_KMFLAG(crq)) != NULL)
			goto retry;
	}

	if (list != NULL)
		kcf_free_triedlist(list);

	if (next_req != NULL)
		kmem_free(next_req, sizeof (kcf_dual_req_t));
	KCF_PROV_REFRELE(pd);
	return (error);
}

static int
crypto_mac_decrypt_common_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_dual_data_t *ct,
    crypto_key_t *mac_key, crypto_key_t *decr_key,
    crypto_ctx_template_t mac_tmpl, crypto_ctx_template_t decr_tmpl,
    crypto_data_t *mac, crypto_data_t *pt, crypto_call_req_t *crq,
    boolean_t do_verify)
{
	/*
	 * First try to find a provider for the decryption mechanism, that
	 * is also capable of the MAC mechanism.
	 * We still favor optimizing the costlier decryption.
	 */
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	kcf_ctx_template_t *ctx_decr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_mac_decrypt_ops_params_t *cmops;
	crypto_spi_ctx_template_t spi_decr_tmpl = NULL, spi_mac_tmpl = NULL;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		error = kcf_get_hardware_provider(decr_mech->cm_type, decr_key,
		    mac_mech->cm_type, mac_key, pd, &real_provider,
		    CRYPTO_FG_MAC_DECRYPT_ATOMIC);

		if (error != CRYPTO_SUCCESS)
			return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 */

	if (real_provider->pd_prov_type == CRYPTO_SW_PROVIDER) {
		if (decr_tmpl != NULL) {
			if (kcf_get_mech_entry(decr_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				error = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_decr_tmpl = (kcf_ctx_template_t *)decr_tmpl;
			if (ctx_decr_tmpl->ct_generation != me->me_gen_swprov) {
				error = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_decr_tmpl = ctx_decr_tmpl->ct_prov_tmpl;
		}

		if (mac_tmpl != NULL) {
			if (kcf_get_mech_entry(mac_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				error = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {
				error = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(crq, pd)) {
		crypto_mechanism_t lmac_mech;
		crypto_mechanism_t ldecr_mech;

		/* careful! structs assignments */
		ldecr_mech = *decr_mech;
		KCF_SET_PROVIDER_MECHNUM(decr_mech->cm_type, real_provider,
		    &ldecr_mech);

		lmac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &lmac_mech);

		if (do_verify)
			error = KCF_PROV_MAC_VERIFY_DECRYPT_ATOMIC(
			    real_provider, sid, &lmac_mech, mac_key,
			    &ldecr_mech, decr_key, ct, mac, pt, spi_mac_tmpl,
			    spi_decr_tmpl, KCF_SWFP_RHNDL(crq));
		else
			error = KCF_PROV_MAC_DECRYPT_ATOMIC(real_provider, sid,
			    &lmac_mech, mac_key, &ldecr_mech, decr_key,
			    ct, mac, pt, spi_mac_tmpl, spi_decr_tmpl,
			    KCF_SWFP_RHNDL(crq));

		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params,
		    (do_verify) ? KCF_OP_MAC_VERIFY_DECRYPT_ATOMIC :
		    KCF_OP_ATOMIC, sid, mac_key, decr_key, ct, mac, pt,
		    spi_mac_tmpl, spi_decr_tmpl);

		cmops = &(params.rp_u.mac_decrypt_params);

		/* careful! structs assignments */
		cmops->md_decr_mech = *decr_mech;
		KCF_SET_PROVIDER_MECHNUM(decr_mech->cm_type, real_provider,
		    &cmops->md_decr_mech);
		cmops->md_framework_decr_mechtype = decr_mech->cm_type;

		cmops->md_mac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &cmops->md_mac_mech);
		cmops->md_framework_mac_mechtype = mac_mech->cm_type;

		error = kcf_submit_request(real_provider, NULL, crq, &params,
		    B_FALSE);
	}

out:
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);
	return (error);
}

/*
 * Starts a multi-part dual mac/decrypt operation. The provider to
 * use is determined by the KCF dispatcher.
 */
/* ARGSUSED */
int
crypto_mac_decrypt_init(crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_key_t *mac_key,
    crypto_key_t *decr_key, crypto_ctx_template_t mac_tmpl,
    crypto_ctx_template_t decr_tmpl, crypto_context_t *ctxp,
    crypto_call_req_t *cr)
{
	/*
	 * First try to find a provider for the decryption mechanism, that
	 * is also capable of the MAC mechanism.
	 * We still favor optimizing the costlier decryption.
	 */
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_ctx_template_t *ctx_decr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_mac_decrypt_ops_params_t *mdops;
	crypto_spi_ctx_template_t spi_decr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_mech_type_t prov_decr_mechid, prov_mac_mechid;
	kcf_prov_tried_t *list = NULL;
	boolean_t decr_tmpl_checked = B_FALSE;
	boolean_t mac_tmpl_checked = B_FALSE;
	crypto_ctx_t *ctx = NULL;
	kcf_context_t *decr_kcf_context = NULL, *mac_kcf_context = NULL;
	crypto_call_flag_t save_flag;

retry:
	/* pd is returned held on success */
	pd = kcf_get_dual_provider(decr_mech, decr_key, mac_mech, mac_key,
	    &me, &prov_decr_mechid,
	    &prov_mac_mechid, &error, list,
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_MAC_DECRYPT, CRYPTO_FG_MAC, 0);
	if (pd == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if ((!decr_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if (decr_tmpl != NULL) {
			ctx_decr_tmpl = (kcf_ctx_template_t *)decr_tmpl;
			if (ctx_decr_tmpl->ct_generation != me->me_gen_swprov) {

				if (list != NULL)
					kcf_free_triedlist(list);
				if (decr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(decr_kcf_context);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_decr_tmpl = ctx_decr_tmpl->ct_prov_tmpl;
		}
		decr_tmpl_checked = B_TRUE;
	}

	if (prov_mac_mechid == CRYPTO_MECH_INVALID) {
		/* Need to emulate with 2 internal calls */

		/*
		 * We avoid code complexity by limiting the pure async.
		 * case to be done using only a SW provider.
		 * XXX - Redo the emulation code below so that we can
		 * remove this limitation.
		 */
		if (cr != NULL && pd->pd_prov_type == CRYPTO_HW_PROVIDER) {
			if ((kcf_insert_triedlist(&list, pd, KCF_KMFLAG(cr))
			    != NULL))
				goto retry;
			if (list != NULL)
				kcf_free_triedlist(list);
			if (decr_kcf_context != NULL)
				KCF_CONTEXT_REFRELE(decr_kcf_context);
			KCF_PROV_REFRELE(pd);
			return (CRYPTO_HOST_MEMORY);
		}

		if (ctx == NULL && pd->pd_prov_type == CRYPTO_SW_PROVIDER) {
			ctx = kcf_new_ctx(cr, pd, pd->pd_sid);
			if (ctx == NULL) {
				if (list != NULL)
					kcf_free_triedlist(list);
				if (decr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(decr_kcf_context);
				KCF_PROV_REFRELE(pd);
				return (CRYPTO_HOST_MEMORY);
			}
			decr_kcf_context = (kcf_context_t *)
			    ctx->cc_framework_private;
		}
		/*
		 * Trade-off speed vs avoidance of code complexity and
		 * duplication:
		 * Could do all the combinations of fastpath / synch / asynch
		 * for the decryption and the mac steps. Early attempts
		 * showed the code grew wild and bug-prone, for little gain.
		 * Therefore, the adaptative asynch case is not implemented.
		 * It's either pure synchronous, or pure asynchronous.
		 * We still preserve a fastpath for the pure synchronous
		 * requests to SW providers.
		 */
		if (cr == NULL) {
			crypto_context_t mac_context;

			error = crypto_mac_init(mac_mech, mac_key, mac_tmpl,
			    &mac_context, NULL);

			if (error != CRYPTO_SUCCESS) {
				/* Can't be CRYPTO_QUEUED. return the failure */
				if (list != NULL)
					kcf_free_triedlist(list);

				if (decr_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(decr_kcf_context);
				return (error);
			}
			if (pd->pd_prov_type == CRYPTO_SW_PROVIDER) {
				crypto_mechanism_t lmech = *decr_mech;

				lmech.cm_type = prov_decr_mechid;

				error = KCF_PROV_DECRYPT_INIT(pd, ctx, &lmech,
				    decr_key, spi_decr_tmpl,
				    KCF_RHNDL(KM_SLEEP));
			} else {
				/*
				 * If we did the 'goto retry' then ctx may not
				 * be NULL.  In general, we can't reuse another
				 * provider's context, so we free it now so
				 * we don't leak it.
				 */
				if (ctx != NULL) {
					KCF_CONTEXT_REFRELE((kcf_context_t *)
					    ctx->cc_framework_private);
					decr_kcf_context = NULL;
				}
				error = crypto_decrypt_init_prov(pd, pd->pd_sid,
				    decr_mech, decr_key, &decr_tmpl,
				    (crypto_context_t *)&ctx, NULL);

				if (error == CRYPTO_SUCCESS) {
					decr_kcf_context = (kcf_context_t *)
					    ctx->cc_framework_private;
				}
			}

			KCF_PROV_INCRSTATS(pd, error);

			KCF_PROV_REFRELE(pd);

			if (error != CRYPTO_SUCCESS) {
				/* Can't be CRYPTO_QUEUED. return the failure */
				if (list != NULL)
					kcf_free_triedlist(list);
				if (mac_kcf_context != NULL)
					KCF_CONTEXT_REFRELE(mac_kcf_context);

				return (error);
			}
			mac_kcf_context = (kcf_context_t *)
			    ((crypto_ctx_t *)mac_context)->
			    cc_framework_private;

			decr_kcf_context = (kcf_context_t *)
			    ctx->cc_framework_private;

			/*
			 * Here also, the mac context is second. The callback
			 * case can't overwrite the context returned to
			 * the caller.
			 */
			decr_kcf_context->kc_secondctx = mac_kcf_context;
			KCF_CONTEXT_REFHOLD(mac_kcf_context);

			*ctxp = (crypto_context_t)ctx;

			return (error);
		}
		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_INIT,
		    pd->pd_sid, mac_key, decr_key, NULL, NULL, NULL,
		    spi_mac_tmpl, spi_decr_tmpl);

		mdops = &(params.rp_u.mac_decrypt_params);

		/* careful! structs assignments */
		mdops->md_decr_mech = *decr_mech;
		/*
		 * mdops->md_decr_mech.cm_type will be set when we get to
		 * kcf_emulate_dual() routine.
		 */
		mdops->md_framework_decr_mechtype = decr_mech->cm_type;
		mdops->md_mac_mech = *mac_mech;

		/*
		 * mdops->md_mac_mech.cm_type will be set when we know the
		 * MAC provider.
		 */
		mdops->md_framework_mac_mechtype = mac_mech->cm_type;

		/*
		 * non-NULL ctx->kc_secondctx tells common_submit_request
		 * that this request uses separate cipher and MAC contexts.
		 * That function will set the MAC context's kc_secondctx to
		 * this decrypt context.
		 */
		decr_kcf_context->kc_secondctx = decr_kcf_context;

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;

		if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED) {
			KCF_CONTEXT_REFRELE(decr_kcf_context);
		}
		if (list != NULL)
			kcf_free_triedlist(list);
		*ctxp =  ctx;
		KCF_PROV_REFRELE(pd);
		return (error);
	}

	if ((!mac_tmpl_checked) && (pd->pd_prov_type == CRYPTO_SW_PROVIDER)) {
		if ((mac_tmpl != NULL) &&
		    (prov_mac_mechid != CRYPTO_MECH_INVALID)) {
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {

				if (list != NULL)
					kcf_free_triedlist(list);

				KCF_PROV_REFRELE(pd);
				/* Which one is the the old one ? */
				return (CRYPTO_OLD_CTX_TEMPLATE);
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
		mac_tmpl_checked = B_TRUE;
	}

	if (ctx == NULL) {
		ctx = kcf_new_ctx(cr, pd, pd->pd_sid);
		if (ctx == NULL) {
			error = CRYPTO_HOST_MEMORY;
			if (list != NULL)
				kcf_free_triedlist(list);
			return (CRYPTO_HOST_MEMORY);
		}
		decr_kcf_context = (kcf_context_t *)ctx->cc_framework_private;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		crypto_mechanism_t ldecr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		ldecr_mech = *decr_mech;
		ldecr_mech.cm_type = prov_decr_mechid;
		lmac_mech = *mac_mech;
		lmac_mech.cm_type = prov_mac_mechid;

		error = KCF_PROV_MAC_DECRYPT_INIT(pd, ctx, &lmac_mech,
		    mac_key, &ldecr_mech, decr_key, spi_mac_tmpl, spi_decr_tmpl,
		    KCF_SWFP_RHNDL(cr));

		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_INIT,
		    pd->pd_sid, mac_key, decr_key, NULL, NULL, NULL,
		    spi_mac_tmpl, spi_decr_tmpl);

		mdops = &(params.rp_u.mac_decrypt_params);

		/* careful! structs assignments */
		mdops->md_decr_mech = *decr_mech;
		mdops->md_decr_mech.cm_type = prov_decr_mechid;
		mdops->md_framework_decr_mechtype = decr_mech->cm_type;
		mdops->md_mac_mech = *mac_mech;
		mdops->md_mac_mech.cm_type = prov_mac_mechid;
		mdops->md_framework_mac_mechtype = mac_mech->cm_type;

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}

	if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED) {
		if ((IS_RECOVERABLE(error)) &&
		    (kcf_insert_triedlist(&list, pd, KCF_KMFLAG(cr)) != NULL))
			goto retry;

		KCF_CONTEXT_REFRELE(decr_kcf_context);
	} else
		*ctxp = (crypto_context_t)ctx;

	if (list != NULL)
		kcf_free_triedlist(list);

	KCF_PROV_REFRELE(pd);
	return (error);
}

int
crypto_mac_decrypt_init_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *mac_mech,
    crypto_mechanism_t *decr_mech, crypto_key_t *mac_key,
    crypto_key_t *decr_key, crypto_ctx_template_t mac_tmpl,
    crypto_ctx_template_t decr_tmpl, crypto_context_t *ctxp,
    crypto_call_req_t *cr)
{
	/*
	 * First try to find a provider for the decryption mechanism, that
	 * is also capable of the MAC mechanism.
	 * We still favor optimizing the costlier decryption.
	 */
	int rv;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	kcf_ctx_template_t *ctx_decr_tmpl, *ctx_mac_tmpl;
	kcf_req_params_t params;
	kcf_mac_decrypt_ops_params_t *mdops;
	crypto_spi_ctx_template_t spi_decr_tmpl = NULL, spi_mac_tmpl = NULL;
	crypto_ctx_t *ctx;
	kcf_context_t *decr_kcf_context = NULL;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(decr_mech->cm_type, decr_key,
		    mac_mech->cm_type, mac_key, pd, &real_provider,
		    CRYPTO_FG_MAC_DECRYPT);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider
	 * Warning! will need to change when multiple software providers
	 * per mechanism are supported.
	 */

	if (real_provider->pd_prov_type == CRYPTO_SW_PROVIDER) {
		if (decr_tmpl != NULL) {
			if (kcf_get_mech_entry(decr_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_decr_tmpl = (kcf_ctx_template_t *)decr_tmpl;
			if (ctx_decr_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_decr_tmpl = ctx_decr_tmpl->ct_prov_tmpl;
		}

		if (mac_tmpl != NULL) {
			if (kcf_get_mech_entry(mac_mech->cm_type, &me) !=
			    KCF_SUCCESS) {
				rv = CRYPTO_MECHANISM_INVALID;
				goto out;
			}
			ctx_mac_tmpl = (kcf_ctx_template_t *)mac_tmpl;
			if (ctx_mac_tmpl->ct_generation != me->me_gen_swprov) {
				rv = CRYPTO_OLD_CTX_TEMPLATE;
				goto out;
			}
			spi_mac_tmpl = ctx_mac_tmpl->ct_prov_tmpl;
		}
	}

	ctx = kcf_new_ctx(cr, real_provider, sid);
	if (ctx == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto out;
	}
	decr_kcf_context = (kcf_context_t *)ctx->cc_framework_private;

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		crypto_mechanism_t ldecr_mech;
		crypto_mechanism_t lmac_mech;

		/* careful! structs assignments */
		ldecr_mech = *decr_mech;
		KCF_SET_PROVIDER_MECHNUM(decr_mech->cm_type, real_provider,
		    &ldecr_mech);

		lmac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &lmac_mech);

		rv = KCF_PROV_MAC_DECRYPT_INIT(real_provider, ctx, &lmac_mech,
		    mac_key, &ldecr_mech, decr_key, spi_mac_tmpl, spi_decr_tmpl,
		    KCF_SWFP_RHNDL(cr));

		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_INIT,
		    sid, mac_key, decr_key, NULL, NULL, NULL,
		    spi_mac_tmpl, spi_decr_tmpl);

		mdops = &(params.rp_u.mac_decrypt_params);

		/* careful! structs assignments */
		mdops->md_decr_mech = *decr_mech;
		KCF_SET_PROVIDER_MECHNUM(decr_mech->cm_type, real_provider,
		    &mdops->md_decr_mech);
		mdops->md_framework_decr_mechtype = decr_mech->cm_type;

		mdops->md_mac_mech = *mac_mech;
		KCF_SET_PROVIDER_MECHNUM(mac_mech->cm_type, real_provider,
		    &mdops->md_mac_mech);
		mdops->md_framework_mac_mechtype = mac_mech->cm_type;

		rv = kcf_submit_request(real_provider, ctx, cr, &params,
		    B_FALSE);
	}

	if (rv != CRYPTO_SUCCESS && rv != CRYPTO_QUEUED) {
		KCF_CONTEXT_REFRELE(decr_kcf_context);
	} else
		*ctxp = (crypto_context_t)ctx;

out:
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);
	return (rv);
}
/*
 * Continues a multi-part dual mac/decrypt operation.
 */
/* ARGSUSED */
int
crypto_mac_decrypt_update(crypto_context_t context,
    crypto_dual_data_t *ct, crypto_data_t *pt, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context, *mac_ctx;
	kcf_context_t *kcf_ctx, *kcf_mac_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	if ((kcf_mac_ctx = kcf_ctx->kc_secondctx) != NULL) {
		off_t save_offset;
		size_t save_len;
		crypto_call_flag_t save_flag;

		if (kcf_mac_ctx->kc_prov_desc == NULL) {
			error = CRYPTO_INVALID_CONTEXT;
			goto out;
		}
		mac_ctx = &kcf_mac_ctx->kc_glbl_ctx;

		/* First we submit the MAC request */
		if (cr == NULL) {
			/*
			 * 'ct' is always not NULL.
			 */
			error = crypto_mac_update((crypto_context_t)mac_ctx,
			    (crypto_data_t *)ct, NULL);

			if (error != CRYPTO_SUCCESS)
				goto out;

			/* Decrypt a different length only when told so */

			save_offset = ct->dd_offset1;
			save_len = ct->dd_len1;

			if (ct->dd_len2 > 0) {
				ct->dd_offset1 = ct->dd_offset2;
				ct->dd_len1 = ct->dd_len2;
			}

			error = crypto_decrypt_update(context,
			    (crypto_data_t *)ct, pt, NULL);

			ct->dd_offset1 = save_offset;
			ct->dd_len1 = save_len;

			goto out;
		}
		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_UPDATE,
		    pd->pd_sid, NULL, NULL, ct, NULL, pt, NULL, NULL)


		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;
		goto out;
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		error = KCF_PROV_MAC_DECRYPT_UPDATE(pd, ctx, ct, pt, NULL);
		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_UPDATE,
		    ctx->cc_session, NULL, NULL, ct, NULL, pt, NULL, NULL);

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}
out:
	return (error);
}

/*
 * Terminates a multi-part dual mac/decrypt operation.
 */
/* ARGSUSED */
int
crypto_mac_decrypt_final(crypto_context_t context, crypto_data_t *mac,
    crypto_data_t *pt, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context, *mac_ctx;
	kcf_context_t *kcf_ctx, *kcf_mac_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);

	if ((kcf_mac_ctx = kcf_ctx->kc_secondctx) != NULL) {
		crypto_call_flag_t save_flag;

		if (kcf_mac_ctx->kc_prov_desc == NULL) {
			error = CRYPTO_INVALID_CONTEXT;
			goto out;
		}
		mac_ctx = &kcf_mac_ctx->kc_glbl_ctx;

		/* First we collect the MAC */
		if (cr == NULL) {

			error = crypto_mac_final((crypto_context_t)mac_ctx,
			    mac, NULL);

			if (error != CRYPTO_SUCCESS) {
				crypto_cancel_ctx(ctx);
			} else {
				/* Get the last chunk of plaintext */
				error = crypto_decrypt_final(context, pt, NULL);
			}

			return (error);
		}
		/* submit a pure asynchronous request. */
		save_flag = cr->cr_flag;
		cr->cr_flag |= CRYPTO_ALWAYS_QUEUE;

		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_FINAL,
		    pd->pd_sid, NULL, NULL, NULL, mac, pt, NULL, NULL)


		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

		cr->cr_flag = save_flag;

		return (error);
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(cr, pd)) {
		error = KCF_PROV_MAC_DECRYPT_FINAL(pd, ctx, mac, pt, NULL);
		KCF_PROV_INCRSTATS(pd, error);
	} else {
		KCF_WRAP_MAC_DECRYPT_OPS_PARAMS(&params, KCF_OP_FINAL,
		    ctx->cc_session, NULL, NULL, NULL, mac, pt, NULL, NULL);

		error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);
	}
out:
	/* Release the hold done in kcf_new_ctx() during init step. */
	KCF_CONTEXT_COND_RELEASE(error, kcf_ctx);
	return (error);
}

/*
 * Digest/Encrypt dual operation. Project-private entry point, not part of
 * the k-API.
 */
/* ARGSUSED */
int
crypto_digest_encrypt_update(crypto_context_t digest_ctx,
    crypto_context_t encrypt_ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_call_req_t *crq)
{
	/*
	 * RFE 4688647:
	 * core functions needed by ioctl interface missing from impl.h
	 */
	return (CRYPTO_NOT_SUPPORTED);
}

/*
 * Decrypt/Digest dual operation. Project-private entry point, not part of
 * the k-API.
 */
/* ARGSUSED */
int
crypto_decrypt_digest_update(crypto_context_t decryptctx,
    crypto_context_t encrypt_ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_call_req_t *crq)
{
	/*
	 * RFE 4688647:
	 * core functions needed by ioctl interface missing from impl.h
	 */
	return (CRYPTO_NOT_SUPPORTED);
}

/*
 * Sign/Encrypt dual operation. Project-private entry point, not part of
 * the k-API.
 */
/* ARGSUSED */
int
crypto_sign_encrypt_update(crypto_context_t sign_ctx,
    crypto_context_t encrypt_ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_call_req_t *crq)
{
	/*
	 * RFE 4688647:
	 * core functions needed by ioctl interface missing from impl.h
	 */
	return (CRYPTO_NOT_SUPPORTED);
}

/*
 * Decrypt/Verify dual operation. Project-private entry point, not part of
 * the k-API.
 */
/* ARGSUSED */
int
crypto_decrypt_verify_update(crypto_context_t decrypt_ctx,
    crypto_context_t verify_ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_call_req_t *crq)
{
	/*
	 * RFE 4688647:
	 * core functions needed by ioctl interface missing from impl.h
	 */
	return (CRYPTO_NOT_SUPPORTED);
}
