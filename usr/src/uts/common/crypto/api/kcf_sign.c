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
#define	CRYPTO_SIGN_OFFSET(f)		offsetof(crypto_sign_ops_t, f)

/*
 * Sign entry points.
 */

/*
 * See comments for crypto_digest_init_prov().
 */
int
crypto_sign_init_prov(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *key, crypto_ctx_template_t tmpl,
    crypto_context_t *ctxp, crypto_call_req_t *crq)
{
	int rv;
	crypto_ctx_t *ctx;
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_SIGN);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	/* Allocate and initialize the canonical context */
	if ((ctx = kcf_new_ctx(crq, real_provider, sid)) == NULL) {
		if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
			KCF_PROV_REFRELE(real_provider);
		return (CRYPTO_HOST_MEMORY);
	}

	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_INIT, sid, mech,
	    key, NULL, NULL, tmpl);
	rv = kcf_submit_request(real_provider, ctx, crq, &params, B_FALSE);
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	if ((rv == CRYPTO_SUCCESS) || (rv == CRYPTO_QUEUED))
		*ctxp = (crypto_context_t)ctx;
	else {
		/* Release the hold done in kcf_new_ctx(). */
		KCF_CONTEXT_REFRELE((kcf_context_t *)ctx->cc_framework_private);
	}

	return (rv);
}

int
crypto_sign_init(crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_ctx_template_t tmpl, crypto_context_t *ctxp, crypto_call_req_t *crq)
{
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_prov_tried_t *list = NULL;
	kcf_ctx_template_t *ctx_tmpl;
	crypto_spi_ctx_template_t spi_ctx_tmpl = NULL;

retry:
	/* The pd is returned held */
	if ((pd = kcf_get_mech_provider(mech->cm_type, key, &me, &error,
	    list, CRYPTO_FG_SIGN, 0)) == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * it is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider.
	 */
	if ((pd->pd_prov_type == CRYPTO_SW_PROVIDER) &&
	    ((ctx_tmpl = (kcf_ctx_template_t *)tmpl) != NULL)) {
		if (ctx_tmpl->ct_generation != me->me_gen_swprov) {
			if (list != NULL)
				kcf_free_triedlist(list);
			KCF_PROV_REFRELE(pd);
			return (CRYPTO_OLD_CTX_TEMPLATE);
		} else {
			spi_ctx_tmpl = ctx_tmpl->ct_prov_tmpl;
		}
	}

	error = crypto_sign_init_prov(pd, pd->pd_sid, mech, key, spi_ctx_tmpl,
	    ctxp, crq);

	if (error != CRYPTO_SUCCESS && error != CRYPTO_QUEUED &&
	    IS_RECOVERABLE(error)) {
		/* Add pd to the linked list of providers tried. */
		if (kcf_insert_triedlist(&list, pd, KCF_KMFLAG(crq)) != NULL)
			goto retry;
	}

	if (list != NULL)
		kcf_free_triedlist(list);
	KCF_PROV_REFRELE(pd);
	return (error);
}

int
crypto_sign_single(crypto_context_t context, crypto_data_t *data,
    crypto_data_t *signature, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context;
	kcf_context_t *kcf_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_SINGLE, 0, NULL,
	    NULL, data, signature, NULL);
	error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

	/* Release the hold done in kcf_new_ctx() during init step. */
	KCF_CONTEXT_COND_RELEASE(error, kcf_ctx);
	return (error);
}

/*
 * See comments for crypto_digest_update().
 */
int
crypto_sign_update(crypto_context_t context, crypto_data_t *data,
    crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context;
	kcf_context_t *kcf_ctx;
	kcf_provider_desc_t *pd;
	kcf_req_params_t params;
	int rv;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);
	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_UPDATE, ctx->cc_session, NULL,
	    NULL, data, NULL, NULL);
	rv = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

	return (rv);
}

/*
 * See comments for crypto_digest_final().
 */
int
crypto_sign_final(crypto_context_t context, crypto_data_t *signature,
    crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context;
	kcf_context_t *kcf_ctx;
	kcf_provider_desc_t *pd;
	int rv;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	ASSERT(pd->pd_prov_type != CRYPTO_LOGICAL_PROVIDER);
	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_FINAL, ctx->cc_session, NULL,
	    NULL, NULL, signature, NULL);
	rv = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

	/* Release the hold done in kcf_new_ctx() during init step. */
	KCF_CONTEXT_COND_RELEASE(rv, kcf_ctx);
	return (rv);
}

int
crypto_sign_prov(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *key, crypto_data_t *data,
    crypto_ctx_template_t tmpl, crypto_data_t *signature,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_SIGN_ATOMIC);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}
	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_ATOMIC, sid, mech,
	    key, data, signature, tmpl);
	rv = kcf_submit_request(real_provider, NULL, crq, &params, B_FALSE);
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

static int
sign_sr_atomic_common(crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_data_t *data, crypto_ctx_template_t tmpl, crypto_data_t *signature,
    crypto_call_req_t *crq, crypto_func_group_t fg)
{
	int error;
	kcf_mech_entry_t *me;
	kcf_provider_desc_t *pd;
	kcf_req_params_t params;
	kcf_prov_tried_t *list = NULL;
	kcf_ctx_template_t *ctx_tmpl;
	crypto_spi_ctx_template_t spi_ctx_tmpl = NULL;

retry:
	/* The pd is returned held */
	if ((pd = kcf_get_mech_provider(mech->cm_type, key, &me, &error,
	    list, fg, data->cd_length)) == NULL) {
		if (list != NULL)
			kcf_free_triedlist(list);
		return (error);
	}

	/*
	 * For SW providers, check the validity of the context template
	 * It is very rare that the generation number mis-matches, so
	 * it is acceptable to fail here, and let the consumer recover by
	 * freeing this tmpl and create a new one for the key and new SW
	 * provider.
	 */
	if ((pd->pd_prov_type == CRYPTO_SW_PROVIDER) &&
	    ((ctx_tmpl = (kcf_ctx_template_t *)tmpl) != NULL)) {
		if (ctx_tmpl->ct_generation != me->me_gen_swprov) {
			if (list != NULL)
				kcf_free_triedlist(list);
			KCF_PROV_REFRELE(pd);
			return (CRYPTO_OLD_CTX_TEMPLATE);
		} else {
			spi_ctx_tmpl = ctx_tmpl->ct_prov_tmpl;
		}
	}

	/* The fast path for SW providers. */
	if (CHECK_FASTPATH(crq, pd)) {
		crypto_mechanism_t lmech;

		lmech = *mech;
		KCF_SET_PROVIDER_MECHNUM(mech->cm_type, pd, &lmech);
		if (fg == CRYPTO_FG_SIGN_ATOMIC)
			error = KCF_PROV_SIGN_ATOMIC(pd, pd->pd_sid, &lmech,
			    key, data, spi_ctx_tmpl, signature,
			    KCF_SWFP_RHNDL(crq));
		else
			error = KCF_PROV_SIGN_RECOVER_ATOMIC(pd, pd->pd_sid,
			    &lmech, key, data, spi_ctx_tmpl, signature,
			    KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, error);
	} else {
		kcf_op_type_t op = ((fg == CRYPTO_FG_SIGN_ATOMIC) ?
		    KCF_OP_ATOMIC : KCF_OP_SIGN_RECOVER_ATOMIC);

		KCF_WRAP_SIGN_OPS_PARAMS(&params, op, pd->pd_sid,
		    mech, key, data, signature, spi_ctx_tmpl);

		/* no crypto context to carry between multiple parts. */
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

	KCF_PROV_REFRELE(pd);
	return (error);
}

int
crypto_sign(crypto_mechanism_t *mech, crypto_key_t *key, crypto_data_t *data,
    crypto_ctx_template_t tmpl, crypto_data_t *signature,
    crypto_call_req_t *crq)
{
	return (sign_sr_atomic_common(mech, key, data, tmpl, signature, crq,
	    CRYPTO_FG_SIGN_ATOMIC));
}

int
crypto_sign_recover_prov(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *key, crypto_data_t *data,
    crypto_ctx_template_t tmpl, crypto_data_t *signature,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_SIGN_RECOVER_ATOMIC);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}
	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_SIGN_RECOVER_ATOMIC, sid, mech,
	    key, data, signature, tmpl);
	rv = kcf_submit_request(real_provider, NULL, crq, &params, B_FALSE);
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_sign_recover(crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_data_t *data, crypto_ctx_template_t tmpl, crypto_data_t *signature,
    crypto_call_req_t *crq)
{
	return (sign_sr_atomic_common(mech, key, data, tmpl, signature, crq,
	    CRYPTO_FG_SIGN_RECOVER_ATOMIC));
}

int
crypto_sign_recover_init_prov(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_ctx_template_t tmpl, crypto_context_t *ctxp, crypto_call_req_t *crq)
{
	int rv;
	crypto_ctx_t *ctx;
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_SIGN_RECOVER);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	/* Allocate and initialize the canonical context */
	if ((ctx = kcf_new_ctx(crq, real_provider, sid)) == NULL) {
		if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
			KCF_PROV_REFRELE(real_provider);
		return (CRYPTO_HOST_MEMORY);
	}

	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_SIGN_RECOVER_INIT, sid, mech,
	    key, NULL, NULL, tmpl);
	rv = kcf_submit_request(real_provider, ctx, crq, &params, B_FALSE);
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	if ((rv == CRYPTO_SUCCESS) || (rv == CRYPTO_QUEUED))
		*ctxp = (crypto_context_t)ctx;
	else {
		/* Release the hold done in kcf_new_ctx(). */
		KCF_CONTEXT_REFRELE((kcf_context_t *)ctx->cc_framework_private);
	}

	return (rv);
}

int
crypto_sign_recover_single(crypto_context_t context, crypto_data_t *data,
    crypto_data_t *signature, crypto_call_req_t *cr)
{
	crypto_ctx_t *ctx = (crypto_ctx_t *)context;
	kcf_context_t *kcf_ctx;
	kcf_provider_desc_t *pd;
	int error;
	kcf_req_params_t params;

	if ((ctx == NULL) ||
	    ((kcf_ctx = (kcf_context_t *)ctx->cc_framework_private) == NULL) ||
	    ((pd = kcf_ctx->kc_prov_desc) == NULL)) {
		return (CRYPTO_INVALID_CONTEXT);
	}

	KCF_WRAP_SIGN_OPS_PARAMS(&params, KCF_OP_SIGN_RECOVER, 0, NULL,
	    NULL, data, signature, NULL);
	error = kcf_submit_request(pd, ctx, cr, &params, B_FALSE);

	/* Release the hold done in kcf_new_ctx() during init step. */
	KCF_CONTEXT_COND_RELEASE(error, kcf_ctx);
	return (error);
}
