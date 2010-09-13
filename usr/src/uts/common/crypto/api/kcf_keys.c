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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/api.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/sched_impl.h>

#define	CRYPTO_OPS_OFFSET(f)		offsetof(crypto_ops_t, co_##f)
#define	CRYPTO_KEY_OFFSET(f)		offsetof(crypto_key_ops_t, f)

int
crypto_key_generate(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_object_attribute_t *attrs, uint_t count,
    crypto_object_id_t *handle, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, NULL,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_GENERATE);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_KEY_GENERATE(real_provider, sid,
		    mech, attrs, count, handle, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE, sid,
		    mech, attrs, count, handle, NULL, 0, NULL, NULL, NULL, 0);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_key_generate_pair(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_object_attribute_t *pub_attrs,
    uint_t pub_count, crypto_object_attribute_t *pri_attrs, uint_t pri_count,
    crypto_object_id_t *pub_handle, crypto_object_id_t *pri_handle,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, NULL,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_GENERATE_KEY_PAIR);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_KEY_GENERATE_PAIR(real_provider, sid, mech,
		    pub_attrs, pub_count, pri_attrs, pri_count, pub_handle,
		    pri_handle, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE_PAIR,
		    sid, mech, pub_attrs, pub_count, pub_handle, pri_attrs,
		    pri_count, pri_handle, NULL, NULL, 0);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_key_wrap(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *wrapping_key,
    crypto_object_id_t *key, uchar_t *wrapped_key, size_t *wrapped_key_len,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, wrapping_key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_WRAP);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_KEY_WRAP(real_provider, sid, mech, wrapping_key,
		    key, wrapped_key, wrapped_key_len, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_WRAP, sid, mech,
		    NULL, 0, key, NULL, 0, NULL, wrapping_key, wrapped_key,
		    wrapped_key_len);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_key_unwrap(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *unwrapping_key,
    uchar_t *wrapped_key, size_t *wrapped_key_len,
    crypto_object_attribute_t *attrs, uint_t count, crypto_object_id_t *key,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, unwrapping_key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_UNWRAP);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_KEY_UNWRAP(real_provider, sid, mech,
		    unwrapping_key, wrapped_key, wrapped_key_len, attrs,
		    count, key, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_UNWRAP, sid, mech,
		    attrs, count, key, NULL, 0, NULL, unwrapping_key,
		    wrapped_key, wrapped_key_len);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_key_derive(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_mechanism_t *mech, crypto_key_t *base_key,
    crypto_object_attribute_t *attrs, uint_t count,
    crypto_object_id_t *new_key, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider(mech->cm_type, base_key,
		    CRYPTO_MECH_INVALID, NULL, pd, &real_provider,
		    CRYPTO_FG_DERIVE);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_KEY_DERIVE(real_provider, sid, mech, base_key,
		    attrs, count, new_key, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_DERIVE, sid, mech,
		    attrs, count, new_key, NULL, 0, NULL, base_key, NULL, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}
