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
#define	CRYPTO_OBJECT_OFFSET(f)		offsetof(crypto_object_ops_t, f)

int
crypto_object_create(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_object_attribute_t *attrs, uint_t count,
    crypto_object_id_t *object_handle, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_create),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_CREATE(real_provider, sid,
		    attrs, count, object_handle, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_CREATE,
		    sid, 0, attrs, count, object_handle, 0,
		    NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_destroy(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_object_id_t object_handle, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_destroy),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_DESTROY(real_provider, sid,
		    object_handle, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_DESTROY,
		    sid, object_handle, NULL, 0, NULL, 0,
		    NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_copy(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_object_id_t object_handle, crypto_object_attribute_t *attrs,
    uint_t count, crypto_object_id_t *new_handle, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_copy),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_COPY(real_provider, sid,
		    object_handle, attrs, count, new_handle,
		    KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_COPY,
		    sid, object_handle, attrs, count,
		    new_handle, 0, NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_get_attribute_value(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_object_id_t object_handle,
    crypto_object_attribute_t *attrs, uint_t count, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops),
		    CRYPTO_OBJECT_OFFSET(object_get_attribute_value),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_GET_ATTRIBUTE_VALUE(real_provider,
		    sid, object_handle, attrs, count, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params,
		    KCF_OP_OBJECT_GET_ATTRIBUTE_VALUE, sid, object_handle,
		    attrs, count, NULL, 0, NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_set_attribute_value(crypto_provider_t provider,
    crypto_session_id_t sid, crypto_object_id_t object_handle,
    crypto_object_attribute_t *attrs, uint_t count, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops),
		    CRYPTO_OBJECT_OFFSET(object_set_attribute_value),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_SET_ATTRIBUTE_VALUE(real_provider,
		    sid, object_handle, attrs, count, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params,
		    KCF_OP_OBJECT_SET_ATTRIBUTE_VALUE, sid, object_handle,
		    attrs, count, NULL, 0, NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_get_size(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_object_id_t object_handle, size_t *size, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_get_size),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);

	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_GET_SIZE(real_provider,
		    sid, object_handle, size, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_GET_SIZE, sid,
		    object_handle, NULL, 0, NULL, size, NULL, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_find_init(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_object_attribute_t *attrs, uint_t count, void **cookie,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (cookie == NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_find_init),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_FIND_INIT(real_provider,
		    sid, attrs, count, cookie, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND_INIT,
		    sid, 0, attrs, count, NULL, 0, cookie, NULL, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_find_final(crypto_provider_t provider, void *cookie,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_find_final),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_FIND_FINAL(real_provider,
		    cookie, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND_FINAL,
		    0, 0, NULL, 0, NULL, 0, NULL, cookie, 0, NULL);
		rv = kcf_submit_request(real_provider, NULL, NULL, &params,
		    B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_object_find(crypto_provider_t provider, void *cookie,
    crypto_object_id_t *handles, uint_t *count, uint_t max_count,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    object_ops), CRYPTO_OBJECT_OFFSET(object_find),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_OBJECT_FIND(real_provider, cookie, handles,
		    max_count, count, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND, 0,
		    0, NULL, 0, handles, 0, NULL, cookie, max_count, count);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}
