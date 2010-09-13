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
#define	CRYPTO_SESSION_OFFSET(f)	offsetof(crypto_session_ops_t, f)

int
crypto_session_open(crypto_provider_t provider, crypto_session_id_t *sidp,
crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *real_provider;
	kcf_provider_desc_t *pd = provider;

	ASSERT(KCF_PROV_REFHELD(pd));

	/* find a provider that supports session ops */
	(void) kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(session_ops),
	    CRYPTO_SESSION_OFFSET(session_open), pd, &real_provider);

	if (real_provider != NULL) {
		int rv;

		ASSERT(real_provider == pd ||
		    pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER);

		if (CHECK_FASTPATH(crq, pd)) {
			rv = KCF_PROV_SESSION_OPEN(real_provider, sidp,
			    KCF_SWFP_RHNDL(crq), pd);
			KCF_PROV_INCRSTATS(pd, rv);
		} else {
			KCF_WRAP_SESSION_OPS_PARAMS(&params,
			    KCF_OP_SESSION_OPEN, sidp, 0, CRYPTO_USER, NULL,
			    0, pd);
			rv = kcf_submit_request(real_provider, NULL, crq,
			    &params, B_FALSE);
		}
		KCF_PROV_REFRELE(real_provider);

		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}
	return (CRYPTO_SUCCESS);
}

int
crypto_session_close(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_call_req_t *crq)
{
	int rv;
	kcf_req_params_t params;
	kcf_provider_desc_t *real_provider;
	kcf_provider_desc_t *pd = provider;

	if (pd == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	ASSERT(KCF_PROV_REFHELD(pd));

	/* find a provider that supports session ops */
	(void) kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(session_ops),
	    CRYPTO_SESSION_OFFSET(session_close), pd, &real_provider);

	ASSERT(real_provider == pd ||
	    pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER);

	/* edge case is where the logical provider has no members */
	if (real_provider != NULL) {
		/* The fast path for SW providers. */
		if (CHECK_FASTPATH(crq, pd)) {
			rv = KCF_PROV_SESSION_CLOSE(real_provider,
			    sid, KCF_SWFP_RHNDL(crq), pd);
			KCF_PROV_INCRSTATS(pd, rv);
		} else {
			KCF_WRAP_SESSION_OPS_PARAMS(&params,
			    KCF_OP_SESSION_CLOSE, NULL, sid,
			    CRYPTO_USER, NULL, 0, pd);
			rv = kcf_submit_request(real_provider, NULL, crq,
			    &params, B_FALSE);
		}
		KCF_PROV_REFRELE(real_provider);
	}
	return (CRYPTO_SUCCESS);
}

int
crypto_session_login(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_user_type_t type, char *pin, ulong_t len, crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    session_ops), CRYPTO_SESSION_OFFSET(session_login),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_SESSION_LOGIN(real_provider, sid,
		    type, pin, len, KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_LOGIN,
		    NULL, sid, type, pin, len, real_provider);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}

int
crypto_session_logout(crypto_provider_t provider, crypto_session_id_t sid,
    crypto_call_req_t *crq)
{
	kcf_req_params_t params;
	kcf_provider_desc_t *pd = provider;
	kcf_provider_desc_t *real_provider = pd;
	int rv;

	ASSERT(KCF_PROV_REFHELD(pd));

	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER) {
		rv = kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(
		    session_ops), CRYPTO_SESSION_OFFSET(session_logout),
		    pd, &real_provider);

		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}

	if (CHECK_FASTPATH(crq, real_provider)) {
		rv = KCF_PROV_SESSION_LOGOUT(real_provider, sid,
		    KCF_SWFP_RHNDL(crq));
		KCF_PROV_INCRSTATS(pd, rv);
	} else {
		KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_LOGOUT,
		    NULL, sid, 0, NULL, 0, real_provider);
		rv = kcf_submit_request(real_provider, NULL, crq,
		    &params, B_FALSE);
	}
	if (pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER)
		KCF_PROV_REFRELE(real_provider);

	return (rv);
}
