/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>

#include <sys/crypto/api.h>

#include <sys/callb.h>
#include <sys/uio.h>

int
k5_ef_hash(krb5_context context, int icount,
	const krb5_data *input,
	krb5_data *output)
{
	int i;
	int rv = CRYPTO_FAILED;
	iovec_t v1, v2;
	crypto_data_t d1, d2;
	crypto_mechanism_t mech;
	crypto_context_t ctxp;

	KRB5_LOG0(KRB5_INFO, "k5_ef_hash() start");

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	v2.iov_base = (void *)output->data;
	v2.iov_len = output->length;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = output->length;
	d2.cd_raw = v2;

	mech.cm_type = context->kef_cksum_mt;
	if (mech.cm_type == CRYPTO_MECH_INVALID) {
		KRB5_LOG(KRB5_ERR,
			"k5_ef_hash() invalid mech specified: 0x%llx",
			(long long)context->kef_hash_mt);
		return (CRYPTO_FAILED);
	}
	mech.cm_param = 0;
	mech.cm_param_len = 0;

	rv = crypto_digest_init(&mech, &ctxp, NULL);
	if (rv != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR, "crypto_digest_init error: %0x", rv);
		return (rv);
	}

	for (i = 0; i < icount; i++) {
		v1.iov_base = (void *)input[i].data;
		v1.iov_len = input[i].length;
		d1.cd_length = input[i].length;
		d1.cd_format = CRYPTO_DATA_RAW;
		d1.cd_offset = 0;
		d1.cd_raw = v1;

		rv = crypto_digest_update(ctxp, &d1, NULL);
		if (rv != CRYPTO_SUCCESS) {
			KRB5_LOG(KRB5_ERR,
				"crypto_digest_update error: %0x", rv);
			crypto_cancel_ctx(ctxp);
			return (rv);
		}
	}

	rv = crypto_digest_final(ctxp, &d2, NULL);
	/*
	 * crypto_digest_final() internally destroys the context. So, we
	 * do not use the context any more. This means we do not call
	 * crypto_cancel_ctx() for the failure case here unlike the failure
	 * case of crypto_digest_update() where we do.
	 */
	if (rv != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR, "crypto_digest_final error: %0x", rv);
	}

	return (rv);
}

int
k5_ef_mac(krb5_context context,
	krb5_keyblock *key,
	krb5_data *ivec,
	const krb5_data *input,
	krb5_data *output)
{
	int rv;
	iovec_t v1, v2;
	crypto_data_t d1, d2;
	crypto_mechanism_t mech;

	KRB5_LOG0(KRB5_INFO, "k5_ef_mac() start");

	ASSERT(input != NULL);
	ASSERT(ivec != NULL);
	ASSERT(output != NULL);

	v2.iov_base = (void *)output->data;
	v2.iov_len = output->length;

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = output->length;
	d2.cd_raw = v2;

	mech.cm_type = context->kef_hash_mt;
	if (mech.cm_type == CRYPTO_MECH_INVALID) {
		KRB5_LOG(KRB5_ERR,
			"k5_ef_mac() invalid mech specified: 0x%llx",
			(long long)context->kef_hash_mt);
		return (CRYPTO_FAILED);
	}

	mech.cm_param = ivec->data;
	mech.cm_param_len = ivec->length;

	v1.iov_base = (void *)input->data;
	v1.iov_len = input->length;

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = input->length;
	d1.cd_raw = v1;

	rv = crypto_mac(&mech, &d1, &key->kef_key, key->key_tmpl, &d2, NULL);
	if (rv != CRYPTO_SUCCESS) {
		KRB5_LOG(KRB5_ERR,
			"k5_ef_mac(): crypto_mac error: %0x", rv);
	}

	return (rv);
}
