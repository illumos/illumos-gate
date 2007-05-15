/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <des_int.h>
#include <sys/crypto/api.h>

#include <sys/callb.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>

int
k5_ef_crypto(const char *in, char *out,
	long length, krb5_keyblock *key,
	const krb5_data *ivec, int encrypt_flag)
{
	int rv = CRYPTO_FAILED;

	crypto_mechanism_t mech;
	crypto_data_t d1, d2;

	ASSERT(in != NULL);
	ASSERT(out != NULL);
	ASSERT(key != NULL);
	ASSERT(key->contents != NULL);

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = length;
	d1.cd_raw.iov_base = (char *)in;
	d1.cd_raw.iov_len = length;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = length;
	d2.cd_raw.iov_base = (char *)out;
	d2.cd_raw.iov_len = length;

	mech.cm_type = key->kef_mt;
	if (mech.cm_type == CRYPTO_MECH_INVALID) {
		KRB5_LOG(KRB5_ERR,
		    "k5_ef_crypto - invalid crypto mech type: 0x%llx",
		    (long long)key->kef_mt);
		return (CRYPTO_FAILED);
	}

	if (ivec != NULL) {
		mech.cm_param_len = ivec->length;
		mech.cm_param = (char *)ivec->data;
	} else {
		mech.cm_param_len = 0;
		mech.cm_param = NULL;
	}

	if (encrypt_flag)
		rv = crypto_encrypt(&mech, &d1,
				    &key->kef_key,
				    key->key_tmpl,
				    (in != out ? &d2 : NULL),
				    NULL);
	else
		rv = crypto_decrypt(&mech, &d1,
				    &key->kef_key,
				    key->key_tmpl,
				    (in != out ? &d2 : NULL),
				    NULL);

	if (rv != CRYPTO_SUCCESS) {
		KRB5_LOG1(KRB5_ERR,
			"k5_ef_crypto: %s error: rv = 0x%08x",
			(encrypt_flag ? "encrypt" : "decrypt"),
			rv);
		return (CRYPTO_FAILED);
	}

	return (0);
}
