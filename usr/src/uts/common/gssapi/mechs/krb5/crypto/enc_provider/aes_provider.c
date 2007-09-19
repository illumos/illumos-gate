/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * Note, this file is cstyle and lint clean and should stay that way.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#include <k5-int.h>
#include <enc_provider.h>

#define	BLOCK_SIZE 16

/*
 * AES encrypt using CipherText Stealing mode built on top of CBC mode.  CBC is
 * being used because the Solaris Cryptographic Framework/PKCS11 does not
 * currently support CTS while CBC is supported.  CBC as compared to ECB that
 * was previously used allows crypto providers to do the crypto more
 * efficiently.  In addition there is a crypto card (SCA6000) that did not
 * provide ECB mode so krb was unable to take advantage.  If CTS mode is ever
 * supported by the Solaris Cryptographic Framework then this code should be
 * changed to use that.
 *
 * CTS is based on what is described in Schneier's Applied Cryptography and RFC
 * 3962.
 */

#ifdef _KERNEL
/*ARGSUSED*/
krb5_error_code
krb5int_aes_encrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
	int ret = 0;
	int nblocks, partialamount;
	crypto_mechanism_t mech;
	/*
	 * nlobp = next to last output block pointer, lobp = last output block
	 * pointer
	 */
	char *nlobp, *lobp;
	char local_iv_data[BLOCK_SIZE];
	krb5_data local_iv;

	KRB5_LOG0(KRB5_INFO, "In krb5int_aes_encrypt(kernel): start");

	ASSERT(input != NULL);
	ASSERT(output != NULL);
	ASSERT(input->length == output->length);
	ASSERT(key != NULL);
	ASSERT(key->key_tmpl != NULL);
	ASSERT(key->kef_mt == crypto_mech2id(SUN_CKM_AES_CBC));

	if (ivec != NULL) {
		/*
		 * This function updates ivec->data if the ivec is passed in so
		 * it better have a data pointer and a proper length.
		 */
		if (ivec->data == NULL || ivec->length != BLOCK_SIZE) {
			ASSERT(ivec->data != NULL);
			ASSERT(ivec->length == BLOCK_SIZE);
			KRB5_LOG1(KRB5_ERR, "In krb5int_aes_encrypt: error "
			    "ivec->data = %p ivec->length = %d",
			    (void *)ivec->data, ivec->length);
			ret = KRB5_CRYPTO_INTERNAL;
			goto cleanup;
		}
	}

	/* number of input blocks including partial block */
	nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "nblocks = %d", nblocks);
	/* get # of bytes in partially filled block */
	partialamount = input->length % BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "partialamount = %d", partialamount);

	if (nblocks == 1 || (partialamount == 0)) {
		/*
		 * Simple case:
		 *
		 * Use CBC for all plaintext blocks, all must be full, then swap
		 * last 2 ciphertext blocks to implement CTS.  Note, CBC needs a
		 * non-NULL IV.
		 */
		if (ivec != NULL) {
			local_iv.data = ivec->data;
			local_iv.length = ivec->length;
		} else {
			bzero(local_iv_data, sizeof (local_iv_data));
			local_iv.data = local_iv_data;
			local_iv.length = sizeof (local_iv_data);
		}
		/*
		 * XXX due to a bug in the previous version of this function,
		 * input data that was 1 block long was decrypted instead of
		 * encypted.  The fix for that is in another CR so until then
		 * we'll continue the tradition for interop's sake.
		 */
		ret = k5_ef_crypto((const char *)input->data,
			(char *)output->data,
			input->length, (krb5_keyblock *)key,
			&local_iv, (nblocks == 1 ? FALSE : TRUE));

		if (ret != 0) {
			KRB5_LOG(KRB5_ERR,
				"k5_ef_crypto: error: ret = 0x%08x",
				ret);
			goto cleanup;
		}

		if (nblocks > 1) {
			/*
			 * swap last 2 ciphertext blocks to implement CTS
			 */
			char tmp[BLOCK_SIZE];

			nlobp = (char *)(output->data +
			    ((nblocks - 2) * BLOCK_SIZE));
			lobp = (char *)(output->data +
			    ((nblocks - 1) * BLOCK_SIZE));

			bcopy(nlobp, tmp, BLOCK_SIZE);
			bcopy(lobp, nlobp, BLOCK_SIZE);
			bcopy(tmp, lobp, BLOCK_SIZE);
		}
	} else {
		/*
		 * Complex case:
		 *
		 * This implements CTS mode where there is > 1 block and the
		 * last block is partially filled Uses CBC mode in the kCF, then
		 * does some swapping.
		 *
		 * pt = plain text, ct = cipher text
		 */
		char tmp_pt[BLOCK_SIZE], tmp_ct[BLOCK_SIZE];
		/* Note the iovec below is NOT the ivec in the crypto sense */
		struct iovec iovarray_pt[2], iovarray_ct[2];
		struct uio uio_pt, uio_ct;
		/* ct = ciphertext, pt = plaintext */
		crypto_data_t ct, pt;

		/* tmp_pt will provide 0 padding for last parital pt block */
		bzero(tmp_pt, sizeof (tmp_pt));

		/*
		 * Setup the uio/iovecs so only one call to crypto_encrypt() is
		 * made.  Plaintext first.
		 */
		pt.cd_format = CRYPTO_DATA_UIO;
		pt.cd_offset = 0;
		pt.cd_length = nblocks * BLOCK_SIZE;
		pt.cd_miscdata = NULL;
		bzero(&uio_pt, sizeof (uio_pt));
		pt.cd_uio = &uio_pt;
		pt.cd_uio->uio_iov = iovarray_pt;
		pt.cd_uio->uio_iovcnt = 2;
		pt.cd_uio->uio_segflg = UIO_SYSSPACE;

		/*
		 * first iovec has all full blocks of pt.
		 */
		pt.cd_uio->uio_iov[0].iov_base = (char *)input->data;
		/* use full block input */
		pt.cd_uio->uio_iov[0].iov_len = input->length - partialamount;

		KRB5_LOG(KRB5_INFO, "pt0 iov_len = %d",
		    (int)pt.cd_uio->uio_iov[0].iov_len);

		/*
		 * second iovec has the parital pt and 0 padding
		 */
		pt.cd_uio->uio_iov[1].iov_base = tmp_pt;
		/*
		 * since the first iovec includes the last partial pt,
		 * set length to enough bytes to pad out to a full block
		 */
		bcopy(input->data + (input->length - partialamount), tmp_pt,
		    partialamount);
		pt.cd_uio->uio_iov[1].iov_len = BLOCK_SIZE;

		/* setup ciphertext iovecs */
		ct.cd_format = CRYPTO_DATA_UIO;
		ct.cd_offset = 0;
		ct.cd_length = nblocks * BLOCK_SIZE;
		ct.cd_miscdata = NULL;
		bzero(&uio_ct, sizeof (uio_ct));
		ct.cd_uio = &uio_ct;
		ct.cd_uio->uio_iov = iovarray_ct;
		ct.cd_uio->uio_iovcnt = 2;
		ct.cd_uio->uio_segflg = UIO_SYSSPACE;

		/*
		 * First iovec has almost all the ct but not the ct for the last
		 * partial pt with the padding.  That will be stored in the
		 * secont ct iovec.
		 */
		ct.cd_uio->uio_iov[0].iov_base = (char *)output->data;
		ct.cd_uio->uio_iov[0].iov_len = output->length - partialamount;
		KRB5_LOG(KRB5_INFO, "ct0 iov_len = %d",
		    (int)ct.cd_uio->uio_iov[0].iov_len);
		/*
		 * Second iovec has the last ciphertext block
		 */
		ct.cd_uio->uio_iov[1].iov_base = tmp_ct;
		ct.cd_uio->uio_iov[1].iov_len = BLOCK_SIZE;

		/* This had better be AES CBC mode! */
		mech.cm_type = key->kef_mt;

		if (ivec == NULL) {
			bzero(local_iv_data, sizeof (local_iv_data));
			mech.cm_param = local_iv_data;
			mech.cm_param_len = sizeof (local_iv_data);
		} else {
			mech.cm_param = ivec->data;
			mech.cm_param_len = ivec->length;
		}

		/* encrypt using AES CBC */
		ret = crypto_encrypt(&mech, &pt, (crypto_key_t *)&key->kef_key,
					key->key_tmpl, &ct, NULL);

		if (ret != CRYPTO_SUCCESS) {
		    KRB5_LOG(KRB5_ERR,
			    "crypto_encrypt: error: ret = 0x%08x",
			    ret);
		    goto cleanup;
		}

		/*
		 * Swap:
		 * copy the next to last ct to last partial output block (only
		 * the partial amount is copied).
		 */
		nlobp = (char *)(output->data + ((nblocks - 2) * BLOCK_SIZE));
		lobp = (char *)(output->data + ((nblocks - 1) * BLOCK_SIZE));

		bcopy(nlobp, lobp, partialamount);
		/*
		 * copy the last ct output block to next to last output block
		 */
		bcopy(tmp_ct, nlobp, BLOCK_SIZE);

	} /* end partial block processing */

	/*
	 * The ivec is updated to allow the caller to chain ivecs.  At this
	 * point I don't think any kernel callers are using this however the
	 * userland version of this function does it so this should be done in
	 * kernel for consistency's sake.  This is not done for 1 block, got
	 * this from MIT.  Note, the next to last output block is copied because
	 * it contains the last full block of cipher text.
	 */
	if (nblocks > 1 && ivec)
		(void) memcpy(ivec->data, nlobp, BLOCK_SIZE);

cleanup:
	if (ret)
		bzero(output->data, output->length);
	return (ret);
}

#else /* User Space */

/*ARGSUSED*/
krb5_error_code
krb5int_aes_encrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
	krb5_error_code ret = 0;
	int nblocks, partialamount;
	CK_RV rv;
	KRB5_MECH_TO_PKCS algos;
	CK_MECHANISM mechanism;
	CK_ULONG outlen;
	/*
	 * nlobp = next to last output block pointer, lobp = last output block
	 * pointer
	 */
	char *nlobp, *lobp;
	char tmp_ivec[BLOCK_SIZE];

	assert(input != NULL);
	assert(output != NULL);
	assert(input->length == output->length);
	assert(key != NULL);

	if (ivec != NULL) {
		/*
		 * This function updates ivec->data if the ivec is passed in so
		 * it better have a data pointer and a proper length.
		 */
		if (ivec->data == NULL || ivec->length != BLOCK_SIZE) {
			assert(ivec->data != NULL);
			assert(ivec->length == BLOCK_SIZE);
			KRB5_LOG1(KRB5_ERR, "In krb5int_aes_encrypt: error "
			    "ivec->data = %p ivec->length = %d", ivec->data,
			    ivec->length);
			ret = KRB5_CRYPTO_INTERNAL;
			goto cleanup;
		}
	}

	/* number of input blocks including partial block */
	nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "nblocks = %d", nblocks);
	/* get # of bytes in partially filled block */
	partialamount = input->length % BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "partialamount = %d", partialamount);

	rv = get_algo(key->enctype, &algos);
	if (rv != CKR_OK)
		goto cleanup;
	assert(algos.enc_algo == CKM_AES_CBC);

	rv = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key);
	if (rv != CKR_OK)
		goto cleanup;

	mechanism.mechanism = algos.enc_algo;

	if (ivec == NULL) {
		bzero(tmp_ivec, sizeof (tmp_ivec));
		mechanism.pParameter = tmp_ivec;
		mechanism.ulParameterLen = sizeof (tmp_ivec);
	} else {
		mechanism.pParameter = ivec->data;
		mechanism.ulParameterLen = ivec->length;
	}
	/*
	 * Note, since CBC is assumed to be the underlying mode, this
	 * call to C_EncryptInit is setting the IV.  The IV in use here
	 * is either the ivec passed in or a block of 0's.
	 */
	rv = C_EncryptInit(krb_ctx_hSession(context), &mechanism, key->hKey);

	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_EncryptInit failed in "
		    "krb5int_aes_encrypt: rv = 0x%x", rv);
		goto cleanup;
	}

	if (nblocks == 1 || (partialamount == 0)) {
		/*
		 * Simple case:
		 *
		 * Use CBC for all plaintext blocks, all must be full, then swap
		 * last 2 ciphertext blocks to implement CTS.
		 */

		/*
		 * C_Encrypt/Decrypt requires a pointer to long, not a pointer
		 * to int cast to pointer to long!!!
		 */
		outlen = output->length;

		rv = C_Encrypt(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)input->data,
			    input->length,
			    (CK_BYTE_PTR)output->data,
			    &outlen);

		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_Encrypt failed in "
			    "krb5int_aes_encrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		assert(output->length == (unsigned int)outlen);

		if (nblocks > 1) {
			/*
			 * swap last 2 ciphertext blocks to implement CTS
			 */
			char tmp[BLOCK_SIZE];

			nlobp = (char *)(output->data +
				((nblocks - 2) * BLOCK_SIZE));
			lobp = (char *)(output->data +
				((nblocks - 1) * BLOCK_SIZE));

			bcopy(nlobp, tmp, BLOCK_SIZE);
			bcopy(lobp, nlobp, BLOCK_SIZE);
			bcopy(tmp, lobp, BLOCK_SIZE);
		}
	} else {
		/*
		 * Complex case:
		 *
		 * This implements CTS mode where there is > 1 block and the
		 * last block is partially filled. Uses CBC mode in uCF/PKCS11,
		 * then does some swapping.
		 *
		 * pt = plain text, ct = cipher text
		 */
		char tmp_pt[BLOCK_SIZE], tmp_ct[BLOCK_SIZE];

		/*
		 * encrypt from P0...Pn-1 using CBC, last block of output is Cn
		 * & C'
		 */
		outlen = input->length - partialamount;

		rv = C_EncryptUpdate(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)input->data,
			    input->length - partialamount,
			    (CK_BYTE_PTR)output->data,
			    &outlen);

		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_EncryptUpdate failed in "
			    "krb5int_aes_encrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		/* tmp_pt will provide 0 padding for last parital pt block */
		bzero(tmp_pt, sizeof (tmp_pt));
		/* copy Pn to tmp_pt which has 0 padding */
		bcopy(input->data + (input->length - partialamount), tmp_pt,
		    partialamount);

		/* encrypt Pn with 0 padding, Cn & C' ivec, output is Cn-1 */
		outlen = sizeof (tmp_ct);

		rv = C_EncryptUpdate(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)tmp_pt,
			    BLOCK_SIZE,
			    (CK_BYTE_PTR)tmp_ct,
			    &outlen);

		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_Encrypt failed in "
			    "krb5int_aes_encrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		nlobp = (char *)(output->data + ((nblocks - 2) * BLOCK_SIZE));
		lobp = (char *)(output->data + ((nblocks - 1) * BLOCK_SIZE));

		/* copy Cn from next to last output block to last block */
		bcopy(nlobp, lobp, partialamount);
		/* copy Cn-1 from tmp_ct to next to last output block */
		bcopy(tmp_ct, nlobp, BLOCK_SIZE);

		/* Close the crypto session, ignore the output */
		rv = C_EncryptFinal(krb_ctx_hSession(context),
			(CK_BYTE_PTR)tmp_ct, &outlen);

		if (rv != CKR_OK)
			goto cleanup;
	}
	/*
	 * The ivec is updated to allow the caller to chain ivecs, done for the
	 * kcmd (rsh/rcp/etc...).  Note this is not done for 1 block although I
	 * am not sure why but I'm continuing the tradition from the MIT code.
	 * Note, the next to last output block is copied because it contains the
	 * last full block of cipher text.
	 */
	if (nblocks > 1 && ivec)
		(void) memcpy(ivec->data, nlobp, BLOCK_SIZE);

cleanup:
	if (rv != CKR_OK)
		ret = PKCS_ERR;

	if (ret)
		bzero(output->data, input->length);

	return (ret);
}
#endif /* _KERNEL */

/*
 * AES Decrypt using CipherText Stealing mode built on top of CBC mode.  See the
 * krb5int_aes_encrypt() comments for the reason CBC is being used.
 */

#ifdef _KERNEL
/*ARGSUSED*/
krb5_error_code
krb5int_aes_decrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
	krb5_error_code ret = 0;
	int nblocks, partialamount;
	char local_iv_data[BLOCK_SIZE];
	krb5_data local_iv;

	KRB5_LOG0(KRB5_INFO, "In krb5int_aes_decrypt: start");

	ASSERT(input != NULL);
	ASSERT(output != NULL);
	ASSERT(input->length == output->length);
	ASSERT(key != NULL);
	ASSERT(key->kef_mt == crypto_mech2id(SUN_CKM_AES_CBC));

	if (ivec != NULL) {
		/*
		 * This function updates ivec->data if the ivec is passed in so
		 * it better have a data pointer and a proper length.
		 */
		if (ivec->data == NULL || ivec->length != BLOCK_SIZE) {
			ASSERT(ivec->data != NULL);
			ASSERT(ivec->length == BLOCK_SIZE);
			KRB5_LOG1(KRB5_ERR, "In krb5int_aes_decrypt: error "
			    "ivec->data = %p ivec->length = %d",
			    (void *)ivec->data, ivec->length);
			ret = KRB5_CRYPTO_INTERNAL;
			goto cleanup;
		}
	}

	/* number of input blocks including partial block */
	nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "nblocks = %d", nblocks);
	/* get # of bytes in partially filled block */
	partialamount = input->length % BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "partialamount = %d", partialamount);

	if (ivec != NULL) {
		local_iv.data = ivec->data;
		local_iv.length = ivec->length;
	} else {
		bzero(local_iv_data, sizeof (local_iv_data));
		local_iv.data = local_iv_data;
		local_iv.length = sizeof (local_iv_data);
	}

	if (nblocks == 1 || (partialamount == 0)) {
		char orig_input[BLOCK_SIZE * 2];
		/*
		 * nlibp = next to last input block pointer
		 * libp = last input block pointer
		 */
		char *nlibp, *libp;

		/*
		 * Simple case:
		 *
		 * Swap last 2 ciphertext blocks (all must be full), then use
		 * CBC to implement CTS.
		 */

		if (nblocks > 1) {
			/*
			 * swap last 2 ciphertext blocks to implement CTS
			 */
			char tmp[BLOCK_SIZE];

			nlibp = input->data + ((nblocks - 2) * BLOCK_SIZE);
			libp = input->data + ((nblocks - 1) * BLOCK_SIZE);

			/* first save orig input data for later restore */
			/* we know that partial amount is 0, because */
			/* nblocks is > 1, so we copy the last two blocks */
			bcopy(nlibp, orig_input, sizeof (orig_input));

			/* swap */
			bcopy(nlibp, tmp, BLOCK_SIZE);
			bcopy(libp, nlibp, BLOCK_SIZE);
			bcopy(tmp, libp, BLOCK_SIZE);
		}

		ret = k5_ef_crypto((const char *)input->data,
			(char *)output->data,
			input->length, (krb5_keyblock *)key,
			&local_iv, FALSE);

		if (nblocks > 1) {
			/* restore orig input data */
			bcopy(orig_input, nlibp, sizeof (orig_input));
		}

		if (ret != 0) {
		    KRB5_LOG(KRB5_ERR,
			    "k5_ef_crypto returned error: ret = 0x%08x",
			    ret);
		    goto cleanup;
		}

	} else {
		krb5_data tmp_ivec;
		char tmp_ivec_data[BLOCK_SIZE], tmp_input_data[BLOCK_SIZE],
			tmp_output_data[BLOCK_SIZE];
		/* pointers to Cn, Cn-1, Cn-2 CipherText */
		char *Cn, *Cn_1, *Cn_2;
		long length;

		/*
		 * Complex case:
		 *
		 * Decrypting in CTS where there is a partial block of
		 * ciphertext.
		 */

		/* setting pointers to CipherText for later use */
		Cn = input->data + (input->length - partialamount);
		/* Cn - 1 */
		Cn_1 = Cn - BLOCK_SIZE;
		/* Cn - 2 */
		Cn_2 = Cn_1 - BLOCK_SIZE;

		if (nblocks > 2) {
			/* set length to include blocks C0 thru Cn-2 */
			length = input->length - (BLOCK_SIZE + partialamount);

			/*
			 * First decrypt C0 thru Cn-2 using CBC with the input
			 * ivec.
			 */
			ret = k5_ef_crypto((const char *)input->data,
				output->data, length, (krb5_keyblock *)key,
				&local_iv, FALSE);

			if (ret != 0) {
			    KRB5_LOG(KRB5_ERR,
				    "k5_ef_crypto: error: ret = 0x%08x",
				    ret);
			    goto cleanup;
			}
		}
		/*
		 * Prepare to decrypt Cn-1 using a ivec of Cn with 0 padding.
		 */
		bzero(tmp_ivec_data, sizeof (tmp_ivec_data));
		/* the tmp ivec data holds Cn with 0 padding */
		bcopy(Cn, tmp_ivec_data, partialamount);
		tmp_ivec.data = tmp_ivec_data;
		tmp_ivec.length = sizeof (tmp_ivec_data);

		/* decrypt 1 block */
		length = BLOCK_SIZE;

		/*
		 * Now decrypt using Cn-1 input, Cn + 0 padding for ivec, Pn &
		 * C' output
		 */
		ret = k5_ef_crypto((const char *)Cn_1,
		    tmp_output_data, length,
		    (krb5_keyblock *)key, &tmp_ivec, FALSE);

		if (ret != 0) {
		    KRB5_LOG(KRB5_ERR,
			    "k5_ef_crypto: error: ret = 0x%08x",
			    ret);
		    goto cleanup;
		}
		/*
		 * tmp input data should hold Cn with C'
		 * Note, tmp_output_data contains Pn + C',
		 */
		/* copy Cn */
		bcopy(Cn, tmp_input_data, partialamount);
		/* copy C' */
		bcopy(tmp_output_data + partialamount,
		    tmp_input_data + partialamount,
		    (BLOCK_SIZE - partialamount));

		/* copy Pn in tmp output to output->data */
		bcopy(tmp_output_data,
		    output->data + (input->length - partialamount),
		    partialamount);

		if (nblocks > 2) {
			/* use Cn-2 as ivec */
			tmp_ivec.data = Cn_2;
		} else {
			/* use 0 as ivec because Cn-2 does not exist */
			bzero(tmp_ivec_data, sizeof (tmp_ivec_data));
		}

		/*
		 * Now decrypt Cn + C' input, using either Cn-2 or 0 for ivec
		 * (set above), Pn-1 output.
		 */
		ret = k5_ef_crypto((const char *)tmp_input_data,
			(char *)output->data +
				(input->length - (BLOCK_SIZE + partialamount)),
			length, (krb5_keyblock *)key,
			&tmp_ivec, FALSE);

		if (ret != 0) {
		    KRB5_LOG(KRB5_ERR,
			    "k5_ef_crypto: error: ret = 0x%08x",
			    ret);
		    goto cleanup;
		}

	} /* end partial block processing */
	/*
	 * The ivec is updated to allow the caller to chain ivecs.  At this
	 * point I don't think any kernel callers are using this however the
	 * userland version of this function does it so this should be done in
	 * kernel for consistency's sake.  This is not done for 1 block, got
	 * this from MIT.
	 */
	if (nblocks > 1 && ivec) {
		(void) memcpy(ivec->data,
			input->data + ((nblocks - 2) * BLOCK_SIZE),
			BLOCK_SIZE);
	}

cleanup:
	if (ret)
		bzero(output->data, output->length);

	return (ret);
}

#else /* User Space */

/*ARGSUSED*/
krb5_error_code
krb5int_aes_decrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *ivec,
	const krb5_data *input, krb5_data *output)
{
	krb5_error_code ret = 0;
	int nblocks, partialamount;
	CK_RV rv;
	KRB5_MECH_TO_PKCS algos;
	CK_MECHANISM mechanism;
	CK_ULONG outlen;
	char tmp_ivec[BLOCK_SIZE];

	assert(input != NULL);
	assert(output != NULL);
	assert(input->length == output->length);
	assert(key != NULL);

	if (ivec != NULL) {
		/*
		 * This function updates ivec->data if the ivec is passed in so
		 * it better have a data pointer and a proper length.
		 */
		if (ivec->data == NULL || ivec->length != BLOCK_SIZE) {
			assert(ivec->data != NULL);
			assert(ivec->length == BLOCK_SIZE);
			KRB5_LOG1(KRB5_ERR, "In krb5int_aes_decrypt: error "
			    "ivec->data = %p ivec->length = %d", ivec->data,
			    ivec->length);
			ret = KRB5_CRYPTO_INTERNAL;
			goto cleanup;
		}
	}

	/* number of input blocks including partial block */
	nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "nblocks = %d", nblocks);
	/* get # of bytes in partially filled block */
	partialamount = input->length % BLOCK_SIZE;
	KRB5_LOG(KRB5_INFO, "partialamount = %d", partialamount);

	rv = get_algo(key->enctype, &algos);
	if (rv != CKR_OK)
		goto cleanup;
	assert(algos.enc_algo == CKM_AES_CBC);

	rv = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key);
	if (rv != CKR_OK) {
		goto cleanup;
	}

	mechanism.mechanism = algos.enc_algo;
	if (ivec == NULL) {
		bzero(tmp_ivec, sizeof (tmp_ivec));
		mechanism.pParameter = tmp_ivec;
		mechanism.ulParameterLen = sizeof (tmp_ivec);
	} else {
		mechanism.pParameter = ivec->data;
		mechanism.ulParameterLen = ivec->length;
	}

	if (nblocks == 1 || (partialamount == 0)) {
		char orig_input[BLOCK_SIZE * 2];
		/*
		 * nlibp = next to last input block pointer
		 * libp = last input block pointer
		 */
		char *nlibp, *libp;

		/*
		 * Simple case:
		 *
		 * Swap last 2 ciphertext blocks (all must be full), then use
		 * CBC to implement CTS.
		 */
		if (nblocks > 1) {
			/*
			 * swap last 2 ciphertext blocks to implement CTS
			 */
			char tmp[BLOCK_SIZE];

			/*
			 * Note, the side effect with this is that we are
			 * modifying the input->data!
			 */
			nlibp = input->data + ((nblocks - 2) * BLOCK_SIZE);
			libp = input->data + ((nblocks - 1) * BLOCK_SIZE);

			/* first save orig input data for later restore */
			/* we know that partial amount is 0, because */
			/* nblocks is > 1, so we copy the last two blocks */
			bcopy(nlibp, orig_input, sizeof (orig_input));

			bcopy(nlibp, tmp, BLOCK_SIZE);
			bcopy(libp, nlibp, BLOCK_SIZE);
			bcopy(tmp, libp, BLOCK_SIZE);
		} else {
			if (input->length < BLOCK_SIZE)
				return (KRB5_CRYPTO_INTERNAL);
		}

		/*
		 * Note, since CBC is assumed to be the underlying mode, this
		 * call to C_DecryptInit is setting the IV.  The IV in use here
		 * is either the ivec passed in or a block of 0's.  All calls to
		 * C_DecryptInit set the IV in this function.
		 */
		rv = C_DecryptInit(krb_ctx_hSession(context), &mechanism,
				key->hKey);
		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
			    "krb5int_aes_decrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		/*
		 * C_Encrypt/Decrypt requires a pointer to long, not a pointer
		 * to int cast to pointer to long!!!
		 */
		outlen = output->length;

		rv = C_Decrypt(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)input->data,
			    input->length,
			    (CK_BYTE_PTR)output->data,
			    &outlen);

		if (nblocks > 1) {
			/* restore orig input data */
			bcopy(orig_input, nlibp, sizeof (orig_input));
		}
	} else {
		char tmp_ivec_data[BLOCK_SIZE], tmp_input_data[BLOCK_SIZE],
			tmp_output_data[BLOCK_SIZE];
		/* pointers to Cn, Cn-1, Cn-2 CipherText */
		char *Cn, *Cn_1, *Cn_2;
		CK_ULONG length;

		/*
		 * Complex case:
		 *
		 * Decrypting in CTS where there is a partial block of
		 * ciphertext.
		 */

		/* setting pointers to CipherText for later use */
		Cn = input->data + (input->length - partialamount);
		/* Cn - 1 */
		Cn_1 = Cn - BLOCK_SIZE;
		/* Cn - 2 */
		Cn_2 = Cn_1 - BLOCK_SIZE;

		if (nblocks > 2) {
			rv = C_DecryptInit(krb_ctx_hSession(context),
				&mechanism, key->hKey);
			if (rv != CKR_OK) {
				KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
				    "krb5int_aes_decrypt: rv = 0x%x", rv);
				goto cleanup;
			}
			/* set length to include blocks C0 thru Cn-2 */
			length = input->length - (BLOCK_SIZE + partialamount);
			outlen = length;
			/*
			 * First decrypt C0 thru Cn-2 using CBC with the input
			 * ivec.
			 */
			rv = C_Decrypt(krb_ctx_hSession(context),
				    (CK_BYTE_PTR)input->data,
				    length,
				    (CK_BYTE_PTR)output->data,
				    &outlen);
			if (rv != CKR_OK)
				goto cleanup;
		}

		/*
		 * Prepare to decrypt Cn-1 using a ivec of Cn with 0 padding.
		 */
		bzero(tmp_ivec_data, sizeof (tmp_ivec_data));
		/* the tmp ivec data holds Cn with 0 padding */
		bcopy(Cn, tmp_ivec_data, partialamount);

		/* decrypt 1 block */
		length = BLOCK_SIZE;
		outlen = length;

		/* set ivec to Cn with 0 padding */
		mechanism.pParameter = tmp_ivec_data;
		mechanism.ulParameterLen = sizeof (tmp_ivec_data);

		rv = C_DecryptInit(krb_ctx_hSession(context), &mechanism,
			    key->hKey);
		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
			    "krb5int_aes_decrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		/*
		 * Now decrypt using Cn-1 input, Cn + 0 padding for ivec, Pn &
		 * C' output
		 */
		rv = C_Decrypt(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)Cn_1,
			    length,
			    (CK_BYTE_PTR)tmp_output_data,
			    &outlen);

		if (rv != CKR_OK)
			goto cleanup;

		/*
		 * tmp input data should hold Cn with C'
		 * Note, tmp_output_data contains Pn + C',
		 */
		/* copy Cn */
		bcopy(Cn, tmp_input_data, partialamount);
		/* copy C' */
		bcopy(tmp_output_data + partialamount,
		    tmp_input_data + partialamount,
		    (BLOCK_SIZE - partialamount));

		/* copy Pn in tmp output to output->data last block */
		bcopy(tmp_output_data,
		    output->data + (input->length - partialamount),
		    partialamount);

		if (nblocks > 2) {
			/* use Cn-2 as ivec */
			mechanism.pParameter = Cn_2;
		} else {
			/*
			 * nblocks == 2
			 *
			 * Cn-2 does not exist so either use 0 if input ivec
			 * does not exist or use the input ivec.
			 */
			if (ivec == NULL) {
				bzero(tmp_ivec_data, sizeof (tmp_ivec_data));
			} else {
				/* use original input ivec */
				mechanism.pParameter = ivec->data;
				mechanism.ulParameterLen = ivec->length;
			}
		}

		rv = C_DecryptInit(krb_ctx_hSession(context), &mechanism,
			    key->hKey);
		if (rv != CKR_OK) {
			KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
			    "krb5int_aes_decrypt: rv = 0x%x", rv);
			goto cleanup;
		}

		/*
		 * Now decrypt Cn + C' input, using either Cn-2, original input
		 * ivec or 0 for ivec (set above), Pn-1 output.
		 */
		rv = C_Decrypt(krb_ctx_hSession(context),
			    (CK_BYTE_PTR)tmp_input_data,
			    length,
			    (CK_BYTE_PTR)output->data + (input->length -
				(BLOCK_SIZE + partialamount)),
			    &outlen);
		if (rv != CKR_OK)
			goto cleanup;
	} /* end partial block processing */

	/*
	 * The ivec is updated to allow the caller to chain ivecs, done for the
	 * kcmd (rsh/rcp/etc...).  Note this is not done for 1 block although I
	 * am not sure why but I'm continuing the tradition from the MIT code.
	 */
	if (nblocks > 1 && ivec) {
		(void) memcpy(ivec->data,
			input->data + ((nblocks - 2) * BLOCK_SIZE),
			BLOCK_SIZE);
	}

cleanup:
	if (rv != CKR_OK)
		ret = PKCS_ERR;

	if (ret)
		bzero(output->data, input->length);

	return (ret);
}

#endif /* _KERNEL */

static krb5_error_code
k5_aes_make_key(krb5_context context,
	const krb5_data *randombits, krb5_keyblock *key)
{
	krb5_error_code ret = 0;
	if (key->length != 16 && key->length != 32)
		return (KRB5_BAD_KEYSIZE);
	if (randombits->length != key->length)
		return (KRB5_CRYPTO_INTERNAL);

	key->magic = KV5M_KEYBLOCK;
	key->dk_list = NULL;

#ifdef _KERNEL
	key->kef_key.ck_data = NULL;
	key->key_tmpl = NULL;
	(void) memcpy(key->contents, randombits->data, randombits->length);
	ret = init_key_kef(context->kef_cipher_mt, key);
#else
	key->hKey = CK_INVALID_HANDLE;
	(void) memcpy(key->contents, randombits->data, randombits->length);
	ret = init_key_uef(krb_ctx_hSession(context), key);
#endif /* _KERNEL */

	KRB5_LOG0(KRB5_INFO, "k5_aes_make_key() end\n");
	return (ret);
}

/*ARGSUSED*/
static krb5_error_code
krb5int_aes_init_state(krb5_context context, const krb5_keyblock *key,
	krb5_keyusage usage, krb5_data *state)
{
	if (!state)
		return (0);

	if (state && state->data)
		FREE(state->data, state->length);

	state->length = BLOCK_SIZE;
	state->data = (void *) MALLOC(BLOCK_SIZE);

	if (state->data == NULL)
		return (ENOMEM);

	(void) memset(state->data, 0, state->length);
	return (0);
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    BLOCK_SIZE,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    BLOCK_SIZE,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state
};
