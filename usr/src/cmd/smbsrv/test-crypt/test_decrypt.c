/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <smbsrv/smb_kcrypt.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "test_data.h"
#include "utils.h"

/*
 * Test program for the interfaces used in
 * smb3_decrypt_command()
 */
int
do_decrypt(char *outbuf, size_t *outlen,
    const uint8_t *inbuf, size_t inlen, int mid)
{
	smb_enc_ctx_t ctx;
	uio_t uio_in;
	uio_t uio_out;
	iovec_t iov_in[4];
	iovec_t iov_out[4];
	int rc;

	bzero(&ctx, sizeof (ctx));
	ctx.mech.mechanism = mid; // CKM_AES_CCM or CKM_AES_GCM

	switch (mid) {

	case CKM_AES_CCM:
		smb3_crypto_init_ccm_param(&ctx,
		    (uint8_t *)nonce, 11,
		    (uint8_t *)authdata, 16,
		    inlen);
		break;

	case CKM_AES_GCM:
		smb3_crypto_init_gcm_param(&ctx,
		    (uint8_t *)nonce, 12,
		    (uint8_t *)authdata, 16);
		break;

	default:
		return (1);
	}

	rc = smb3_decrypt_init(&ctx,
	    (uint8_t *)keydata, 16);
	if (rc != 0)
		return (rc);

	make_uio((void *)inbuf, inlen, &uio_in, iov_in, 4);
	make_uio(outbuf, *outlen, &uio_out, iov_out, 4);
	*outlen = uio_out.uio_resid;

	rc = smb3_decrypt_uio(&ctx, &uio_in, &uio_out);
	*outlen -= uio_out.uio_resid;

	smb3_enc_ctx_done(&ctx);

	return (rc);
}

char outbuf[CLEAR_DATA_LEN];

void
test_decrypt(const uint8_t *cipher, int mid)
{
	size_t outlen;
	int rc;

	outlen = sizeof (outbuf);
	rc = do_decrypt(outbuf, &outlen,
	    cipher, CIPHER_DATA_LEN, mid);
	if (rc != 0) {
		printf("FAIL: decrypt rc= %d\n");
		return;
	}

	if (outlen != CLEAR_DATA_LEN) {
		printf("FAIL: out len = %d (want %d)\n",
		    outlen, CLEAR_DATA_LEN);
		return;
	}

	if (memcmp(outbuf, clear_data_ref, CLEAR_DATA_LEN) != 0) {
		printf("FAIL: ciphertext:\n");
		hexdump((uchar_t *)outbuf, CLEAR_DATA_LEN);
		return;
	}

	printf("PASS mid=0x%x\n", mid);
}

int
main(int argc, char *argv[])
{

	test_decrypt(cipher_data_ccm, CKM_AES_CCM);
	test_decrypt(cipher_data_gcm, CKM_AES_GCM);

	return (0);
}
