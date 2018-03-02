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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#define	__EXTENSIONS__
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include "cryptotest.h"



test_fg_t cryptotest_decr_fg = {test_decrypt_single, test_decrypt};
test_fg_t cryptotest_encr_fg = {test_encrypt_single, test_encrypt};
test_fg_t cryptotest_mac_fg = {test_mac_single, test_mac};
test_fg_t cryptotest_digest_fg = {test_digest_single, test_digest};

/*
 * Utils
 */

void
printbuf(uint8_t *buf, char *name, size_t size)
{
	size_t i;

	flockfile(stderr);
	(void) fprintf(stderr, "%s%s", name, (size > 0) ? " " : "");
	for (i = 0; i < size; i++)
		(void) fprintf(stderr, "%02x", buf[i]);
	(void) fputc('\n', stderr);
	funlockfile(stderr);
}

int
bufcmp(uint8_t *auth, uint8_t *cmp, size_t size)
{
	if (memcmp(cmp, auth, size) != 0) {
		(void) fprintf(stderr, "mismatched result\n\n");
		printbuf(cmp, "calc", size);
		printbuf(auth, "orig", size);
		return (1);
	} else {
		(void) fprintf(stderr, "result matches\n\n");
		return (0);
	}
}

/*
 * Wrapper functions
 */

int
run_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen,
    test_fg_t *funcs)
{
	int ret, errs = 0;
	static int i = 0;

	(void) fprintf(stderr, "%s: run %d\n", args->mechname, ++i);
	bzero(args->out, args->outlen);
	ret = funcs->update(args);
	if (ret > 0) {
		(void) fprintf(stderr, "failure %x\n", ret);
		errs += 1;
	} else if (ret < 0) {
		(void) fprintf(stderr, "fatal error %d\n", ret);
		exit(1);
	} else
		errs += bufcmp(cmp, args->out, cmplen);

	bzero(args->out, args->outlen);
	ret = funcs->single(args);
	if (ret > 0) {
		(void) fprintf(stderr, "failure %x\n", ret);
		errs += 1;
	} else if (ret < 0) {
		(void) fprintf(stderr, "fatal error %d\n", ret);
		exit(2);
	} else
		errs += bufcmp(cmp, args->out, cmplen);

	return (errs);
}

static int
test_mac_common(cryptotest_t *args, boolean_t AIO)
{
	int ret, i;
	crypto_op_t *crypto_op;

	if (args->in == NULL || args->key == NULL)
		return (CRYPTO_FAILED);

	if ((crypto_op = cryptotest_init(args, CRYPTO_FG_MAC)) == NULL) {
		(void) fprintf(stderr, "Error occured during initialization\n");
		(void) cryptotest_close(NULL);
		return (CTEST_INIT_FAILED);
	}

	if ((ret = get_mech_info(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = get_hsession_by_mech(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = mac_init(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if (AIO) {
		if ((ret = mac_single(crypto_op)) != CRYPTO_SUCCESS)
			goto out;
	} else {
		for (i = 0; i < args->inlen; i += args->updatelen) {

			if ((ret = mac_update(crypto_op, i)) != CRYPTO_SUCCESS)
				goto out;
		}

		if ((ret = mac_final(crypto_op)) != CRYPTO_SUCCESS)
			goto out;

	}

out:
	(void) cryptotest_close(crypto_op);
	return (ret);
}

int
test_mac_single(cryptotest_t *args)
{
	return (test_mac_common(args, B_TRUE));
}

int
test_mac(cryptotest_t *args)
{
	return (test_mac_common(args, B_FALSE));
}

static int
test_encrypt_common(cryptotest_t *args, boolean_t AIO)
{
	int ret, i;
	size_t encrlen = 0;
	crypto_op_t *crypto_op;

	if (args->key == NULL)
		return (CRYPTO_FAILED);

	if ((crypto_op = cryptotest_init(args, CRYPTO_FG_ENCRYPT)) == NULL) {
		(void) fprintf(stderr, "Error occured during initialization\n");
		(void) cryptotest_close(NULL);
		return (CTEST_INIT_FAILED);
	}

	if ((ret = get_mech_info(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = get_hsession_by_mech(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = encrypt_init(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if (AIO) {
		if ((ret = encrypt_single(crypto_op)) != CRYPTO_SUCCESS)
			goto out;
	} else {
		for (i = 0; i < args->inlen; i += args->updatelen) {

			if ((ret = encrypt_update(crypto_op, i,
			    &encrlen)) != CRYPTO_SUCCESS)
				goto out;
		}

		if ((ret = encrypt_final(crypto_op, encrlen)) != CRYPTO_SUCCESS)
			goto out;

	}

out:
	(void) cryptotest_close(crypto_op);
	return (ret);
}

int
test_encrypt_single(cryptotest_t *args)
{
	return (test_encrypt_common(args, B_TRUE));
}


int
test_encrypt(cryptotest_t *args)
{
	return (test_encrypt_common(args, B_FALSE));
}

static int
test_decrypt_common(cryptotest_t *args, boolean_t AIO)
{
	int ret, i;
	size_t encrlen = 0;
	crypto_op_t *crypto_op;

	if (args->key == NULL)
		return (CRYPTO_FAILED);

	if ((crypto_op = cryptotest_init(args, CRYPTO_FG_DECRYPT)) == NULL) {
		(void) fprintf(stderr, "Error occured during initialization\n");
		(void) cryptotest_close(NULL);
		return (CTEST_INIT_FAILED);
	}

	if ((ret = get_mech_info(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = get_hsession_by_mech(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = decrypt_init(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if (AIO) {
		if ((ret = decrypt_single(crypto_op)) != CRYPTO_SUCCESS)
			goto out;
	} else {
		for (i = 0; i < args->inlen; i += args->updatelen) {

			if ((ret = decrypt_update(crypto_op, i,
			    &encrlen)) != CRYPTO_SUCCESS)
				goto out;
		}

		if ((ret = decrypt_final(crypto_op, encrlen)) != CRYPTO_SUCCESS)
			goto out;

	}

out:
	(void) cryptotest_close(crypto_op);
	return (ret);
}

int
test_decrypt_single(cryptotest_t *args)
{
	return (test_decrypt_common(args, B_TRUE));
}


int
test_decrypt(cryptotest_t *args)
{
	return (test_decrypt_common(args, B_FALSE));
}

static int
test_digest_common(cryptotest_t *args, boolean_t AIO)
{
	int ret, i;
	crypto_op_t *crypto_op;

	if ((crypto_op = cryptotest_init(args, CRYPTO_FG_DIGEST)) == NULL) {
		(void) fprintf(stderr, "Error occured during initalization\n");
		(void) cryptotest_close(NULL);
		return (CTEST_INIT_FAILED);
	}

	if ((ret = get_mech_info(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = get_hsession_by_mech(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if ((ret = digest_init(crypto_op)) != CRYPTO_SUCCESS)
		goto out;

	if (AIO) {
		if ((ret = digest_single(crypto_op)) != CRYPTO_SUCCESS)
			goto out;
	} else {
		for (i = 0; i < args->inlen; i += args->updatelen) {

			if ((ret = digest_update(crypto_op, i)) !=
			    CRYPTO_SUCCESS)
				goto out;
		}

		if ((ret = digest_final(crypto_op)) != CRYPTO_SUCCESS)
			goto out;
	}

out:
	(void) cryptotest_close(crypto_op);
	return (ret);
}

int
test_digest_single(cryptotest_t *args)
{
	return (test_digest_common(args, B_TRUE));
}

int
test_digest(cryptotest_t *args)
{
	return (test_digest_common(args, B_FALSE));
}
