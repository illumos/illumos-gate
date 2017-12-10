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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _CRYPTOTEST_H
#define	_CRYPTOTEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/crypto/ioctl.h>

#define	CTEST_INIT_FAILED (-1)
#define	CTEST_NAME_RESOLVE_FAILED (-2)
#define	CTEST_MECH_NO_PROVIDER (-3)

typedef struct cryptotest {
	uint8_t *in;
	uint8_t *out;
	uint8_t *key;
	void *param;

	size_t inlen;
	size_t outlen;
	size_t keylen;
	size_t plen;

	char *mechname;
	size_t updatelen;
} cryptotest_t;

typedef int (*testfunc_t)(cryptotest_t *);

typedef struct test_fg {
	testfunc_t single;
	testfunc_t update;
} test_fg_t;

#define	CRYPTO_INVALID_SESSION ((size_t)-1)
typedef struct crypto_op crypto_op_t;

int run_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen, test_fg_t *funcs);

/* utils */
crypto_op_t *cryptotest_init(cryptotest_t *args, crypto_func_group_t fg);
int cryptotest_close(crypto_op_t *op);
int get_mech_info(crypto_op_t *op);
int get_hsession_by_mech(crypto_op_t *op);

/* CRYPTO_MAC */
int mac_init(crypto_op_t *op);
int mac_single(crypto_op_t *op);
int mac_update(crypto_op_t *op, int offset);
int mac_final(crypto_op_t *op);

/* CRYPTO_ENCRYPT */
int encrypt_init(crypto_op_t *op);
int encrypt_single(crypto_op_t *op);
int encrypt_update(crypto_op_t *op, int offset, size_t *encrlen);
int encrypt_final(crypto_op_t *op, size_t encrlen);

/* CRYPTO_DECRYPT */
int decrypt_init(crypto_op_t *op);
int decrypt_single(crypto_op_t *op);
int decrypt_update(crypto_op_t *op, int offset, size_t *encrlen);
int decrypt_final(crypto_op_t *op, size_t encrlen);

/* wrappers */
int test_mac_single(cryptotest_t *args);
int test_mac(cryptotest_t *args);

int test_encrypt_single(cryptotest_t *args);
int test_encrypt(cryptotest_t *args);

int test_decrypt_single(cryptotest_t *args);
int test_decrypt(cryptotest_t *args);

extern test_fg_t cryptotest_decr_fg;
extern test_fg_t cryptotest_encr_fg;
extern test_fg_t cryptotest_mac_fg;

#define	MAC_FG (&cryptotest_mac_fg)
#define	ENCR_FG (&cryptotest_encr_fg)
#define	DECR_FG (&cryptotest_decr_fg)

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOTEST_H */
