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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 RackTop Systems, Inc.
 */

#ifndef _CRYPTOTEST_H
#define	_CRYPTOTEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <sys/crypto/ioctl.h>

/*
 * A somewhat arbitrary size that should be large enough to hold the printed
 * error and size messages.
 */
#define	BUFSZ 128

#define	CTEST_INIT_FAILED (-1)
#define	CTEST_NAME_RESOLVE_FAILED (-2)
#define	CTEST_MECH_NO_PROVIDER (-3)

#define	CTEST_UPDATELEN_WHOLE	SIZE_MAX
#define	CTEST_UPDATELEN_END	0

extern boolean_t cryptotest_pkcs;	/* true if PKCS */

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
	size_t *updatelens;
} cryptotest_t;

typedef struct crypto_op crypto_op_t;

typedef struct test_fg {
	crypto_func_group_t tf_fg;
	int (*tf_init)(crypto_op_t *);
	int (*tf_single)(crypto_op_t *);
	int (*tf_update)(crypto_op_t *, size_t, size_t, size_t *);
	int (*tf_final)(crypto_op_t *, size_t);
} test_fg_t;

#define	CRYPTO_INVALID_SESSION ((crypto_session_id_t)-1)

int run_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen, test_fg_t *funcs);

const char *cryptotest_errstr(int e, char *buf, size_t buflen);

/* utils */
crypto_op_t *cryptotest_init(cryptotest_t *args, crypto_func_group_t fg);
void cryptotest_close(crypto_op_t *op);
int get_mech_info(crypto_op_t *op);
int get_hsession_by_mech(crypto_op_t *op);

/* CRYPTO_MAC */
int mac_init(crypto_op_t *op);
int mac_single(crypto_op_t *op);
int mac_update(crypto_op_t *op, size_t offset, size_t len, size_t *dummy);
int mac_final(crypto_op_t *op, size_t dummy);

/* CRYPTO_ENCRYPT */
int encrypt_init(crypto_op_t *op);
int encrypt_single(crypto_op_t *op);
int encrypt_update(crypto_op_t *op, size_t offset, size_t plainlen,
    size_t *encrlen);
int encrypt_final(crypto_op_t *op, size_t encrlen);

/* CRYPTO_DECRYPT */
int decrypt_init(crypto_op_t *op);
int decrypt_single(crypto_op_t *op);
int decrypt_update(crypto_op_t *op, size_t offset, size_t cipherlen,
    size_t *encrlen);
int decrypt_final(crypto_op_t *op, size_t encrlen);

/* CRYPTO_DIGEST */
int digest_init(crypto_op_t *op);
int digest_single(crypto_op_t *op);
int digest_update(crypto_op_t *op, size_t offset, size_t len, size_t *dummy);
int digest_final(crypto_op_t *op, size_t dummy);

extern test_fg_t cryptotest_decr_fg;
extern test_fg_t cryptotest_encr_fg;
extern test_fg_t cryptotest_mac_fg;
extern test_fg_t cryptotest_digest_fg;

#define	MAC_FG (&cryptotest_mac_fg)
#define	ENCR_FG (&cryptotest_encr_fg)
#define	DECR_FG (&cryptotest_decr_fg)
#define	DIGEST_FG (&cryptotest_digest_fg)

/*
 * KCF and PKCS11 use different structures for the CCM params (CK_AES_CCM_PARAMS
 * and CK_CCM_PARAMS respectively.  Each cryptotest_*.c file implements this
 * for their respective structs.
 */
void ccm_init_params(void *, ulong_t, uchar_t *, ulong_t, uchar_t *, ulong_t,
    ulong_t);
size_t ccm_param_len(void);

void gmac_init_params(void *, uchar_t *, uchar_t *, ulong_t);
size_t gmac_param_len(void);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOTEST_H */
