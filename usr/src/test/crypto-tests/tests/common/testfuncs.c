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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 RackTop Systems, Inc.
 */

#define	__EXTENSIONS__
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/debug.h>
#include "cryptotest.h"

#define	EXIT_FAILURE_MULTIPART	1
#define	EXIT_FAILURE_SINGLEPART	2

test_fg_t cryptotest_decr_fg = {
	.tf_fg = CRYPTO_FG_DECRYPT,
	.tf_init = decrypt_init,
	.tf_single = decrypt_single,
	.tf_update = decrypt_update,
	.tf_final = decrypt_final
};

test_fg_t cryptotest_encr_fg = {
	.tf_fg = CRYPTO_FG_ENCRYPT,
	.tf_init = encrypt_init,
	.tf_single = encrypt_single,
	.tf_update = encrypt_update,
	.tf_final = encrypt_final
};

test_fg_t cryptotest_mac_fg = {
	.tf_fg = CRYPTO_FG_MAC,
	.tf_init = mac_init,
	.tf_single = mac_single,
	.tf_update = mac_update,
	.tf_final = mac_final
};

test_fg_t cryptotest_digest_fg = {
	.tf_fg = CRYPTO_FG_DIGEST,
	.tf_init = digest_init,
	.tf_single = digest_single,
	.tf_update = digest_update,
	.tf_final = digest_final
};

/*
 * Utils
 */

static const char *
ctest_errstr(int e, char *buf, size_t buflen)
{
	const char *name = NULL;
	;
	switch (e) {
	case CTEST_INIT_FAILED:
		name = "CTEST_INIT_FAILED";
		break;
	case CTEST_NAME_RESOLVE_FAILED:
		name = "CTEST_MECH_NO_PROVIDER";
		break;
	case CTEST_MECH_NO_PROVIDER:
		name = "CTEST_MECH_NO_PROVIDER";
		break;
	default:
		name = "Unknown fatal error";
		break;
	}

	(void) snprintf(buf, buflen, "%s (%d)", name, e);
	return (buf);
}

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
		(void) fprintf(stderr, "        mismatched result\n\n");
		printbuf(cmp, "calc", size);
		printbuf(auth, "orig", size);
		return (1);
	} else {
		(void) fprintf(stderr, "        result matches\n\n");
		return (0);
	}
}

static int
test_setup(cryptotest_t *args, test_fg_t *funcs, crypto_op_t **opp)
{
	crypto_op_t *crypto_op = NULL;
	int ret;

	switch (funcs->tf_fg) {
	case CRYPTO_FG_DECRYPT:
	case CRYPTO_FG_ENCRYPT:
		if (args->key == NULL)
			return (CRYPTO_FAILED);
		break;
	case CRYPTO_FG_MAC:
		if (args->in == NULL || args->key == NULL)
			return (CRYPTO_FAILED);
		break;
	case CRYPTO_FG_DIGEST:
		break;
	default:
		(void) fprintf(stderr,
		    "Unexpected function group value %" PRIu32 "\n",
		    funcs->tf_fg);
		abort();
	}

	if ((crypto_op = cryptotest_init(args, funcs->tf_fg)) == NULL) {
		/* cryptotest_init() will prints out a specific error msg  */
		cryptotest_close(NULL);
		return (CTEST_INIT_FAILED);
	}

	if ((ret = get_mech_info(crypto_op)) != CRYPTO_SUCCESS) {
		cryptotest_close(crypto_op);
		return (ret);
	}

	if ((ret = get_hsession_by_mech(crypto_op)) != CRYPTO_SUCCESS) {
		cryptotest_close(crypto_op);
		return (ret);
	}

	*opp = crypto_op;
	return (CRYPTO_SUCCESS);
}

static int
test_multi(cryptotest_t *args, test_fg_t *funcs, uint8_t *cmp, size_t cmplen)
{
	crypto_op_t *crypto_op = NULL;
	size_t errs = 0;
	size_t n;
	int ret;

	(void) fprintf(stderr, "multi-part:\n");

	if ((ret = test_setup(args, funcs, &crypto_op)) != CRYPTO_SUCCESS) {
		(void) fprintf(stderr, "        fatal error %d\n", ret);
		exit(EXIT_FAILURE_MULTIPART);
	}

	for (n = 0; args->updatelens[n] != CTEST_UPDATELEN_END; n++) {
		char errbuf[BUFSZ] = { 0 };
		char sizebuf[BUFSZ] = { 0 };
		size_t updatelen = args->updatelens[n];
		size_t offset = 0;
		size_t outlen = 0;

		bzero(args->out, args->outlen);

		if (updatelen == CTEST_UPDATELEN_WHOLE) {
			updatelen = args->inlen;
			(void) snprintf(sizebuf, sizeof (sizebuf),
			    "%zu (whole buffer)", updatelen);
		} else if (updatelen > args->inlen) {
			/*
			 * This can sometimes cause the same update size to
			 * be used twice if one is specified larger than the
			 * input and one also specifies a test using the
			 * entire input as the update size.  It doesn't
			 * hurt anything other than adding a little extra
			 * time.
			 */
			updatelen = args->inlen;
			(void) snprintf(sizebuf, sizeof (sizebuf),
			    "%zu (was %zu but capped at input size)",
			    updatelen, args->updatelens[n]);
		} else {
			(void) snprintf(sizebuf, sizeof (sizebuf), "%zu",
			    updatelen);
		}
		(void) fprintf(stderr, "    update size: %s\n", sizebuf);
		(void) fflush(stderr);

		if ((ret = funcs->tf_init(crypto_op)) != CRYPTO_SUCCESS) {
			(void) fprintf(stderr, "    tf_init error %d\n", ret);
			errs += 1;
			continue;
		}

		while (offset < args->inlen) {
			size_t len = updatelen;

			if (offset + updatelen > args->inlen) {
				len = args->inlen - offset;
			}

			ret = funcs->tf_update(crypto_op, offset, len, &outlen);
			if (ret != CRYPTO_SUCCESS) {
				/*
				 * The update functions will print out their
				 * own error messages, so we don't need to.
				 */
				errs += 1;
				break;
			}

			offset += len;
		}

		if (ret != CRYPTO_SUCCESS)
			continue;

		ret = funcs->tf_final(crypto_op, outlen);

		/*
		 * Errors from the crypto frameworks (KCF, PKCS#11) are all
		 * positive (and 0 == success).  Negative values are used by
		 * the test framework to signal fatal errors (CTEST_xxx).
		 */
		if (ret > 0) {
			(void) fprintf(stderr, "        failure %s\n",
			    cryptotest_errstr(ret, errbuf, sizeof (errbuf)));
			errs += 1;
		} else if (ret < 0) {
			(void) fprintf(stderr, "        fatal error %s\n",
			    ctest_errstr(ret, errbuf, sizeof (errbuf)));
			exit(EXIT_FAILURE_MULTIPART);
		} else {
			errs += bufcmp(cmp, args->out, cmplen);
		}
	}

	VERIFY3U(errs, <=, INT_MAX);
	cryptotest_close(crypto_op);
	return (errs);
}

static int
test_single(cryptotest_t *args, test_fg_t *funcs, uint8_t *cmp, size_t cmplen)
{
	crypto_op_t *crypto_op = NULL;
	char errbuf[BUFSZ] = { 0 };
	int ret;

	(void) fprintf(stderr, "single part:\n");

	if ((ret = test_setup(args, funcs, &crypto_op)) != CRYPTO_SUCCESS) {
		(void) fprintf(stderr, "        setup error %d\n", ret);
		exit(EXIT_FAILURE_SINGLEPART);
	}

	if ((ret = funcs->tf_init(crypto_op)) != CRYPTO_SUCCESS) {
		(void) fprintf(stderr, "        tf_init error %d\n", ret);
		goto out;
	}

	ret = funcs->tf_single(crypto_op);

	/*
	 * Errors from the crypto frameworks (KCF, PKCS#11) are all
	 * positive (and 0 == success).  Negative values are used by
	 * the test framework to signal fatal errors (CTEST_xxx).
	 */
	if (ret > 0) {
		(void) fprintf(stderr, "        failure %s\n",
		    cryptotest_errstr(ret, errbuf, sizeof (errbuf)));
	} else if (ret < 0) {
		(void) fprintf(stderr, "        fatal error %s\n",
		    ctest_errstr(ret, errbuf, sizeof (errbuf)));
		exit(EXIT_FAILURE_SINGLEPART);
	} else {
		ret = bufcmp(cmp, args->out, cmplen);
	}

out:
	(void) cryptotest_close(crypto_op);
	return ((ret == CRYPTO_SUCCESS) ? 0 : 1);
}

/*
 * Wrapper functions
 */

int
run_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen,
    test_fg_t *funcs)
{
	size_t errs = 0;
	static int i = 0;

	(void) fprintf(stderr, "%s: run %d\n", args->mechname, ++i);

	errs += test_multi(args, funcs, cmp, cmplen);

	bzero(args->out, args->outlen);

	errs += test_single(args, funcs, cmp, cmplen);

	VERIFY3U(errs, <=, INT_MAX);
	return (errs);
}
