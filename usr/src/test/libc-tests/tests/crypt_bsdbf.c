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
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Test the bcrypt crypt(3C) module, crypt_bsdbf.so.1, which crypt.conf(5)
 * maps to the "2a" and "2b" algorithms. The expected hashes were generated
 * with the independent Openwall crypt_blowfish implementation, and the first
 * few are well-known published test vectors.
 */

#include <crypt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>

/* "$2a$NN$" followed by 22 characters of base64 encoded salt */
#define	BCRYPT_SALTLEN	29
/* The salt followed by 31 characters of base64 encoded ciphertext */
#define	BCRYPT_HASHLEN	60

#define	NTHREADS	8
#define	NITERS		100

typedef struct {
	const char	*bt_key;
	const char	*bt_hash;
} bcrypt_test_t;

#define	LONGKEY		"0123456789abcdefghijklmnopqrstuvwxyz" \
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
			"chars after 72 are ignored"
#define	TEN		"0123456789"
#define	HUNDRED		TEN TEN TEN TEN TEN TEN TEN TEN TEN TEN

static const bcrypt_test_t tests[] = {
	{ "U*U",
	    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
	{ "U*U*",
	    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK" },
	{ "U*U*U",
	    "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a" },
	{ "",
	    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy" },
	{ LONGKEY,
	    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" },
	{ "password",
	    "$2a$04$abcdefghijklmnopqrstuughE8Ev8uGFaUgY2cNEySvxngrb/Jzdm" },
	{ "U*U",
	    "$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
	{ "",
	    "$2b$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy" },
	{ LONGKEY,
	    "$2b$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" },
	{ "password",
	    "$2b$06$abcdefghijklmnopqrstuuNBpXtlux7FnXJE0fnrtkSXNhdOGmWHu" },
	/*
	 * 2b caps the key at 72 bytes, so this is also the hash of the first
	 * 72 characters alone.
	 */
	{ HUNDRED HUNDRED HUNDRED,
	    "$2b$05$abcdefghijklmnopqrstuuLkMZtUsVwf9Ptg/wgiNv8ZhtnAHnix." },
};

/*
 * Salts that name a bcrypt algorithm but are otherwise malformed. The module
 * returns ":" for these, which can never match a stored hash.
 */
static const char *bad_salts[] = {
	"$2a$03$CCCCCCCCCCCCCCCCCCCCC.",	/* too few rounds */
	"$2a$32$CCCCCCCCCCCCCCCCCCCCC.",	/* too many rounds */
	"$2a$xx$CCCCCCCCCCCCCCCCCCCCC.",	/* non-numeric rounds */
	"$2a$5$CCCCCCCCCCCCCCCCCCCCC.",		/* one digit rounds */
	"$2b$05$CCCCCCCCCCCCCCC",		/* short salt */
	"$2b$05",				/* no salt */
};

static const char base64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static bool
check_hash(const bcrypt_test_t *t, const char *salt, bool verbose)
{
	const char *ret = crypt(t->bt_key, salt);

	if (ret == NULL) {
		(void) fprintf(stderr, "FAIL crypt(\"%s\", \"%s\") returned "
		    "NULL\n", t->bt_key, salt);
		return (false);
	}
	if (strcmp(ret, t->bt_hash) != 0) {
		(void) fprintf(stderr, "FAIL crypt(\"%s\", \"%s\") = \"%s\", "
		    "expected \"%s\"\n", t->bt_key, salt, ret, t->bt_hash);
		return (false);
	}
	if (verbose) {
		(void) printf("PASS crypt(\"%s\", \"%s\")\n", t->bt_key,
		    salt);
	}
	return (true);
}

static bool
test_known_answers(void)
{
	bool pass = true;

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const bcrypt_test_t *t = &tests[i];
		char salt[BCRYPT_SALTLEN + 1];

		/* Hashing with just the salt, as when setting a password */
		(void) strlcpy(salt, t->bt_hash, sizeof (salt));
		if (!check_hash(t, salt, true))
			pass = false;

		/* and with the full stored hash, as when verifying one */
		if (!check_hash(t, t->bt_hash, true))
			pass = false;
	}

	return (pass);
}

static bool
test_bad_salts(void)
{
	bool pass = true;

	for (size_t i = 0; i < ARRAY_SIZE(bad_salts); i++) {
		const char *ret = crypt("password", bad_salts[i]);

		if (ret == NULL) {
			(void) fprintf(stderr, "FAIL crypt() with bad salt "
			    "\"%s\" returned NULL\n", bad_salts[i]);
			pass = false;
		} else if (strcmp(ret, ":") != 0) {
			(void) fprintf(stderr, "FAIL crypt() with bad salt "
			    "\"%s\" = \"%s\", expected \":\"\n", bad_salts[i],
			    ret);
			pass = false;
		} else {
			(void) printf("PASS crypt() with bad salt \"%s\"\n",
			    bad_salts[i]);
		}
	}

	return (pass);
}

static bool
valid_salt(const char *salt)
{
	if (strlen(salt) != BCRYPT_SALTLEN)
		return (false);
	if (strncmp(salt, "$2b$04$", 7) != 0)
		return (false);
	return (strspn(salt + 7, base64) == BCRYPT_SALTLEN - 7);
}

static bool
test_gensalt(void)
{
	char *salt1, *salt2, *hash;
	const char *ret;
	bool pass = false;

	/*
	 * The module generates 2b salts even when asked for 2a. crypt.conf(5)
	 * passes no rounds parameter, so it uses its default of 4. If
	 * policy.conf(5) does not allow 2a then crypt_gensalt() falls back to
	 * the default algorithm instead.
	 */
	salt1 = crypt_gensalt("$2a$", NULL);
	salt2 = crypt_gensalt("$2a$", NULL);
	hash = NULL;
	if (salt1 == NULL || salt2 == NULL) {
		(void) fprintf(stderr, "FAIL crypt_gensalt(\"$2a$\") returned "
		    "NULL\n");
		goto out;
	}
	if (!valid_salt(salt1) || !valid_salt(salt2)) {
		(void) fprintf(stderr, "FAIL crypt_gensalt(\"$2a$\") returned "
		    "\"%s\" and \"%s\", is 2a allowed in policy.conf?\n",
		    salt1, salt2);
		goto out;
	}
	if (strcmp(salt1, salt2) == 0) {
		(void) fprintf(stderr, "FAIL crypt_gensalt(\"$2a$\") returned "
		    "\"%s\" twice\n", salt1);
		goto out;
	}
	(void) printf("PASS crypt_gensalt(\"$2a$\") = \"%s\", \"%s\"\n",
	    salt1, salt2);

	ret = crypt("password", salt1);
	if (ret == NULL || strlen(ret) != BCRYPT_HASHLEN ||
	    strncmp(ret, salt1, BCRYPT_SALTLEN) != 0 ||
	    strspn(ret + BCRYPT_SALTLEN, base64) !=
	    BCRYPT_HASHLEN - BCRYPT_SALTLEN) {
		(void) fprintf(stderr, "FAIL crypt() with generated salt "
		    "\"%s\" = \"%s\"\n", salt1, ret == NULL ? "NULL" : ret);
		goto out;
	}
	if ((hash = strdup(ret)) == NULL) {
		(void) fprintf(stderr, "FAIL out of memory\n");
		goto out;
	}

	ret = crypt("password", hash);
	if (ret == NULL || strcmp(ret, hash) != 0) {
		(void) fprintf(stderr, "FAIL crypt() did not verify \"%s\", "
		    "got \"%s\"\n", hash, ret == NULL ? "NULL" : ret);
		goto out;
	}
	ret = crypt("Password", hash);
	if (ret == NULL || strcmp(ret, hash) == 0) {
		(void) fprintf(stderr, "FAIL crypt() verified \"%s\" with the "
		    "wrong key\n", hash);
		goto out;
	}
	(void) printf("PASS crypt() round trip with generated salt \"%s\"\n",
	    salt1);
	pass = true;

out:
	free(salt1);
	free(salt2);
	free(hash);
	return (pass);
}

/*
 * Have several threads hash the test vectors at once, each starting at a
 * different vector so that they are working on different keys and salts at
 * the same time. Any state shared between threads in the module shows up as
 * a wrong hash.
 */
static void *
mt_thread(void *arg)
{
	size_t start = (uintptr_t)arg;
	uintptr_t failures = 0;

	for (uint_t iter = 0; iter < NITERS; iter++) {
		for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
			const bcrypt_test_t *t =
			    &tests[(start + i) % ARRAY_SIZE(tests)];

			if (!check_hash(t, t->bt_hash, false))
				failures++;
		}
	}

	return ((void *)failures);
}

static bool
test_mt(void)
{
	pthread_t tids[NTHREADS];
	uintptr_t failures = 0;
	bool pass = true;
	int ret;

	for (uintptr_t i = 0; i < NTHREADS; i++) {
		ret = pthread_create(&tids[i], NULL, mt_thread, (void *)i);
		if (ret != 0) {
			(void) fprintf(stderr, "FAIL pthread_create: %s\n",
			    strerror(ret));
			return (false);
		}
	}

	for (uint_t i = 0; i < NTHREADS; i++) {
		void *thr_failures;

		ret = pthread_join(tids[i], &thr_failures);
		if (ret != 0) {
			(void) fprintf(stderr, "FAIL pthread_join: %s\n",
			    strerror(ret));
			pass = false;
			continue;
		}
		failures += (uintptr_t)thr_failures;
	}

	if (failures != 0) {
		(void) fprintf(stderr, "FAIL %lu of %u concurrent hashes were "
		    "wrong\n", (ulong_t)failures,
		    NTHREADS * NITERS * (uint_t)ARRAY_SIZE(tests));
		pass = false;
	} else if (pass) {
		(void) printf("PASS %u concurrent hashes in %u threads\n",
		    NTHREADS * NITERS * (uint_t)ARRAY_SIZE(tests), NTHREADS);
	}

	return (pass);
}

int
main(void)
{
	bool pass = true;

	if (!test_known_answers())
		pass = false;
	if (!test_bad_salts())
		pass = false;
	if (!test_gensalt())
		pass = false;
	if (!test_mt())
		pass = false;

	if (pass)
		(void) printf("All tests passed\n");
	return (pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
