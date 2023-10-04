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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Basic tests for the ilstr string handling routines.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <upanic.h>
#include <sys/ilstr.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

typedef enum ilstr_test_types {
	ITT_STD = 0x01,
	ITT_PRE = 0x02,
} ilstr_test_types_t;

#define	ITT_ALL	(ITT_STD | ITT_PRE)

typedef struct ilstr_test {
	char *ist_name;
	int (*ist_func)(ilstr_t *ils);
	uint_t ist_trials;
	ilstr_test_types_t ist_types;
} ilstr_test_t;

#define	PREALLOC_SZ	1024
static char ilsbuf[PREALLOC_SZ];

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("transaction,contents,fail");
}

int
ist_empty(ilstr_t *ils)
{
	VERIFY3U(ilstr_len(ils), ==, 0);
	VERIFY(ilstr_cstr(ils) != NULL);
	VERIFY3U(ilstr_cstr(ils)[0], ==, '\0');
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);

	return (0);
}

int
ist_prealloc_toobig(ilstr_t *ils)
{
	for (uint_t n = 0; n < PREALLOC_SZ - 1; n++) {
		ilstr_append_str(ils, "A");
	}
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);

	ilstr_append_str(ils, "A");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_NOMEM);

	ilstr_append_str(ils, "A");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_NOMEM);

	ilstr_reset(ils);

	ilstr_append_str(ils, "B");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY(strcmp(ilstr_cstr(ils), "B") == 0);

	return (0);
}

int
ist_huge(ilstr_t *ils)
{
	/*
	 * Build a 26MB string by repeating the alphabet over and over:
	 */
	uint_t target = 26 * 1024 * 1024;

	for (uint_t n = 0; n < target / 26; n++) {
		ilstr_append_str(ils, "abcdefghijklmnopqrstuvwxyz");

		if (ilstr_errno(ils) == ILSTR_ERROR_NOMEM) {
			return (ENOMEM);
		}
		VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	}

	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY3U(ilstr_len(ils), ==, target);

	return (0);
}

int
ist_printf_1(ilstr_t *ils)
{
	const char *want = "a\nb\n1000\ntest string\n";

	ilstr_aprintf(ils, "a\nb\n%u\n%s\n", 1000, "test string");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY(strcmp(ilstr_cstr(ils), want) == 0);

	return (0);
}

int
ist_printf_2(ilstr_t *ils)
{
	int r = 0;

	const char *lorem = "Lorem ipsum dolor sit amet, consectetur "
	    "adipiscing elit, sed do eiusmod tempor incididunt ut labore "
	    "et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud "
	    "exercitation ullamco laboris nisi ut aliquip ex ea commodo "
	    "consequat.";
	char *want;

	if (asprintf(&want, "%s\n\tnumber 1\n%s\n\n%s\n   number 100000000\n",
	    lorem, lorem, lorem) < 0) {
		return (errno);
	}

	ilstr_aprintf(ils, "%s\n\t", lorem);
	ilstr_append_str(ils, "number");
	ilstr_aprintf(ils, " %u\n%s\n\n", 1, lorem);
	ilstr_append_str(ils, lorem);
	ilstr_aprintf(ils, "\n   number %lld\n", (long long)100000000);

	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	if (strcmp(ilstr_cstr(ils), want) != 0) {
		printf("want: %s\n", want);
		printf("got:  %s\n", ilstr_cstr(ils));
		r = ENOENT;
	}

	free(want);

	return (r);
}

int
ist_resets(ilstr_t *ils)
{
	VERIFY(strcmp(ilstr_cstr(ils), "") == 0);

	ilstr_reset(ils);
	VERIFY(strcmp(ilstr_cstr(ils), "") == 0);

	ilstr_append_str(ils, "abc");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY(strcmp(ilstr_cstr(ils), "abc") == 0);

	ilstr_append_str(ils, "def");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY(strcmp(ilstr_cstr(ils), "abcdef") == 0);

	ilstr_reset(ils);
	VERIFY(strcmp(ilstr_cstr(ils), "") == 0);

	ilstr_append_str(ils, "xyz");
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
	VERIFY(strcmp(ilstr_cstr(ils), "xyz") == 0);

	ilstr_reset(ils);
	VERIFY(strcmp(ilstr_cstr(ils), "") == 0);

	return (0);
}

int
ist_random(ilstr_t *ils)
{
	char *work;
	uint_t target = 256 + arc4random_uniform(1024 - 256);

	printf(" - target string length %u\n", target);
	if ((work = calloc(1, 1024 + 1)) == NULL) {
		return (errno);
	}

	VERIFY3U(ilstr_len(ils), ==, 0);
	VERIFY3U(ilstr_cstr(ils)[0], ==, '\0');
	VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);

	for (uint_t n = 0; n < target; n++) {
		char c[2] = { arc4random_uniform('Z' - 'A') + 'A', '\0' };

		work[n] = c[0];
		ilstr_append_str(ils, c);

		VERIFY3U(ilstr_errno(ils), ==, ILSTR_ERROR_OK);
		VERIFY3U(ilstr_len(ils), ==, n + 1);
		VERIFY(strcmp(ilstr_cstr(ils), work) == 0);
	}

	VERIFY3U(ilstr_len(ils), ==, target);
	VERIFY(strcmp(ilstr_cstr(ils), work) == 0);
	printf(" - final string: %s\n", work);

	free(work);
	return (0);
}

uint_t
ist_drive_test(const ilstr_test_t *ist)
{
	uint_t nfails = 0;
	int r;
	ilstr_t ils;

	for (uint_t n = 0; n < ist->ist_trials; n++) {
		if (ist->ist_types & ITT_STD) {
			ilstr_init(&ils, 0);
			printf("STD[%s]... run %d\n", ist->ist_name, n);
			if ((r = ist->ist_func(&ils)) != 0) {
				(void) fprintf(stderr,
				    "TEST FAILED: STD[%s]: %s\n",
				    ist->ist_name, strerror(r));
				nfails += 1;
			} else {
				printf("TEST PASSED: STD[%s]\n",
				    ist->ist_name);
			}
			ilstr_fini(&ils);
			printf("\n");
		}

		if (ist->ist_types & ITT_PRE) {
			ilstr_init_prealloc(&ils, ilsbuf, sizeof (ilsbuf));
			printf("PRE[%s]... run %d\n", ist->ist_name, n);
			if ((r = ist->ist_func(&ils)) != 0) {
				(void) fprintf(stderr,
				    "TEST FAILED: PRE[%s]: %s\n",
				    ist->ist_name, strerror(r));
				nfails += 1;
			} else {
				printf("TEST PASSED: PRE[%s]\n",
				    ist->ist_name);
			}
			ilstr_fini(&ils);
			printf("\n");
		}
	}

	return (nfails);
}

static const ilstr_test_t ilstr_tests[] = {
	{ "empty",		ist_empty,		1,	ITT_ALL },
	{ "resets",		ist_resets,		1,	ITT_ALL },
	{ "printf-1",		ist_printf_1,		1,	ITT_ALL },
	{ "printf-2",		ist_printf_2,		1,	ITT_ALL },
	{ "prealloc_toobig",	ist_prealloc_toobig,	1,	ITT_PRE },
	/*
	 * Run the random generation test many times, as an attempt at fuzzing:
	 */
	{ "random",		ist_random,		1000,	ITT_ALL },
	/*
	 * Run the huge allocation test some number of times to try to make
	 * sure we exercise allocation and free of different buffer sizes, and
	 * to increase the likelihood of detecting any heap corruption:
	 */
	{ "huge",		ist_huge,		100,	ITT_STD },
};

int
main(void)
{
	uint_t nfails = 0;

	for (uint_t i = 0; i < ARRAY_SIZE(ilstr_tests); i++) {
		nfails += ist_drive_test(&ilstr_tests[i]);
	}

	char *aoe;
	if ((aoe = getenv("PANIC_ON_EXIT")) != NULL && strcmp(aoe, "1") == 0) {
		const char *msg = "PANIC_ON_EXIT set; panicking for findleaks";
		upanic(msg, strlen(msg));
	}

	return (nfails == 0 ? 0 : 1);
}
