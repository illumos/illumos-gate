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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Test various aspects of wcslcpy. We use various size buffers, fill each with
 * a stock character that we don't use in the test, and then ensure that we get
 * both the expected return value and the expected buffer contents.
 */

#include <wchar.h>
#include <err.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#define	WCSLCPY_BUFLEN	16

typedef struct wcslcpy_test {
	const char *wt_desc;
	wchar_t *wt_src;
	size_t wt_rval;
	size_t wt_dstlen;
	wchar_t wt_res[WCSLCPY_BUFLEN];
} wcslcpy_test_t;

static const wcslcpy_test_t wcslcpy_tests[] = { {
	.wt_desc = "Zero-sized Destination Buffer (1)",
	.wt_src = L"Hello, World!",
	.wt_rval = 13,
	.wt_dstlen = 0,
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Zero-sized Destination Buffer (2)",
	.wt_src = L"光",
	.wt_rval = 1,
	.wt_dstlen = 0,
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Truncation (1)",
	.wt_src = L"asdfasdfasdfasdfasdf",
	.wt_rval = 20,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L'a', L's', L'd', L'f', L'a', L's', L'd', L'f',
		    L'a', L's', L'd', L'f', L'a', L's', L'd', L'\0' }
}, {
	.wt_desc = "Truncation (2)",
	.wt_src = L"77777777777777777777777",
	.wt_rval = 23,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L'7', L'7', L'7', L'7', L'7', L'7', L'7', L'7',
		    L'7', L'7', L'7', L'7', L'7', L'7', L'7', L'\0' }
}, {
	.wt_desc = "Short Write (small buf)",
	.wt_src = L"@",
	.wt_rval = 1,
	.wt_dstlen = 2,
	.wt_res = { L'@', L'\0', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Short Write (small src)",
	.wt_src = L"@",
	.wt_rval = 1,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L'@', L'\0', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Short Write (smallish src)",
	.wt_src = L"Sephiroth",
	.wt_rval = 9,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L'S', L'e', L'p', L'h', L'i', L'r', L'o', L't',
		    L'h', L'\0', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "full buffer, no trunc",
	.wt_src = L"this is a buffe",
	.wt_rval = 15,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L't', L'h', L'i', L's', L' ', L'i', L's', L' ',
		    L'a', L' ', L'b', L'u', L'f', L'f', L'e', L'\0' }
}, {
	.wt_desc = "empty buffer, empty src",
	.wt_src = L"",
	.wt_rval = 0,
	.wt_dstlen = 0,
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "full buffer, empty src",
	.wt_src = L"",
	.wt_rval = 0,
	.wt_dstlen = WCSLCPY_BUFLEN,
	.wt_res = { L'\0', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
} };

static bool
wcslcpy_test_one(const wcslcpy_test_t *test)
{
	wchar_t buf[WCSLCPY_BUFLEN];
	size_t wcret, dstlen;
	bool ret = true;

	(void) wmemset(buf, L'-', ARRAY_SIZE(buf));
	dstlen = MIN(ARRAY_SIZE(buf), test->wt_dstlen);
	VERIFY3U(test->wt_dstlen, ==, dstlen);

	wcret = wcslcpy(buf, test->wt_src, dstlen);
	if (wcret != test->wt_rval) {
		warnx("TEST FAILED: %s: wcslcpy() returned %zu, expected %zu",
		    test->wt_desc, wcret, test->wt_rval);
		ret = false;
	}

	if (wmemcmp(buf, test->wt_res, ARRAY_SIZE(buf)) != 0) {
		warnx("TEST FAILED: %s: resulting buffer mismatch: found vs. "
		    "expected", test->wt_desc);
		for (size_t i = 0; i < ARRAY_SIZE(buf); i++) {
			(void) printf("\t[%zu] = [0x%x] vs [0x%x]\n", i, buf[i],
			    test->wt_res[i]);
		}
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: %s\n", test->wt_desc);
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(wcslcpy_tests); i++) {
		if (!wcslcpy_test_one(&wcslcpy_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
