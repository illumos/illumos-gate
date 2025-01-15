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
 * Test various aspects of wcslcat.
 */

#include <wchar.h>
#include <err.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/sysmacros.h>

#define	WCSLCAT_BUFLEN	16

typedef struct wcslcat_test {
	const char *wt_desc;
	wchar_t *wt_src;
	size_t wt_rval;
	size_t wt_dstlen;
	wchar_t wt_buf[WCSLCAT_BUFLEN];
	wchar_t wt_res[WCSLCAT_BUFLEN];
} wcslcat_test_t;

static const wcslcat_test_t wcslcat_tests[] = { {
	.wt_desc = "Zero-sized Destination Buffer (1)",
	.wt_src = L"Hello, World!",
	.wt_rval = 13,
	.wt_dstlen = 0,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Zero-sized Destination Buffer (2)",
	.wt_src = L"光",
	.wt_rval = 1,
	.wt_dstlen = 0,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Append at start, empty src",
	.wt_src = L"",
	.wt_rval = 0,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'\0', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'\0', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Append at start, don't fill dest",
	.wt_src = L"It's a trap?!",
	.wt_rval = 13,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'\0', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'I', L't', L'\'', L's', L' ', L'a', L' ', L't',
		    L'r', L'a', L'p', L'?', L'!', L'\0', L'-', L'-' }

}, {
	.wt_desc = "Append at start, truncate src",
	.wt_src = L"This little string went to the market",
	.wt_rval = 37,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'\0', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'T', L'h', L'i', L's', L' ', L'l', L'i', L't',
		    L't', L'l', L'e', L' ', L's', L't', L'r', L'\0' }

}, {
	.wt_desc = "Full buffer (no NUL), empty src",
	.wt_src = L"",
	.wt_rval = WCSLCAT_BUFLEN,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Full buffer (no NUL), non-empty src (1)",
	.wt_src = L"光",
	.wt_rval = WCSLCAT_BUFLEN + 1,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Full buffer (no NUL), non-empty src (2)",
	.wt_src = L"Link? Zelda!",
	.wt_rval = WCSLCAT_BUFLEN + 12,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' }
}, {
	.wt_desc = "Full buffer (w/ NUL), empty src",
	.wt_src = L"",
	.wt_rval = WCSLCAT_BUFLEN - 1,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' }
}, {
	.wt_desc = "Full buffer (w/ NUL), non-empty src (1)",
	.wt_src = L"光",
	.wt_rval = WCSLCAT_BUFLEN,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' }
}, {
	.wt_desc = "Full buffer (w/ NUL), non-empty src (2)",
	.wt_src = L"Link? Zelda!",
	.wt_rval = WCSLCAT_BUFLEN + 11,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' },
	.wt_res = { L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'\0' }
}, {
	.wt_desc = "Partial buffer (1)",
	.wt_src = L"",
	.wt_rval = 5,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'H', L'e', L'l', L'l', L'o', L'\0', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'H', L'e', L'l', L'l', L'o', L'\0', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
}, {
	.wt_desc = "Partial buffer (2)",
	.wt_src = L", world!",
	.wt_rval = 13,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'H', L'e', L'l', L'l', L'o', L'\0', L'-', L'-',
		    L'-', L'-', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'H', L'e', L'l', L'l', L'o', L',', L' ', L'w',
		    L'o', L'r', L'l', L'd', L'!', L'\0', L'-', L'-' },
}, {
	.wt_desc = "Partial buffer truncation",
	.wt_src = L"7777 Aerith lives?",
	.wt_rval = 27,
	.wt_dstlen = WCSLCAT_BUFLEN,
	.wt_buf = { L'S', L'e', L'p', L'h', L'i', L'r', L'o', L't',
		    L'h', L'\0', L'-', L'-', L'-', L'-', L'-', L'-' },
	.wt_res = { L'S', L'e', L'p', L'h', L'i', L'r', L'o', L't',
		    L'h', L'7', L'7', L'7', L'7', L' ', L'A', L'\0' }
}  };

static bool
wcslcat_test_one(const wcslcat_test_t *test)
{
	wchar_t buf[WCSLCAT_BUFLEN];
	size_t wcret;
	bool ret = true;

	(void) wmemcpy(buf, test->wt_buf, ARRAY_SIZE(test->wt_buf));
	wcret = wcslcat(buf, test->wt_src, test->wt_dstlen);

	if (wcret != test->wt_rval) {
		warnx("TEST FAILED: %s: wcslcat() returned %zu, expected %zu",
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

	for (size_t i = 0; i < ARRAY_SIZE(wcslcat_tests); i++) {
		if (!wcslcat_test_one(&wcslcat_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
