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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This is a regression test for illumos#14933 where asprintf() in small buffers
 * was thrown off by an embedded NUL. Test both short and large buffers with
 * embedded NULs. "large" at the time 14933 was anything that exceeded 128
 * bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

const char *longstr = "0123456789abcdefghijklmnopqrstuvwxyz";

int
main(void)
{
	int eval = EXIT_SUCCESS;
	char short_exp[] = { '0', '1', '2', '3', '\0', 'a', 'b', 'c', '\0' };
	size_t short_len = ARRAY_SIZE(short_exp);
	size_t long_len;
	char *out;
	int ret;

	ret = asprintf(&out, "%s%c%s", "0123", '\0', "abc");
	if (ret != short_len - 1) {
		(void) fprintf(stderr, "TEST FAILED: short asprintf returned "
		    "wrong length: found %u, expected %u\n", ret,
		    short_len - 1);
		eval = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: short buffer embedded nul has "
		    "correct length\n");
	}

	if (memcmp(short_exp, out, short_len) != 0) {
		(void) fprintf(stderr, "TEST FAILED: short example returned "
		    "wrong value\nexpected:");
		for (size_t i = 0; i < short_len; i++) {
			(void) fprintf(stderr, " 0x%02x", short_exp[i]);
		}
		(void) fprintf(stderr, "\nactual:  ");
		for (size_t i = 0; i < short_len; i++) {
			(void) fprintf(stderr, " 0x%02x", out[i]);
		}
		(void) fputc('\n', stderr);
		eval = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: short buffer data contents "
		    "match\n");
	}

	free(out);
	long_len = strlen(longstr) * 5 + 5;
	ret = asprintf(&out, "%s%c%s%c%s%c%s%c%s", longstr, '\0', longstr, '\0',
	    longstr, '\0', longstr, '\0', longstr);
	if (ret != long_len - 1) {
		(void) fprintf(stderr, "TEST FAILED: long asprintf returned "
		    "wrong length: found %u, expected %u\n", ret, long_len - 1);
		eval = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: long buffer embedded nul has "
		    "correct length\n");
	}

	bool large_pass = true;
	for (uint_t i = 0; i < 5; i++) {
		size_t offset = (strlen(longstr) + 1) * i;
		if (strcmp(longstr, out + offset) != 0) {
			(void) fprintf(stderr, "TEST FAILED: long asprintf "
			    "data buffer mismatch at copy %u\n", i);
			eval = EXIT_FAILURE;
			large_pass = false;
		}
	}
	if (large_pass) {
		(void) printf("TEST PASSED: long buffer data contents match\n");
	}

	return (eval);
}
