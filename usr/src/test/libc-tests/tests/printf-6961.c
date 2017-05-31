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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Regression test for illumos #6961. We mistakenly zeroed out a character that
 * we shouldn't have when dealing with a 64-bit libc.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

static void
print_diff(char *test, char *correct, char *wrong)
{
	int i;
	printf("test failed: received incorrect octal for case %s\n", test);
	for (i = 0; i < 32; i++) {
		printf("byte %d: expected 0x%x, found 0x%x\n", i, correct[i],
		    wrong[i]);
	}
}

int
main(void)
{
	int ret = 0;
	char buf[32];

	/* ~0L in octal */
	char octal0[] = { 'r', 'r', 'r', 'r', '1', '7', '7', '7', '7', '7', '7',
	    '7', '7', '7', '7', '7', '7', '7', '7', '7', '7', '7', '7', '7',
	    '7', '7', '\0', 'r', 'r', 'r', 'r', 'r', 'r' };

	char decimal0[] = { 'r', 'r', 'r', 'r', '-', '1', '\0', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r' };

	char hex0[] = { 'r', 'r', 'r', 'r', 'f', 'f', 'f', 'f', 'f', 'f',
	    'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', '\0', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r' };

	/* 42 in octal */
	char octal1[] = { 'r', 'r', 'r', 'r', '5', '2', '\0', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r' };

	/* 42 in decimal */
	char decimal1[] = { 'r', 'r', 'r', 'r', '4', '2', '\0', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r' };

	/* 42 in hex */
	char hex1[] = { 'r', 'r', 'r', 'r', '2', 'a', '\0', 'r', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r',
	    'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 'r' };


	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%lo", ~0L);
	if (bcmp(octal0, buf, sizeof (buf)) != 0) {
		print_diff("~0 in Octal", octal0, buf);
		ret++;
	}

	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%lo", 42L);
	if (bcmp(octal1, buf, sizeof (buf)) != 0) {
		print_diff("42 in Octal", octal1, buf);
		ret++;
	}

	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%ld", ~0L);
	if (bcmp(decimal0, buf, sizeof (buf)) != 0) {
		print_diff("~0 in Decimal", decimal0, buf);
		ret++;
	}

	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%ld", 42L);
	if (bcmp(decimal1, buf, sizeof (buf)) != 0) {
		print_diff("42 in Decimal", decimal1, buf);
		ret++;
	}

	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%lx", ~0L);
	if (bcmp(hex0, buf, sizeof (buf)) != 0) {
		print_diff("~0 in Hex", hex0, buf);
		ret++;
	}

	(void) memset(buf, 'r', sizeof (buf));
	(void) snprintf(buf + 4, sizeof (buf), "%lx", 42L);
	if (bcmp(hex1, buf, sizeof (buf)) != 0) {
		print_diff("42 in Hex", hex1, buf);
		ret++;
	}

	return (ret);
}
