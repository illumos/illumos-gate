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
 * Copyright 2021, Richard Lowe.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>

extern uint64_t test_data(void);
extern uint64_t test_bss(void);

#define	CORRECT_DATA	8675309
#define	CORRECT_BSS	0

int
main(int argc, char **argv)
{
	uint64_t td = test_data();
	uint64_t tb = test_bss();

	if (td != CORRECT_DATA) {
		printf("FAIL: test data mismatch: should be %ld is %ld\n",
		    CORRECT_DATA, td);
		abort();
	}

	if (tb != CORRECT_BSS) {
		printf("FAIL: test bss mismatch: should be %ld is %ld\n",
		    CORRECT_BSS, tb);
		abort();
	}

	printf("SUCCESS\n");

	return (0);
}
