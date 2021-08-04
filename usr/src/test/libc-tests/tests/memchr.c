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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * Various tests for memchr() and memrchr(). Note, this test assumes that the
 * system is either ILP32 or LP64 with an 8-bit unsigned char due to the tests
 * that are explicitly looking at making sure memchr() and memrchr() truncate
 * correctly.
 */

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <err.h>
#include <stdlib.h>

/*
 * memchr_buf is a page sized buffer surrounded by two PROT_NONE pages which are
 * meant to try and catch us walking over the edge of the buffer.
 */
static uint8_t *memchr_buf;
static size_t memchr_buflen;

static void
memchr_setup(void)
{
	size_t pgsz = getpagesize();
	void *addr;

	if (pgsz <= 0) {
		err(EXIT_FAILURE, "failed to get system page size");
	}

	addr = mmap(NULL, 3 * pgsz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == MAP_FAILED) {
		err(EXIT_FAILURE, "failed to mmap %zu bytes", 3 * pgsz);
	}

	memchr_buf = (uint8_t *)addr + pgsz;
	memchr_buflen = pgsz;

	if (mprotect(addr, pgsz, PROT_NONE) != 0) {
		err(EXIT_FAILURE, "failed to protect leading PROT_NONE guard "
		    "at %p", addr);
	}

	addr = (uint8_t *)addr + 2 * pgsz;
	if (mprotect(addr, pgsz, PROT_NONE) != 0) {
		err(EXIT_FAILURE, "failed to protect trailing PROT_NONE guard "
		    "at %p", addr);
	}
}

static boolean_t
memchr_basic(void)
{
	boolean_t ret = B_TRUE;
	const void *targ;
	const void *found;

	(void) memset(memchr_buf, 0, memchr_buflen);
	memchr_buf[0] = 'r';

	if ((found = memchr(memchr_buf, 'r', memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 'r' (1), found %p, "
		    "expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, 'r', memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memrchr failed to find 'r' (1), found %p, "
		    "expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	memchr_buf[memchr_buflen - 1] = 'r';
	targ = &memchr_buf[memchr_buflen - 1];

	if ((found = memchr(memchr_buf, 'r', memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 'r' (2), found %p, "
		    "expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, 'r', memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 'r' (2), found %p, "
		    "expected %p", found, targ);
		warnx("TEST FAILED: memchr failed to find 'r'");
		ret = B_FALSE;
	}

	memchr_buf[0] = 0;

	if ((found = memchr(memchr_buf, 'r', memchr_buflen)) != targ) {
		warnx("TEST FAILED: memchr failed to find 'r' (3), found %p, "
		    "expected %p", found, targ);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, 'r', memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 'r' (3), found %p, "
		    "expected %p", found, targ);
		ret = B_FALSE;
	}

	if (ret) {
		(void) printf("TEST PASSED: basic memchr() and memrchr()\n");
	}
	return (ret);
}

static boolean_t
memchr_notfound(void)
{
	boolean_t ret = B_TRUE;
	const void *found;

	(void) memset(memchr_buf, 0x23, memchr_buflen);

	if ((found = memchr(memchr_buf, 0, memchr_buflen)) != NULL) {
		warnx("TEST FAILED: memchr unexpectedly found value (1), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (memrchr(memchr_buf, 0, memchr_buflen) != NULL) {
		warnx("TEST FAILED: memrchr unexpectedly found value (1), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (memchr(memchr_buf, 0x24, memchr_buflen) != NULL) {
		warnx("TEST FAILED: memchr unexpectedly found value (2), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (memrchr(memchr_buf, 0x24, memchr_buflen) != NULL) {
		warnx("TEST FAILED: memrchr unexpectedly found value (2), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	memchr_buf[1] = 0x24;

	if (memchr(memchr_buf, 0x24, 1) != NULL) {
		warnx("TEST FAILED: memchr unexpectedly found value (3), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (memrchr(memchr_buf, 0x24, 1) != NULL) {
		warnx("TEST FAILED: memrchr unexpectedly found value (3), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	memchr_buf[1] = 0x24;

	if (memchr(memchr_buf + 1, 0x23, 1) != NULL) {
		warnx("TEST FAILED: memchr unexpectedly found value (4), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (memrchr(memchr_buf + 1, 0x23, 1) != NULL) {
		warnx("TEST FAILED: memrchr unexpectedly found value (4), "
		    "found %p, expected %p", found, NULL);
		ret = B_FALSE;
	}

	if (ret) {
		(void) printf("TEST PASSED: memchr() and memrchr() on "
		    "missing values\n");
	}

	return (ret);
}

static boolean_t
memchr_truncation(void)
{
	boolean_t ret = B_TRUE;
	const void *found;
	const void *targ;

	(void) memset(memchr_buf, 0x42, memchr_buflen);

	if ((found = memchr(memchr_buf, 0x42, memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 0x42, found %p, "
		    "expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	targ = &memchr_buf[memchr_buflen - 1];

	if ((found = memrchr(memchr_buf, 0x42, memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 0x42, found %p, "
		    "expected %p", found, targ);
		ret = B_FALSE;
	}

	if ((found = memchr(memchr_buf, 0x430042, memchr_buflen)) !=
	    memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 0x42 with 0x430042, "
		    "found %p, expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, 0x430042, memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 0x42 with 0x430042, "
		    "found %p, expected %p", found, targ);
		ret = B_FALSE;
	}

	/*
	 * -190 is -0xbe, which when cast to an unsigned char will be 0x42.
	 */
	if ((found = memchr(memchr_buf, -190, memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 0x42 with -190, "
		    "found %p, expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, -190, memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 0x42 with -190, "
		    "found %p, expected %p", found, targ);
		ret = B_FALSE;
	}

	if ((found = memchr(memchr_buf, -190, memchr_buflen)) != memchr_buf) {
		warnx("TEST FAILED: memchr failed to find 0x42 with -190, "
		    "found %p, expected %p", found, memchr_buf);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, -190, memchr_buflen)) != targ) {
		warnx("TEST FAILED: memrchr failed to find 0x42 with -190, "
		    "found %p, expected %p", found, targ);
		ret = B_FALSE;
	}

	if ((found = memchr(memchr_buf, 0x42424200, memchr_buflen)) != NULL) {
		warnx("TEST FAILED: memchr somehow found 0x42 with "
		    "0x42424200, found %p, expected NULL", found);
		ret = B_FALSE;
	}

	if ((found = memrchr(memchr_buf, 0x42424200, memchr_buflen)) != NULL) {
		warnx("TEST FAILED: memrchr somehow found 0x42 with "
		    "0x42424200, found %p, expected NULL", found);
		ret = B_FALSE;
	}

	if (ret) {
		(void) printf("TEST PASSED: truncated values\n");
	}

	return (B_TRUE);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	memchr_setup();

	if (!memchr_basic())
		ret = EXIT_FAILURE;
	if (!memchr_notfound())
		ret = EXIT_FAILURE;
	if (!memchr_truncation())
		ret = EXIT_FAILURE;

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
