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
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * Test getrandom(2)
 */

#include <sys/random.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>

int
main(void)
{
	int ret;
	void *addr;
	uint8_t buf[32];
	uint8_t bigbuf[4096];

	/* Go through flags values, start with invalid */
	ret = getrandom(buf, sizeof (buf), 42);
	assert(ret == -1);
	assert(errno == EINVAL);

	ret = getrandom(buf, sizeof (buf), 0);
	assert(ret >= 0);

	ret = getrandom(buf, sizeof (buf), GRND_NONBLOCK);
	assert(ret >= 0);

	ret = getrandom(buf, sizeof (buf), GRND_RANDOM);
	assert(ret >= 0);

	ret = getrandom(buf, sizeof (buf), GRND_RANDOM | GRND_NONBLOCK);
	assert(ret >= 0);

	ret = getrandom(buf, sizeof (buf), (GRND_RANDOM | GRND_NONBLOCK) << 1);
	assert(ret == -1);
	assert(errno == EINVAL);

	/* Bad buffer addresses, eg. EFAULT */
	ret = getrandom(NULL, sizeof (buf), 0);
	assert(ret == -1);
	assert(errno == EFAULT);

	ret = getrandom(NULL, sizeof (buf), GRND_RANDOM);
	assert(ret == -1);
	assert(errno == EFAULT);

	/* Jump through a hoop to know we'll always have a bad address */
	addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(addr != MAP_FAILED);
	ret = munmap(addr, 4096);
	assert(ret == 0);
	ret = getrandom(addr, sizeof (buf), 0);
	assert(ret == -1);
	assert(errno == EFAULT);
	ret = getrandom(addr, sizeof (buf), GRND_RANDOM);
	assert(ret == -1);
	assert(errno == EFAULT);

	/* Verify that we get rounded down on a getrandom of /dev/random */
	ret = getrandom(bigbuf, sizeof (buf), GRND_RANDOM);
	assert(ret >= 0 && ret < sizeof (bigbuf));

	/* Do a few simple sets where we know we should get data */
	ret = getrandom(buf, sizeof (buf), 0);
	assert(ret == sizeof (buf));
	ret = getrandom(buf, sizeof (buf), GRND_RANDOM);
	assert(ret == sizeof (buf));

	return (0);
}
