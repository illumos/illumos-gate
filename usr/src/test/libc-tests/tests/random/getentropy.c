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
 * Test getentropy(3C)
 */

#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>

int
main(void)
{
	int ret;
	void *addr;
	uint8_t errbuf[512];
	uint8_t buf[128];

	ret = getentropy(buf, sizeof (buf));
	assert(ret == 0);

	/* Max buffer is 256 bytes, verify if we go larger, we error */
	ret = getentropy(errbuf, sizeof (errbuf));
	assert(ret == -1);
	assert(errno == EIO);

	ret = getentropy(errbuf, 257);
	assert(ret == -1);
	assert(errno == EIO);

	ret = getentropy(errbuf, 256);
	assert(ret == 0);

	ret = getentropy(errbuf, 0);
	assert(ret == 0);

	/* Bad buffers */
	ret = getentropy(NULL, sizeof (buf));
	assert(ret == -1);
	assert(errno == EFAULT);

	/* Jump through a hoop to know we'll always have a bad address */
	addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(addr != MAP_FAILED);
	ret = munmap(addr, 4096);
	assert(ret == 0);
	ret = getentropy(addr, sizeof (buf));
	assert(ret == -1);
	assert(errno == EFAULT);

	return (0);
}
