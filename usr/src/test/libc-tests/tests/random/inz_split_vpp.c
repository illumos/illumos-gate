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
 * Verify that using MC_INHERIT_ZERO works just fine when applied to a subset of
 * a region, meaning that we should have created a struct vpage for that region.
 * Then unmap a hole in the middle, so that way we force subsets of children
 * that have struct vpage entries.
 */

#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <wait.h>

int
main(void)
{
	void *buf;
	pid_t child;
	int ret, i;
	siginfo_t info;
	uint8_t *ubuf;
	size_t pgsz = sysconf(_SC_PAGESIZE);
	size_t mapsz = 10 * pgsz;
	size_t clrsz = 5 * pgsz;
	size_t clroff = 2 * pgsz;
	size_t spltsz = 1 * pgsz;
	size_t spltoff = 3 * pgsz;

	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(buf != MAP_FAILED);
	memset(buf, 'a', mapsz);

	ret = memcntl(buf + clroff, clrsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == 0);

	ret = munmap(buf + spltoff, spltsz);
	assert(ret == 0);

	child = fork();
	if (child == 0) {
		ubuf = buf;
		for (i = 0; i < clroff; i++)
			assert(ubuf[i] == 'a');
		for (i = clroff; i < spltoff; i++)
			assert(ubuf[i] == 0);
		for (i = spltoff + spltsz; i < clroff + clrsz; i++)
			assert(ubuf[i] == 0);
		for (i = clrsz + clroff; i < mapsz; i++)
			assert(ubuf[i] == 'a');
		exit(0);
	}
	assert(child != -1);

	do {
		ret = waitid(P_PID, child, &info, WEXITED);
	} while (ret == -1 && errno == EINTR);
	assert(ret == 0);
	assert(info.si_pid == child);
	assert(info.si_status == 0);

	ubuf = buf;
	for (i = 0; i < clroff; i++)
		assert(ubuf[i] == 'a');
	for (i = clroff; i < spltoff; i++)
		assert(ubuf[i] == 'a');
	for (i = spltoff + spltsz; i < clroff + clrsz; i++)
		assert(ubuf[i] == 'a');
	for (i = clrsz + clroff; i < mapsz; i++)
		assert(ubuf[i] == 'a');


	return (0);
}
