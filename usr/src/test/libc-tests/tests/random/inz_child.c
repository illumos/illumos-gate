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
 * Verify that using MC_INHERIT_ZERO works just fine when applied to an entire
 * region across multiple children.
 */

#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <wait.h>

static int nchild = 5;

int
main(void)
{
	void *buf;
	pid_t child;
	int ret, i;
	siginfo_t info;
	uint8_t *ubuf;
	size_t mapsz = sysconf(_SC_PAGESIZE) * 2;

	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(buf != MAP_FAILED);

	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == 0);

again:
	memset(buf, 'a' + nchild, mapsz);
	child = fork();
	if (child == 0) {
		nchild--;
		for (i = 0, ubuf = buf; i < mapsz; i++)
			assert(ubuf[i] == 0);
		if (nchild != 0)
			goto again;
		exit(0);
	}
	assert(child != -1);

	do {
		ret = waitid(P_PID, child, &info, WEXITED);
	} while (ret == -1 && errno == EINTR);
	assert(ret == 0);
	assert(info.si_pid == child);
	assert(info.si_status == 0);

	for (i = 0, ubuf = buf; i < mapsz; i++)
		assert(ubuf[i] == 'a' + nchild);

	return (0);
}
