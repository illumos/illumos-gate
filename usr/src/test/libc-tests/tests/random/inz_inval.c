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
 * Verify that using MC_INHERIT_ZERO doesn't work on mappings that aren't
 * anonymous private mappings.
 */

#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <wait.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main(void)
{
	void *buf;
	int ret, fd;
	char *template = "/tmp/inz_inval.XXXXXX";
	char *tmpfile;
	size_t mapsz = sysconf(_SC_PAGESIZE) * 2;
	caddr_t bad = (caddr_t)(uintptr_t)23;

	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(buf != MAP_FAILED);

	/* Bad arguments to memcntl */
	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, bad, 0, 0);
	assert(ret == -1);
	assert(errno == EINVAL);

	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, PROT_READ, 0);
	assert(ret == -1);
	assert(errno == EINVAL);

	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, bad, PROT_READ | PRIVATE, 0);
	assert(ret == -1);
	assert(errno == EINVAL);

	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 1);
	assert(ret == -1);
	assert(errno == EINVAL);

	ret = munmap(buf, mapsz);
	assert(ret == 0);

	/* Mapping non-existant region */
	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == -1);
	assert(errno == ENOMEM);

	/* Map anon MAP_SHARED */
	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	assert(buf != MAP_FAILED);
	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == -1);
	assert(errno == EINVAL);
	ret = munmap(buf, mapsz);
	assert(ret == 0);

	/* Grab a temp file and get it to be the right size */
	tmpfile = strdup(template);
	assert(tmpfile != NULL);
	fd = mkstemp(tmpfile);
	assert(fd >= 0);
	ret = ftruncate(fd, mapsz);
	assert(ret == 0);

	/* MAP_PRIVATE file */
	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	assert(buf != MAP_FAILED);
	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == -1);
	assert(errno == EINVAL);
	ret = munmap(buf, mapsz);
	assert(ret == 0);

	/* MAP_SHARED file */
	buf = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	assert(buf != MAP_FAILED);
	ret = memcntl(buf, mapsz, MC_INHERIT_ZERO, 0, 0, 0);
	assert(ret == -1);
	assert(errno == EINVAL);
	ret = munmap(buf, mapsz);
	assert(ret == 0);

	ret = close(fd);
	assert(ret == 0);
	(void) unlink(tmpfile);
	free(tmpfile);

	return (0);
}
