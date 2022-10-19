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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <port.h>
#include <err.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/poll.h>

/*
 * Attempt to trigger the #15036 regression.  This depends on a subsequent
 * allocation in the same slab setting a bit at a specific offset, so reliable
 * detection of the issue is a challenge.  This test uses brute force in its
 * attempt, but cannot guarantee to trigger the behavior on a system affected by
 * the issue.
 */

/*
 * We need regular files on a regular filesystem for fs_poll to be called.
 * Assume that we can find some in our own tests dir.
 *
 * As for repetitions, this is not especially consistent, so really hammer
 * things out of brute force.
 */
#define	FILE_SRC	"/opt/os-tests/tests"
#define	FILE_COUNT	10
#define	TEST_REPEAT	10000

static uint_t
find_test_files(const char *dir, uint_t count, int *result_fds)
{
	assert(count > 0);

	DIR *dirp;

	dirp = opendir(dir);
	if (dirp == NULL) {
		return (0);
	}

	dirent_t *de;
	uint_t nvalid = 0;
	while ((de = readdir(dirp)) != NULL) {
		char path[MAXPATHLEN];
		struct stat st;

		(void) snprintf(path, sizeof (path), "%s/%s", dir, de->d_name);
		if (lstat(path, &st) != 0 || (st.st_mode & S_IFREG) == 0) {
			continue;
		}
		result_fds[nvalid] = open(path, O_RDONLY, 0);
		if (result_fds[nvalid] < 0) {
			continue;
		}

		nvalid++;
		if (nvalid == count) {
			break;
		}
	}

	(void) closedir(dirp);
	return (nvalid);
}

int
main(int argc, char *argv[])
{
	int poll_fds[FILE_COUNT];

	if (find_test_files(FILE_SRC, FILE_COUNT, poll_fds) != FILE_COUNT) {
		errx(EXIT_FAILURE, "FAIL - count not open test files to poll");
	}

	for (uint_t i = 0; i < TEST_REPEAT; i++) {
		int port_fds[FILE_COUNT];

		for (uint_t j = 0; j < FILE_COUNT; j++) {
			port_fds[j] = port_create();
			if (port_fds[j] < 0) {
				err(EXIT_FAILURE, "FAIL - port_create()");
			}

			int res = port_associate(port_fds[j], PORT_SOURCE_FD,
			    (uintptr_t)poll_fds[j], POLLIN, NULL);
			if (res != 0) {
				err(EXIT_FAILURE, "FAIL - port_associate()");
			}
		}

		for (uint_t j = 0; j < FILE_COUNT; j++) {
			int res = port_dissociate(port_fds[j], PORT_SOURCE_FD,
			    (uintptr_t)poll_fds[j]);
			if (res != 0) {
				err(EXIT_FAILURE, "FAIL - port_dissociate()");
			}
			(void) close(port_fds[j]);
		}
	}

	(void) printf("PASS\n");
	return (EXIT_SUCCESS);
}
