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
#include <port.h>
#include <err.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <stdbool.h>

static bool
has_event(int pfd)
{
	port_event_t ev = { 0 };
	timespec_t ts = { 0 };

	/* Because of illumos 14912, more care needs to be taken here */
	int res = port_get(pfd, &ev, &ts);
	if (res != 0 || ev.portev_source == 0) {
		return (false);
	} else {
		return (true);
	}
}

int
main(int argc, char *argv[])
{
	int res;
	int pipes[2];

	res = pipe2(pipes, 0);
	assert(res == 0);

	int pfd = port_create();
	assert(pfd >= 0);

	res = port_associate(pfd, PORT_SOURCE_FD, (uintptr_t)pipes[1], POLLIN,
	    NULL);
	assert(res == 0);

	if (has_event(pfd)) {
		errx(EXIT_FAILURE, "FAIL - unexpected early event");
	}

	char port_path[MAXPATHLEN];
	(void) sprintf(port_path, "/proc/%d/fd/%d", getpid(), pfd);

	/* incur the procfs FDINFO access */
	struct stat sbuf;
	res = lstat(port_path, &sbuf);
	assert(res == 0);

	/* write a byte to wake up the pipe */
	(void) write(pipes[0], port_path, 1);

	/*
	 * Check to see that the FDINFO access did not detach our registration
	 * for the event port.
	 */
	if (!has_event(pfd)) {
		errx(EXIT_FAILURE, "FAIL - no event found");
	}

	(void) printf("PASS\n");
	return (EXIT_SUCCESS);
}
