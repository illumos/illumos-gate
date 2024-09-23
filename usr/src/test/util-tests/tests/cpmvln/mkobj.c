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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This is a utility program for the various cp/mv/ln tests to create file
 * system objects which are not as simple with basic utilities. In particular we
 * support creating bound unix domain sockets, doors, and throw in a fifo for
 * good measure (though that's a bit easier).
 */

#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <door.h>
#include <stropts.h>
#include <string.h>
#include <sys/socket.h>

static void
mkobj_server(void *cookie, char *argp, size_t size, door_desc_t *dp,
    uint_t ndesc)
{
	(void) door_return(NULL, 0, NULL, 0);
}

int
main(int argc, char *argv[])
{
	int c;
	const char *door = NULL;
	const char *fifo = NULL;
	const char *uds = NULL;

	while ((c = getopt(argc, argv, ":d:f:s:")) != -1) {
		switch (c) {
		case 'd':
			door = optarg;
			break;
		case 'f':
			fifo = optarg;
			break;
		case 's':
			uds = optarg;
			break;
		case ':':
			errx(EXIT_FAILURE, "option -%c requires an operand", c);
		case '?':
			(void) fprintf(stderr, "unknown option: -%c\n", c);
			(void) fprintf(stderr, "mkobj [-d door] [-f fifo] "
			    "[-s socket]\n");
			exit(EXIT_FAILURE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 0) {
		errx(EXIT_FAILURE, "extraneous arguments starting with %s",
		    argv[0]);
	}

	if (door == NULL && fifo == NULL && uds == NULL) {
		errx(EXIT_FAILURE, "at least one of -d, -f and -s must be "
		    "specified");
	}

	if (door != NULL) {
		int fd;

		if ((fd = open(door, O_CREAT | O_EXCL | O_RDWR, 0666)) < 0) {
			err(EXIT_FAILURE, "failed to create file %s for door "
			    "server attachment", door);
		}

		(void) close(fd);

		if ((fd = door_create(mkobj_server, NULL, DOOR_REFUSE_DESC |
		    DOOR_NO_CANCEL)) < 0) {
			err(EXIT_FAILURE, "failed to create door server");
		}

		if (fattach(fd, door) != 0) {
			err(EXIT_FAILURE, "failed to attach door to %s", door);
		}
	}

	if (fifo != NULL) {
		if (mkfifo(fifo, 0666) != 0) {
			err(EXIT_FAILURE, "failed to make fifo %s", fifo);
		}
	}

	if (uds != NULL) {
		int fd;
		struct sockaddr_un un;

		if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
			err(EXIT_FAILURE, "failed to create a unix domain "
			    "socket");
		}

		(void) memset(&un, 0, sizeof (un));
		un.sun_family = AF_UNIX;
		if (strlcpy(un.sun_path, uds, sizeof (un.sun_path)) >=
		    sizeof (un.sun_path)) {
			errx(EXIT_FAILURE, "UDS path %s doesn't fit in "
			    "sockaddr sun_path", uds);
		}

		if (bind(fd, (struct sockaddr *)&un, sizeof (un)) != 0) {
			errx(EXIT_FAILURE, "failed to bind uds to %s", uds);
		}
	}

	/*
	 * Explicitly exit to ensure that we don't end up letting door threads
	 * stick around.
	 */
	exit(EXIT_SUCCESS);
}
