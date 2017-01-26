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

/* Copyright 2016, Richard Lowe. */

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void
diff_sets(fd_set *a, fd_set *b, size_t size)
{
	for (int i = 0; i < size; i++) {
		if (FD_ISSET(i, a) != FD_ISSET(i, b))
			printf("fd %d: %d should be %d\n", i, FD_ISSET(i, a),
			    FD_ISSET(i, b));
	}
}

void
print_set(fd_set *a, size_t size)
{
	for (int i = 0; i < size; i++) {
		if (FD_ISSET(i, a))
			putc('1', stdout);
		else
			putc('0', stdout);
	}

	putc('\n', stdout);
}

int
main(int argc, char **argv)
{
	struct timeval tv = {0, 0};
	fd_set check, proto;
	fd_set *sread = NULL, *swrite = NULL, *serr = NULL;
	int null, zero, maxfd = -1, nfds;
	char buf[1];

	if (argc != 2)
		errx(1, "usage: select_test <number of fds>");

	nfds = atoi(argv[1]);
	if (errno != 0)
		err(1, "couldn't convert %s to int", argv[1]);

	if (nfds > FD_SETSIZE)
		errx(1, "can't have more fds than FD_SETSIZE %d", FD_SETSIZE);

	FD_ZERO(&proto);
	FD_ZERO(&check);

	switch (arc4random_uniform(3)) {
	case 0:
		sread = &check;
		break;
	case 1:
		swrite = &check;
		break;
	case 2:
		serr = &check;
		break;
	}

	closefrom(3);

	if ((null = open("/dev/null", O_RDONLY)) == -1)
		err(1, "couldn't open /dev/null");
	read(null, &buf, 1);
	read(null, &buf, 1);

	if ((zero = open("/dev/zero", O_RDWR)) == -1)
		err(1, "couldn't open /dev/zero");

	for (int i = zero; i < (zero + nfds); i++) {
		int fd = (serr != NULL) ? null : zero;
		if (arc4random_uniform(100) > 90) {
			FD_SET(i, &proto);
		}

		if (dup2(fd, i) == -1)
			err(1, "couldn't dup fd to fd %d", i);
		maxfd = i;
	}

	if (swrite != NULL)
		puts("write");
	else if (sread != NULL)
		puts("read");
	else if (serr != NULL)
		puts("err");

	print_set(&proto, 80);

	memcpy(&check, &proto, sizeof (check));

	if (select(maxfd + 1, sread, swrite, serr, &tv) == -1)
		err(1, "select failed");

	if (memcmp(&check, &proto, sizeof (check)) != 0) {
		diff_sets(&check, &proto, sizeof (check));
		warnx("fd set mismatch: check: %p  proto: %p", &check, &proto);
		abort();
	}

	return (0);
}
