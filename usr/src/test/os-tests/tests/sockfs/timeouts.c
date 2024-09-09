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
 * Test that setting timeout options on a UNIX stream socket after connection
 * works, in that the timeout values are accepted and subsequently returned.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

static bool pass = true;

typedef struct to_test {
	char *name;		/* Name of the test */
	int option;		/* Socket option */
	time_t sec;		/* Number of seconds */
	suseconds_t usec;	/* and microseconds */
} to_test_t;

static to_test_t tests[] = {
	{
		.name = "Set 5s receive",
		.option = SO_RCVTIMEO,
		.sec = 5,
		.usec = 0
	}, {
		.name = "Set 5s send",
		.option = SO_SNDTIMEO,
		.sec = 5,
		.usec = 0
	}, {
		.name = "Set 15410s receive",
		.option = SO_RCVTIMEO,
		.sec = 15410,
		.usec = 0
	}, {
		.name = "Set 15410s send",
		.option = SO_SNDTIMEO,
		.sec = 15410,
		.usec = 0
	}, {
		.name = "Set 0s receive",
		.option = SO_RCVTIMEO,
		.sec = 0,
		.usec = 0
	}, {
		.name = "Set 0s send",
		.option = SO_SNDTIMEO,
		.sec = 0,
		.usec = 0
	}, {
		.name = "Set 5.5s receive",
		.option = SO_RCVTIMEO,
		.sec = 5,
		.usec = MICROSEC / 2,
	}, {
		.name = "Set 5.5s send",
		.option = SO_SNDTIMEO,
		.sec = 5,
		.usec = MICROSEC / 2,
	}
};

static int
server(const char *sockpath)
{
	struct sockaddr_un addr;
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		err(EXIT_FAILURE, "failed to create socket");
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, sockpath, sizeof (addr.sun_path));
	if (bind(sock, (struct sockaddr *)&addr, sizeof (addr)) == -1)
		err(EXIT_FAILURE, "bind failed");
	if (listen(sock, 0) == -1)
		err(EXIT_FAILURE, "listen failed");

	return (sock);
}

static int
client(const char *sockpath)
{
	struct sockaddr_un addr;
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		err(EXIT_FAILURE, "failed to create socket");
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, sockpath, sizeof (addr.sun_path));
	if (connect(sock, (struct sockaddr *)&addr, sizeof (addr)) == -1)
		err(EXIT_FAILURE, "could not connect to server socket");

	return (sock);
}

static void __PRINTFLIKE(2)
fail(const to_test_t *t, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "[FAIL] %s: ", t->name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	pass = false;
}

int
main(int argc, const char **argv)
{
	char sockpath[] = "/tmp/to.testsock.XXXXXX";
	int sfd, cfd;

	if (mktemp(sockpath) == NULL)
		err(EXIT_FAILURE, "Failed to make temporary socket path");

	sfd = server(sockpath);
	cfd = client(sockpath);

	for (uint_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const to_test_t *t = &tests[i];
		struct timeval tv = { 0 };
		socklen_t optlen;

		tv.tv_sec = t->sec;
		tv.tv_usec = t->usec;
		optlen = sizeof (tv);
		if (setsockopt(cfd, SOL_SOCKET, t->option, &tv, optlen) != 0) {
			fail(t, "setsockopt error: %s", strerror(errno));
			pass = false;
			continue;
		}

		bzero(&tv, sizeof (tv));
		if (getsockopt(cfd, SOL_SOCKET, t->option, &tv, &optlen) != 0) {
			fail(t, "getsockopt error: %s", strerror(errno));
			pass = false;
			continue;
		}

		if (optlen != sizeof (tv)) {
			fail(t,
			    "getsockopt returned incorrect length: %ld"
			    " vs. %zd", (long)optlen, sizeof (tv));
			continue;
		}

		if (tv.tv_sec != t->sec) {
			fail(t, "returned tv_sec value mismatch: %ld "
			    "vs. expected %ld", tv.tv_sec, t->sec);
			continue;
		}
		if (tv.tv_usec != t->usec) {
			fail(t, "returned tv_usec value mismatch: %ld "
			    "vs. expected %ld", tv.tv_usec, t->usec);
			continue;
		}

		printf("[PASS] %s\n", t->name);
	}

	close(cfd);
	close(sfd);
	unlink(sockpath);

	return (pass ? 0 : EXIT_FAILURE);
}
