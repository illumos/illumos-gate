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
 * Copyright 2025 Hans Rosenfeld
 */

/*
 * Basic dprintf test. Print something into a pipe, and verify that we can
 * read it back.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/fork.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

static const char hello[] = "Hello ";
static const char world[] = "World!";

static void
check_len(const char *ident, ssize_t len, ssize_t exp_len)
{
	if (len == -1)
		err(EXIT_FAILURE, "%s", ident);
	if (len != exp_len)
		errx(EXIT_FAILURE, "unexpected length from %s: %zd "
		    "(expected %zd)", ident, len, exp_len);
}

static void
check_buf(const char *buf, const char *exp, int len)
{
	if (strncmp(buf, exp, len) != 0)
		errx(EXIT_FAILURE, "unexpected buffer contents:\n"
		    "%s\nexpected:\n%s", buf, exp);
}

int
main(int argc, char **argv)
{
	int ret = -1;
	char buf[40] = { 0 };
	int fd[2];
	ssize_t len;
	pid_t pid;

	if (pipe(fd) == -1)
		err(EXIT_FAILURE, "pipe(fd)");

	pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);

	switch (pid) {
	case -1:
		err(EXIT_FAILURE, "fork()");

	case 0:
		(void) close(fd[0]);

		len = dprintf(fd[1], "%s", hello);
		check_len("dprintf(hello)", len, strlen(hello));

		len = dprintf(fd[1], "%s\n", world);
		check_len("dprintf(world)", len, strlen(world) + 1);

		len = dprintf(fd[1], "%sagain, %s\n", hello, world);
		check_len("dprintf(hello, world)", len,
		    strlen(hello) + strlen(world) + 8);

		return (0);

	default:
		(void) close(fd[1]);

		if (waitpid(pid, &ret, 0) != pid)
			err(EXIT_FAILURE, "waitpid()");

		if (ret != 0)
			errx(EXIT_FAILURE, "dprintf tests failed");

		len = read(fd[0], buf, sizeof (buf));
		check_len("read()", len,
		    2 * (strlen(hello) + strlen(world) + 1) + 7);
		check_buf(buf, "Hello World!\nHello again, World!\n", len);
	}

	(void) printf("dprintf tests passed\n");
	return (0);
}
