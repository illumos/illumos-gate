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
 * Copyright 2017 Sebastian Wiedenroth
 */

/*
 * Test for MSG_NOSIGNAL flag.
 */


#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

/* allow the test to build and fail */
#ifndef MSG_NOSIGNAL
#define	MSG_NOSIGNAL 0
#endif

volatile sig_atomic_t sigcount = 0;

void
sigpipe_h(int sig0)
{
	sigcount++;
	signal(SIGPIPE, sigpipe_h);
}

int
main()
{
	signal(SIGPIPE, sigpipe_h);

	int len = 0;
	const char *msg = "hello illumos";

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(4242);

	int s = socket(PF_INET, SOCK_STREAM, 0);
	int c = socket(PF_INET, SOCK_STREAM, 0);
	assert(s >= 0 && c >= 0);

	assert(bind(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0);
	assert(listen(s, 3) >= 0);
	assert(connect(c, (struct sockaddr *)&sin, sizeof (sin)) >= 0);
	assert(close(s) == 0);

	assert(MSG_NOSIGNAL > 0);
	assert(sigcount == 0);

	/* test failure with signal */
	len = send(c, msg, strlen(msg), 0);
	assert(len == -1 && errno == EPIPE);
	sleep(1);
	assert(sigcount == 1);

	/* test failure without signal */
	len = send(c, msg, strlen(msg), MSG_NOSIGNAL);
	assert(len == -1 && errno == EPIPE);
	sleep(1);
	assert(sigcount == 1);

	assert(close(c) == 0);
	return (0);
}
