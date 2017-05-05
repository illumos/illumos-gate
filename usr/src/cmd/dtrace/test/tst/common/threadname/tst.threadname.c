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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * All we're doing is constantly modifying a thread name while DTrace is
 * watching us, making sure we don't break.
 */

#include <sys/fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

#define	NR_THREADS (100)
#define	RUNTIME (30) /* seconds */

static void
random_ascii(char *buf, size_t bufsize)
{
	char table[] = "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ,.-#'?!";
	size_t len = rand() % bufsize;

	bzero(buf, bufsize);

	for (size_t i = 0; i < len; i++) {
		buf[i] = table[rand() % (sizeof (table) - 1)];
	}
}

static void
busy()
{
	struct timeval tv1;
	struct timeval tv2;

	if (gettimeofday(&tv1, NULL) != 0)
		abort();

	for (;;) {
		static volatile int i;
		for (i = 0; i < 2000000; i++)
			;

		if (gettimeofday(&tv2, NULL) != 0)
			abort();

		/* janky, but we don't care */
		if (tv2.tv_sec != tv1.tv_sec)
			return;
	}
}

static void *
thread(void *arg)
{
	char name[PTHREAD_MAX_NAMELEN_NP];

	for (size_t i = 0; ; i++) {
		random_ascii(name, sizeof (name));

		if ((i % 100) == 0) {
			if (pthread_setname_np(pthread_self(), NULL) != 0)
				abort();
		} else {
			(void) pthread_setname_np(pthread_self(), name);
		}

		busy();
	}

	return (NULL);
}

int
main(int argc, char **argv)
{
	pthread_t tids[NR_THREADS];

	for (size_t i = 0; i < NR_THREADS; i++) {
		if (pthread_create(&tids[i], NULL, thread, NULL) != 0)
			exit(EXIT_FAILURE);
	}

	sleep(RUNTIME);
	exit(EXIT_SUCCESS);
}
