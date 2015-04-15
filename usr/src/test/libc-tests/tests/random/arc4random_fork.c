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
 * Tests to make sure that a parent and child do not get the same arc4random
 * state across a fork. This source file is used to make two tests. One which
 * initializes the data in advance, one of which does not.
 */

#include <stdlib.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

typedef struct arc4_fork {
	uint32_t	af_parent;
	uint32_t	af_child;
	uint8_t		af_pbuf[4096];
	uint8_t		af_cbuf[4096];
} arc4_fork_t;

arc4_fork_t *fork_data;

int
main(void)
{
	int e, i;
	pid_t p, child;

#ifdef	ARC4_PREINIT
	(void) arc4random();
#endif

	fork_data = (arc4_fork_t *)mmap(NULL, sizeof (arc4_fork_t),
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	assert(fork_data != MAP_FAILED);

	p = fork();
	assert(p != -1);
	if (p == 0) {
		fork_data->af_child = arc4random();
		arc4random_buf(fork_data->af_cbuf, sizeof (fork_data->af_cbuf));
		exit(0);
	}

	fork_data->af_parent = arc4random();
	arc4random_buf(fork_data->af_pbuf, sizeof (fork_data->af_pbuf));
	do {
		child = wait(&e);
	} while (child == -1 && errno == EINTR);
	assert(child == p);

	/* Now verify our data doesn't match */
	assert(fork_data->af_parent != fork_data->af_child);

	/*
	 * For the buffer here, we're mostly concerned that they aren't somehow
	 * getting the same stream.
	 */
	for (i = 0; i < sizeof (fork_data->af_pbuf); i++) {
		if (fork_data->af_pbuf[i] != fork_data->af_cbuf[i])
			break;
	}
	assert(i != sizeof (fork_data->af_pbuf));

	return (0);
}
