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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * This program is meant to be a victim process. It will set up its core content
 * and location into the specific place we indicate in its arguments and then
 * sleep until we gcore and ABRT it.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/corectl.h>
#include <libproc.h>
#include <signal.h>

extern int which_ff(uint32_t, uint32_t);

int
main(int argc, char *argv[])
{
	pid_t me = getpid();
	core_content_t content;
	sigset_t set = { 0 };

	if (argc != 3) {
		errx(EXIT_FAILURE, "<content> <dump path>");
	}

	if (proc_str2content(argv[1], &content) != 0) {
		err(EXIT_FAILURE, "failed to parse content %s", argv[1]);
	}

	if (core_set_process_content(&content, me) != 0) {
		err(EXIT_FAILURE, "failed to set core content to %s", argv[1]);
	}

	if (core_set_process_path(argv[2], strlen(argv[2]) + 1, me) != 0) {
		err(EXIT_FAILURE, "failed to set core path to %s", argv[2]);
	}

	/*
	 * Call our library function to make sure it's present before we go and
	 * sleep.
	 */
	(void) which_ff(6, 10);

	for (;;) {
		(void) sigsuspend(&set);
	}

	return (0);
}
