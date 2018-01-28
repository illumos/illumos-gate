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
 * Copyright 2017 Joyent, Inc.
 */

#include <unistd.h>

int
startup_wait(int *val)
{
	return (*val);
}

int
baz(void)
{
	return (0);
}

int bar_val = 0;

int
bar(void)
{
	return (bar_val++);
}

int
main(int argc, char **argv)
{
	int wait = 1;

	while (startup_wait(&wait)) {
		usleep(1000);
	}

	if (baz() != 1)
		return (1);

	if (bar() != 0)
		return (1);

	if (bar() != 2)
		return (1);

	if (bar() != 2)
		return (1);

	return (0);
}
