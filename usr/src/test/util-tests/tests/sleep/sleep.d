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
 * Copyright 2019 Robert Mustacchi
 */

/*
 * This is a companion DTrace script that is used by the sleep test. It
 * checks if the executed program asks to sleep for the right amount of
 * time and then exits in a way to indicate this. At the same time, it
 * always uses the SIGALRM feature of sleep(1) to make sure that sleep
 * doesn't continue executing (and also to make sure that the feature
 * works).
 *
 * We expect the number of seconds in $1 and the number of nanoseconds
 * in $2. This script should be invoked as dtrace -s sleep.d -c
 * '/usr/bin/sleep <waittime>' <seconds> <nanoseconds>.
 */
pid$target::nanosleep:entry
/args[0]->tv_sec == $1 && args[0]->tv_nsec == $2/
{
	raise(SIGALRM);
	exit(0);
}

pid$target::nanosleep:entry
{
	print(*args[0]);
	raise(SIGALRM);
	exit(1);
}
