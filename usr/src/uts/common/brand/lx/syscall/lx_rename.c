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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/fcntl.h>
#include <sys/lx_fcntl.h>

/* From uts/common/syscall/rename.c */
extern int rename(char *, char *);
extern int renameat(int, char *, int, char *);

long
lx_rename(char *p1, char *p2)
{
	return (rename(p1, p2));
}

long
lx_renameat(int atfd1, char *p1, int atfd2, char *p2)
{
	if (atfd1 == LX_AT_FDCWD)
		atfd1 = AT_FDCWD;

	if (atfd2 == LX_AT_FDCWD)
		atfd2 = AT_FDCWD;

	return (renameat(atfd1, p1, atfd2, p2));
}
