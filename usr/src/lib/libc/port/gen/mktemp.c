/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	mktemp() expects a string with up to six trailing 'X's.
 *	These will be overlaid with letters, digits and symbols from
 *	the portable filename character set.  If every combination thus
 *	inserted leads to an existing file name, the string is shortened
 *	to length zero and a pointer to a null string is returned.
 *
 *	The guarantee made by mktime() to the caller is that the
 *	generated file name string will not match the string
 *	produced by any other concurrent process using mktemp().
 *	To guarantee uniqueness across the process-id space,
 *	the process-id of the caller is encoded into the string.
 *	To allow repeated calls within the same process to generate
 *	different strings on each call, a sequence number is encoded
 *	into the string along with process-id.
 *
 *	The encoding is performed using radix-64 (6 bits per character),
 *	with 64 characters taken from the portable file name character set.
 *	This allows the six X's to be a representation of a 36-bit integer
 *	composed of bit fields:
 *		( pid | seq )
 *	where the process-id occupies the high-order bits and the sequence
 *	number occupies the low-order bits.  The size of the pid field is
 *	not fixed at the traditional 15 bits (MAXPID = 30000); the system
 *	now allows a larger process-id space and MAXPID is obtained from
 *	the system with a call to sysconf(_SC_MAXPID).
 *
 *	mktime() should fail if fewer than six X's are presented to it.
 *	However, this has been traditionally accepted and is preserved
 *	in the present code.  The consequence is that the 36-bit integer
 *	is reduced to a (6*N)-bit integer, where N is the number of X's.
 *	mktime() fails immediately if the resulting integer is not large
 *	enough to contain MAXPID.
 *
 *	In an attempt to confuse and thwart hackers, the starting
 *	sequence number is randomized using the current time.
 */

#pragma weak _mktemp = mktemp

#define	XCNT  6

#include "lint.h"
#include "mtlib.h"
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

/*
 * 64-bit digits, must be from the POSIX "portable file name character set".
 */
static char
chars[64] = {
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '_',
};

/*
 * Find highest one bit set.
 * Returns bit number of highest bit that is set.
 * Low order bit is number 0, high order bit is number 31.
 */
static int
highbit(uint_t i)
{
	int h = 0;

	if (i & 0xffff0000)
		h += 16, i >>= 16;
	if (i & 0xff00)
		h += 8, i >>= 8;
	if (i & 0xf0)
		h += 4, i >>= 4;
	if (i & 0xc)
		h += 2, i >>= 2;
	if (i & 0x2)
		h += 1;
	return (h);
}

char *
libc_mktemps(char *as, int slen)
{
	/* statics are protected by this static mutex */
	static mutex_t	mktemp_lock = DEFAULTMUTEX;
	static int	pidshift = 0;
	static int	previous_try = 0;
	static pid_t	previous_pid = 0;
	static int	previous_xcnt = XCNT;

	pid_t		pid;
	int		try;
	int		tryshift;
	int		max_try;
	char		*s;
	char		*first_x;
	int		len;
	uint_t		xcnt;
	struct stat64	buf;

	if (as == NULL || *as == '\0')	/* If the string passed is null then */
		return (as);	/* a pointer to a null string is returned. */

	lmutex_lock(&mktemp_lock);

	pid = getpid();
	if (pid != previous_pid) {	/* first time or first after fork() */
		/*
		 * Randomize the starting sequence number in
		 * an attempt to confuse and thwart hackers.
		 * Use the low 12 bits of the time in milliseconds.
		 */
		struct timeval tm;

		(void) gettimeofday(&tm, NULL);
		previous_try = (tm.tv_sec * 1000 + tm.tv_usec / 1000) & 0xfff;
		previous_pid = pid;
		previous_xcnt = XCNT;
	}

	/* for all possible values of pid, 0 <= pid < (1 << pidshift) */
	if (pidshift == 0)	/* one-time initialization */
		pidshift = highbit((uint_t)MAXPID) + 1;

	/* count the X's */
	xcnt = 0;
	len = (int)strlen(as);
	if (slen >= len || slen < 0)
		goto fail;
	len -= slen;
	s = as + (len - 1);
	while ((len != 0) && (xcnt < XCNT) && (*s == 'X')) {
		xcnt++;
		len--;
		--s;
	}
	first_x = s + 1;	/* Remember pointer to the first X */

	/* fail if we don't have enough X's to represent MAXPID */
	if ((tryshift = xcnt * 6 - pidshift) < 0) {
		/*
		 * Some broken programs call mktemp() repeatedly,
		 * passing the same string without reinserting the X's.
		 * Check to see if this is such a call by testing
		 * the trailing characters of the string for a
		 * match with the process-id.
		 */
		uint64_t xpid = 0;		/* reconstructed pid */

		s = as + len;
		for (xcnt = previous_xcnt; xcnt && s > as; xcnt--) {
			int c;
			int i;

			c = *--s;
			for (i = 0; i < 64; i++)
				if (c == chars[i])
					break;
			if (i == 64)
				goto fail;
			xpid = xpid * 64 + i;
		}
		xpid >>= (previous_xcnt * 6 - pidshift);
		xpid &= ((1 << pidshift) - 1);

		if (xpid == pid &&
		    lstat64(as, &buf) == -1 && errno == ENOENT) {
			lmutex_unlock(&mktemp_lock);
			return (as);
		}

		goto fail;
	}

	/* we can try sequence numbers in the range 0 <= try < max_try */
	max_try = 1 << tryshift;
	if (previous_try >= max_try)
		previous_try = 0;

	try = previous_try;
	for (;;) {
		/* num is up to a 36-bit integer ... */
		uint64_t num = ((uint64_t)pid << tryshift) + (uint64_t)try;
		int i;

		/* ... which we represent backwards in base 64 */
		for (i = 0, s = first_x; i < xcnt; i++) {
			*s++ = chars[num & 077];
			num >>= 6;
		}

		if (lstat64(as, &buf) == -1) {
			if (errno != ENOENT)
				break;		/* unrecoverable error */
			/* remember where we left off for the next call */
			previous_try = try + 1;
			previous_xcnt = xcnt;
			lmutex_unlock(&mktemp_lock);
			return (as);
		}

		if (++try == max_try)
			try = 0;
		if (try == previous_try)
			break;
	}

fail:
	lmutex_unlock(&mktemp_lock);
	*as = '\0';
	return (as);
}

char *
mktemp(char *template)
{
	return (libc_mktemps(template, 0));
}
