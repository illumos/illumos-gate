/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Fast strcmp.  This works one int at a time, using aligned pointers
 * if possible, misaligned pointers if necessary.  To avoid taking
 * faults from going off the end of a page, the code is careful to go
 * a byte-at-a-time when a misaligned pointer is near a page boundary.
 * The code is almost portable, but see the assumptions below.
 */

/*
 * ASSUMPTIONS:
 * sizeof (int) is not greater than 8.
 * sizeof (int) is a power of 2.
 * An int pointer can always be dereferenced even if it is not properly
 *   aligned (though aligned references are assumed to be faster).
 * It is OK to assign bogus values to a pointer (in particular, a
 *   value that is before the beginning of the string) as long as that
 *   pointer is only used with indices big enough to bring us back into
 *   the string.
 * It is OK to reference bytes past the end of a string as long as we
 *   don't cross a page boundary.
 */

#include "lint.h"
#include <limits.h>
#include <unistd.h>
#include <sys/sysconfig.h>
#include "libc.h"

/*
 * This strange expression will test to see if *any* byte in the int is
 * a NUL.  The constants are big enough to allow for ints up to 8 bytes.
 * The two arguments are actually two copies of the same value; this
 * allows the compiler freedom to play with both values for efficiency.
 */
#define	ANYNUL(i1, i2)	(((i1) - (int)0x0101010101010101LL) & ~(i2) & \
		(int)0x8080808080808080ULL)

int
strcmp(const char *str1, const char *str2)
{
	int *s1, *s2;
	int i1, i2;
	int count;
	int b1, b2;
	static int pagesize;

	if (str1 == str2)
		return (0);

	/*
	 * Go 1 byte at a time until at least one pointer is word aligned.
	 * Assumes that sizeof (int) is a power of 2.
	 */
	while ((((int) str1) & (sizeof (int) - 1)) &&
	    (((int) str2) & (sizeof (int) - 1))) {
one_byte:
		if (*str1 != *str2)
			return ((unsigned char)*str1 - (unsigned char)*str2);
		if (*str1 == '\0')
			return (0);
		++str1;
		++str2;
	}

	/*
	 * If one pointer is misaligned, we must be careful not to
	 * dereference it when it points across a page boundary.
	 * If we did, we might go past the end of the segment and
	 * get a SIGSEGV.  Set "count" to the number of ints we can
	 * scan before running into such a boundary.
	 */
	count = INT_MAX;
	if (((int) str1) & (sizeof (int) - 1)) {
		if (pagesize == 0)
			pagesize = _sysconfig(_CONFIG_PAGESIZE);
		count = (pagesize - ((int)str1 & (pagesize - 1))) /
			sizeof (int);
	} else if (((int) str2) & (sizeof (int) - 1)) {
		if (pagesize == 0)
			pagesize = _sysconfig(_CONFIG_PAGESIZE);
		count = (pagesize - ((int)str2 & (pagesize - 1))) /
			sizeof (int);
	}

	s1 = (void *) str1;
	s2 = (void *) str2;

	/*
	 * Go "sizeof (int)" bytes at a time until at least one pointer
	 * is word aligned.
	 *
	 * Unwrap the loop for even a bit more speed.
	 */
	for (;;) {
		/*
		 * Check whether we can test the next 4 ints without
		 * hitting a page boundary.  If we can only test 1, 2,
		 * or 3, go and do that first.  If we can't check any
		 * more, go and test one byte, realign, and start again.
		 */
		count -= 4;
		switch (count) {
		case -1:
			--s1;
			--s2;
			goto do3;	/* check only 3 ints */
		case -2:
			s1 -= 2;
			s2 -= 2;
			goto do2;	/* check only 2 ints */
		case -3:
			s1 -= 3;
			s2 -= 3;
			goto do1;	/* check only 1 int */
		case -4:
		case -5:		/* -5, -6, and -7 come up on the */
		case -6:		/* next time around after we do one */
		case -7:		/* of the 3 gotos above */
			str1 = (void *) s1;
			str2 = (void *) s2;
			goto one_byte;
			/*
			 * The goto above should be explained.  By going
			 * into the middle of the loop, it makes sure
			 * that we advance at least one byte.  We will
			 * stay in that loop until the misaligned pointer
			 * becomes aligned (at the page boundary).  We
			 * will then break out of that loop with the
			 * formerly misaligned pointer now aligned, the
			 * formerly aligned pointer now misaligned, and
			 * we will come back into this loop until the
			 * latter pointer reaches a page boundary.
			 */
		default:		/* at least 4 ints to go */
			break;
		}

		i1 = s1[0];
		i2 = s2[0];
		if (i1 != i2)
			break;
		else if (ANYNUL(i1, i2))
			return (0);

do3:
		i1 = s1[1];
		i2 = s2[1];
		if (i1 != i2)
			break;
		else if (ANYNUL(i1, i2))
			return (0);

do2:
		i1 = s1[2];
		i2 = s2[2];
		if (i1 != i2)
			break;
		else if (ANYNUL(i1, i2))
			return (0);

do1:
		i1 = s1[3];
		i2 = s2[3];
		if (i1 != i2)
			break;
		else if (ANYNUL(i1, i2))
			return (0);

		s1 += 4;
		s2 += 4;
	}

	/* We found a difference.  Go one byte at a time to find where. */
	b1 = i1;		/* save the ints in memory */
	b2 = i2;
	str1 = (void *) &b1;	/* point at them */
	str2 = (void *) &b2;
	while (*str1 == *str2) {
		if (*str1 == '\0')
			return (0);
		++str1;
		++str2;
	}
	return ((unsigned char)*str1 - (unsigned char)*str2);
}
