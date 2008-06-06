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
 *	Split buffer into fields delimited by tabs and newlines.
 *	Fill pointer array with pointers to fields.
 * 	Return the number of fields assigned to the array[].
 *	The remainder of the array elements point to the end of the buffer.
 *
 *      Note:
 *	The delimiters are changed to null-bytes in the buffer and array of
 *	pointers is only valid while the buffer is intact.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <pthread.h>

#ifndef _REENTRANT
static char *bsplitchar = "\t\n";	/* characters that separate fields */
#endif

#ifdef _REENTRANT
static char **
_get_bsplitchar(thread_key_t *keyp)
{
	static char *init_bsplitchar = "\t\n";
	char **strp;

	if (thr_keycreate_once(keyp, free) != 0)
		return (NULL);
	strp = pthread_getspecific(*keyp);
	if (strp == NULL) {
		strp = malloc(sizeof (char *));
		if (thr_setspecific(*keyp, strp) != 0) {
			if (strp)
				(void) free(strp);
			strp = NULL;
		}
		if (strp != NULL)
			*strp = init_bsplitchar;
	}
	return (strp);
}
#endif /* _REENTRANT */

size_t
bufsplit(char *buf, size_t dim, char **array)
{
#ifdef _REENTRANT
	static thread_key_t key = THR_ONCE_KEY;
	char  **bsplitchar = _get_bsplitchar(&key);
#define	bsplitchar (*bsplitchar)
#endif /* _REENTRANT */

	unsigned numsplit;
	int	i;

	if (!buf)
		return (0);
	if (!dim ^ !array)
		return (0);
	if (buf && !dim && !array) {
		bsplitchar = buf;
		return (1);
	}
	numsplit = 0;
	while (numsplit < dim) {
		array[numsplit] = buf;
		numsplit++;
		buf = strpbrk(buf, bsplitchar);
		if (buf)
			*(buf++) = '\0';
		else
			break;
		if (*buf == '\0') {
			break;
		}
	}
	buf = strrchr(array[numsplit-1], '\0');
	for (i = numsplit; i < dim; i++)
		array[i] = buf;
	return (numsplit);
}
