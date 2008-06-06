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
 * Read no more than <count> characters into <buf> from stream <fp>,
 * stopping at any characters listed in <stopstr>.
 *
 * NOTE: This function will not work for multi-byte characters.
 */

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <pthread.h>

#define	CHARS	256

#ifdef _REENTRANT
#define	getc(f) getc_unlocked(f)
#else /* _REENTRANT */
static char	*stop = NULL;
#endif /* _REENTRANT */

#ifdef _REENTRANT
static char *
_get_stop(thread_key_t *keyp)
{
	char *str;

	if (thr_keycreate_once(keyp, free) != 0)
		return (NULL);
	str = pthread_getspecific(*keyp);
	if (str == NULL) {
		str = calloc(CHARS, sizeof (char));
		if (thr_setspecific(*keyp, str) != 0) {
			if (str)
				(void) free(str);
			str = NULL;
		}
	}
	return (str);
}
#endif /* _REENTRANT */

char *
bgets(char *buf, size_t count, FILE *fp, char *stopstr)
{
	char	*cp;
	int	c;
	size_t	i;
#ifdef _REENTRANT
	static thread_key_t key = THR_ONCE_KEY;
	char  *stop  = _get_stop(&key);
#else /* _REENTRANT */
	if (!stop)
		stop = (char *)calloc(CHARS, sizeof (char));
	else
#endif /* _REENTRANT */
	if (stopstr) 	/* reset stopstr array */
		(void) memset(stop, 0, CHARS);
	if (stopstr)
		for (cp = stopstr; *cp; cp++)
			stop[(unsigned char)*cp] = 1;
	i = 0;
	flockfile(fp);
	cp = buf;
	for (;;) {
		if (i++ == count) {
			*cp = '\0';
			break;
		}
		if ((c = getc(fp)) == EOF) {
			*cp = '\0';
			if (cp == buf)
				cp = (char *)0;
			break;
		}
		*cp++ = (char)c;
		if (stop[c]) {
			*cp = '\0';
			break;
		}
	}
	funlockfile(fp);
	return (cp);
}
