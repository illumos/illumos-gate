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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include "mtlib.h"
#include "libc.h"
#include "tsd.h"

typedef void (*pfrv_t)(void *);

typedef struct {
	void	*buf;
	size_t	size;
	pfrv_t	destructor;
} tsdent_t;

static void
_free_tsdbuf(void *ptr)
{
	tsdent_t *loc = ptr;
	pfrv_t destructor;
	void *p;
	int i;

	if (loc != NULL) {
		for (i = 0; i < _T_NUM_ENTRIES; i++) {
			if ((p = loc[i].buf) != NULL) {
				destructor = loc[i].destructor;
				if (destructor != NULL)
					destructor(p);
				lfree(p, loc[i].size);
			}
		}
		lfree(loc, _T_NUM_ENTRIES * sizeof (tsdent_t));
	}
}

void *
tsdalloc(__tsd_item_t n, size_t size, pfrv_t destructor)
{
	static thread_key_t	key = THR_ONCE_KEY;
	tsdent_t		*loc;
	void			*p;
	int			error;

	if ((uint_t)n >= _T_NUM_ENTRIES) {
		errno = ENOTSUP;
		return (NULL);
	}

	if ((error = thr_keycreate_once(&key, _free_tsdbuf)) != 0) {
		errno = error;
		return (NULL);
	}

	if ((loc = pthread_getspecific(key)) != NULL) {
		if ((p = loc[n].buf) != NULL)
			return (p);
	} else {
		/* allocate our array of pointers */
		loc = lmalloc(_T_NUM_ENTRIES * sizeof (tsdent_t));
		if (loc == NULL)
			return (NULL);
		if ((error = thr_setspecific(key, loc)) != 0) {
			lfree(loc, _T_NUM_ENTRIES * sizeof (tsdent_t));
			errno = error;
			return (NULL);
		}
	}

	/* allocate item n */
	loc[n].buf = p = lmalloc(size);
	loc[n].size = size;
	loc[n].destructor = destructor;
	return (p);
}
