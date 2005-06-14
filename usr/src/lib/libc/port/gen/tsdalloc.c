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

#include "synonyms.h"
#include <stdlib.h>
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
	static int		once_key = 0;
	static mutex_t		key_lock = DEFAULTMUTEX;
	static thread_key_t	key;
	tsdent_t		*loc;
	void			*p;
	int			error;

	if ((uint_t)n >= _T_NUM_ENTRIES) {
		errno = ENOTSUP;
		return (NULL);
	}

	if (once_key == 0) {
		lmutex_lock(&key_lock);
		if (once_key == 0) {
			if ((error = _thr_keycreate(&key, _free_tsdbuf)) != 0) {
				lmutex_unlock(&key_lock);
				errno = error;
				return (NULL);
			}
			once_key = 1;
		}
		lmutex_unlock(&key_lock);
	}

	if ((loc = _pthread_getspecific(key)) != NULL) {
		if ((p = loc[n].buf) != NULL)
			return (p);
	} else {
		/* allocate our array of pointers */
		loc = lmalloc(_T_NUM_ENTRIES * sizeof (tsdent_t));
		if (loc == NULL)
			return (NULL);
		if ((error = _thr_setspecific(key, loc)) != 0) {
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
