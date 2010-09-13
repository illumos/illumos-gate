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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * utility for vntsd queue handling
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <wait.h>
#include <time.h>
#include <netinet/in.h>
#include <thread.h>
#include <signal.h>
#include "vntsd.h"

/* alloc_que_el() allocates a queue element */
static vntsd_que_t *
alloc_que_el(void *handle)
{
	vntsd_que_t *el;

	/* allocate a queue element */
	el = (vntsd_que_t *)malloc(sizeof (vntsd_que_t));
	if (el == NULL) {
		return (NULL);
	}


	el->nextp = NULL;
	el->prevp = NULL;
	el->handle = handle;

	return (el);
}

/* vntsd_que_append() appends a element to a queue */
int
vntsd_que_append(vntsd_que_t **que_hd, void *handle)
{
	vntsd_que_t *p;
	vntsd_que_t *el;

	assert(que_hd);
	assert(handle);

	/* allocate a queue element */
	el = alloc_que_el(handle);

	if (el == NULL) {
		return (VNTSD_ERR_NO_MEM);
	}

	p = *que_hd;

	if (p == NULL) {
		/* first one */
		*que_hd  = el;
	} else {
		/* walk to the last one */
		while (p->nextp != NULL)
			p = p->nextp;
		p->nextp = el;
	}

	el->prevp = p;

	return (VNTSD_SUCCESS);
}

/* vntsd_que_insert_after() inserts element arter the handle */
int
vntsd_que_insert_after(vntsd_que_t *que, void *handle, void *next)
{
	vntsd_que_t *q, *el;

	assert(que);

	q = que;

	while (q != NULL) {
		if (q->handle == handle) {
			break;
		}

		q = q->nextp;
	}

	if (q == NULL) {
		/* not in queue */
		return (VNTSD_ERR_EL_NOT_FOUND);
	}

	el = alloc_que_el(next);

	if (el == NULL) {
		return (VNTSD_ERR_NO_MEM);
	}

	el->nextp = q->nextp;
	q->nextp = el;
	el->prevp = q;

	return (VNTSD_SUCCESS);
}



/* vntsd_que_rm() removes an element from a queue */
int
vntsd_que_rm(vntsd_que_t **que_hd, void *handle)
{
	vntsd_que_t	*p = *que_hd;
	vntsd_que_t	*prevp = NULL;


	while (p != NULL) {
		/* match handle */
		if (p->handle == handle) {
			break;
		}
		prevp = p;
		p = p->nextp;
	}

	if (p == NULL) {
		/* not found */
		return (VNTSD_ERR_EL_NOT_FOUND);
	}

	/* found */
	if (p == *que_hd) {
		/* first one */
		*que_hd = p->nextp;
	} else {
		prevp->nextp = p->nextp;
	}

	if (p->nextp != NULL) {
		p->nextp->prevp = prevp;
	}

	handle = p->handle;

	free(p);

	return (VNTSD_SUCCESS);

}

/* vntsd_que_walk() - walk queue and apply function to each element */
void *
vntsd_que_walk(vntsd_que_t *que_hd, el_func_t el_func)
{
	vntsd_que_t *p = que_hd;

	while (p != NULL) {
		if ((*el_func)(p->handle)) {
		    return (p->handle);
		}

		p = p->nextp;
	}
	return (VNTSD_SUCCESS);
}


/* vntsd_que_find() finds first match */
void *
vntsd_que_find(vntsd_que_t *que_hd, compare_func_t compare_func, void *data)
{
	vntsd_que_t *p = que_hd;

	assert(compare_func != NULL);
	while (p != NULL) {
		if ((*compare_func)(p->handle, data)) {
			/* found match */
			return (p->handle);
		}

		p = p->nextp;
	}

	/* not found */
	return (NULL);
}

/* vntsd_free_que() frees entire queue */
void
vntsd_free_que(vntsd_que_t **q, clean_func_t clean_func)
{
	vntsd_que_t *p;

	while (*q != NULL) {
		p = *q;

		*q  = p->nextp;

		if (clean_func) {
			/* clean func will free the handle */
			(*clean_func)(p->handle);
		} else {
			free(p->handle);
		}

		free(p);
	}
}

/*
 * vntsd_que_pos() matches a handle and returns a handle located at "pos"
 * relative to the matched handle. pos supported are 1 or -1.
 */
void *
vntsd_que_pos(vntsd_que_t *que_hd, void *handle, int pos)
{
	vntsd_que_t *p = que_hd;

	assert((pos == 1) || (pos == -1));


	while (p != NULL) {
		if (p->handle == handle) {
			/* find match */
			if (pos == 1) {
				/* forward 1 */
				if (p->nextp != NULL) {
					return (p->nextp->handle);
				}

				/* last one go to first */
				return (que_hd->handle);

			} else {
				/* backward 1 */
				if (p->prevp != NULL) {
					return (p->prevp->handle);
				}

				/* first one, return last one */
				while (p->nextp != NULL) {
					p = p->nextp;
				}

				assert(p != NULL);
				assert(p->handle != NULL);
				return (p->handle);

			}
		}
		p = p->nextp;
	}

	DERR(stderr, "t@%d vntsd_que_pos can not find handle \n",
	    thr_self());

	return (NULL);
}
