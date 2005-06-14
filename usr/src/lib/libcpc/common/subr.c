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

#include <sys/types.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <libnvpair.h>
#include <thread.h>
#include <synch.h>

#include "libcpc.h"
#include "libcpc_impl.h"

/*
 * Pack a request set into a buffer using libnvpair. Size of buffer is returned
 * in buflen.
 */
char *
__cpc_pack_set(cpc_set_t *set, uint_t flags, size_t *buflen)
{
	cpc_request_t	*req;
	nvlist_t	*setlist, **reqlist;
	size_t		packsize = 0;
	char		*buf = NULL;
	int		i;
	int		j;

	if (nvlist_alloc(&setlist, 0, 0) == ENOMEM) {
		errno = ENOMEM;
		return (NULL);
	}

	if ((reqlist = (nvlist_t **)malloc(set->cs_nreqs * sizeof (*reqlist)))
	    == NULL) {
		nvlist_free(setlist);
		errno = ENOMEM;
		return (NULL);
	}

	bzero((void *)reqlist, set->cs_nreqs * sizeof (*reqlist));

	i = 0;
	for (req = set->cs_request; req != NULL; req = req->cr_next) {
		if (nvlist_alloc(&reqlist[i], 0, 0) == ENOMEM)
			goto nomem;

		if (nvlist_add_string(reqlist[i], "cr_event",
		    req->cr_event) != 0)
			goto nomem;
		if (nvlist_add_uint64(reqlist[i], "cr_preset",
		    req->cr_preset) != 0)
			goto nomem;
		if (nvlist_add_uint32(reqlist[i], "cr_flags",
		    req->cr_flags) != 0)
			goto nomem;
		if (nvlist_add_uint32(reqlist[i], "cr_index",
		    req->cr_index) != 0)
			goto nomem;

		if (req->cr_nattrs != 0) {
			nvlist_t	*attrs;

			if (nvlist_alloc(&attrs, NV_UNIQUE_NAME, 0) == ENOMEM)
				goto nomem;

			for (j = 0; j < req->cr_nattrs; j++) {
				if (nvlist_add_uint64(attrs,
				    req->cr_attr[j].ka_name,
				    req->cr_attr[j].ka_val) != 0) {
					nvlist_free(attrs);
					goto nomem;
				}
			}

			if (nvlist_add_nvlist(reqlist[i], "cr_attr",
			    attrs) != 0) {
				nvlist_free(attrs);
				goto nomem;
			}

			nvlist_free(attrs);
		}
		i++;
	}

	if (nvlist_add_nvlist_array(setlist, "reqs", reqlist,
	    set->cs_nreqs) != 0)
		goto nomem;

	if (nvlist_add_uint32(setlist, "flags", flags) != 0)
		goto nomem;

	if (nvlist_pack(setlist, &buf, &packsize, NV_ENCODE_NATIVE,
	    0) != 0)
		goto nomem;

	for (i = 0; i < set->cs_nreqs; i++)
		nvlist_free(reqlist[i]);

	nvlist_free(setlist);
	free(reqlist);

	*buflen = packsize;
	return (buf);

nomem:
	for (i = 0; i < set->cs_nreqs; i++) {
		if (reqlist[i] != 0)
			nvlist_free(reqlist[i]);
	}
	nvlist_free(setlist);
	free(reqlist);
	errno = ENOMEM;
	return (NULL);
}

cpc_strhash_t *
__cpc_strhash_alloc(void)
{
	cpc_strhash_t *p;

	if ((p = malloc(sizeof (cpc_strhash_t))) == NULL)
		return (NULL);

	p->str = "";
	p->cur = NULL;
	p->next = NULL;

	return (p);
}

void
__cpc_strhash_free(cpc_strhash_t *hash)
{
	cpc_strhash_t *p = hash, *f;

	while (p != NULL) {
		f = p;
		p = p->next;
		free(f);
	}
}

/*
 * Insert a new key into the hash table.
 *
 * Returns 0 if key was unique and insert successful.
 *
 * Returns 1 if key was already in table and no insert took place.
 *
 * Returns -1 if out of memory.
 */
int
__cpc_strhash_add(cpc_strhash_t *hash, char *key)
{
	cpc_strhash_t *p, *tmp;

	for (p = hash; p != NULL; p = p->next) {
		if (strcmp(p->str, key) == 0)
			return (1);
	}

	if ((p = malloc(sizeof (*p))) == NULL)
		return (-1);

	p->str = key;
	tmp = hash->next;
	hash->next = p;
	p->next = tmp;
	/*
	 * The head node's current pointer must stay pointed at the first
	 * real node. We just inserted at the head.
	 */
	hash->cur = p;

	return (0);
}

char *
__cpc_strhash_next(cpc_strhash_t *hash)
{
	cpc_strhash_t *p;

	if (hash->cur != NULL) {
		p = hash->cur;
		hash->cur = hash->cur->next;
		return (p->str);
	}

	return (NULL);
}
