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
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "med_hash.h"
#include "med_local.h"

#ifdef _KERNEL
#define	memmove(a, b, c)		bcopy(b, a, c)
#define	memcmp				bcmp
#define	memset(a, '\0', c)		bzero(a, c)
#define	Malloc				bkmem_alloc
#endif	/* _KERNEL */

#define	VERIFY_HASH_REALLOC

static int
BCMP(void *str1, void *str2, int len)
{
	return (memcmp((char *)str1, (char *)str2, len));
}

static int
HASH(void *datap, int datalen, int hsz)
{
	char		*cp;
	int		hv = 0;

	for (cp = (char *)datap; cp != ((char *)datap + datalen); hv += *cp++)
		;
	return (hv % hsz);
}

int
init_cache(
	Cache	**cp,
	int	hsz,
	int	bsz,
	int	(*hfunc)(void *, int, int),
	int	(*cfunc)(void *, void *, int),
	void	(*kffunc)(void *),
	void	(*dffunc)(void *)
)
{
	int			i;

	if ((*cp = (Cache *) Malloc(sizeof (**cp))) == NULL) {
		(void) fprintf(stderr, "Malloc(Cache **cp)");
		return (-1);
	}
	(*cp)->bp = (Bucket *) Malloc(sizeof (*(*cp)->bp) * hsz);
	if ((*cp)->bp == NULL) {
		(void) fprintf(stderr, "Malloc(Bucket cp->bp)");
		return (-1);
	}
	(*cp)->hsz = hsz;
	(*cp)->bsz = bsz;
	for (i = 0; i < (*cp)->hsz; i++) {
		(*cp)->bp[i].nent = 0;
		(*cp)->bp[i].nalloc = 0;
		(*cp)->bp[i].itempp = NULL;
	}
	/* Hash function */
	if (hfunc != (int (*)()) NULL)
		(*cp)->hfunc = hfunc;
	else
		(*cp)->hfunc = HASH;

	/* Compare function */
	if (cfunc != (int (*)()) NULL)
		(*cp)->cfunc = cfunc;
	else
		(*cp)->cfunc = BCMP;

	/* Key free function */
	if (kffunc != (void (*)()) NULL)
		(*cp)->kffunc = kffunc;
	else
		(*cp)->kffunc = Free;

	/* Data free function */
	if (dffunc != (void (*)()) NULL)
		(*cp)->dffunc = dffunc;
	else
		(*cp)->dffunc = Free;

	return (0);
}

int
add_cache(Cache *cp, Item *itemp)
{
	Bucket			*bp;
	Item			**titempp;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "add_cache(): init_cache() not called.\n");
		return (-1);
	}

	bp = &cp->bp[(*cp->hfunc)(itemp->key, itemp->keyl, cp->hsz)];
	if (bp->nent >= bp->nalloc) {
		if (bp->nalloc == 0) {
			bp->itempp =
			    (Item **) Malloc(sizeof (*bp->itempp) * cp->bsz);
		} else {
#ifdef	VERIFY_HASH_REALLOC
			(void) fprintf(stderr,
			    "realloc(%d) bucket=%d\n", bp->nalloc + cp->bsz,
			    (*cp->hfunc)(itemp->key, itemp->keyl, cp->hsz));
#endif	/* VERIFY_HASH_REALLOC */
			titempp =
			    (Item **) Malloc(sizeof (*bp->itempp) *
			    (bp->nalloc + cp->bsz));
			if (titempp != NULL) {
				(void) memmove((char *)titempp,
				    (char *)bp->itempp,
				    (sizeof (*bp->itempp) * bp->nalloc));
#ifdef _KERNEL
				bkmem_free(bp->itempp,
				    (sizeof (*bp->itempp) * bp->nalloc));
#else	/* !_KERNEL */
				Free(bp->itempp);
#endif	/* _KERNEL */
				bp->itempp = titempp;
			} else
				bp->itempp = NULL;
		}
		if (bp->itempp == NULL) {
			(void) fprintf(stderr,
			    "add_cache(): out of memory\n");
			return (-1);
		}
		bp->nalloc += cp->bsz;
	}
	bp->itempp[bp->nent] = itemp;
	bp->nent++;
	return (0);
}

Item *
lookup_cache(Cache *cp, void *datap, int datalen)
{
	int			i;
	Bucket			*bp;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "lookup_cache(): init_cache() not called.\n");
		return (Null_Item);
	}

	bp = &cp->bp[(*cp->hfunc)(datap, datalen, cp->hsz)];
	for (i = 0; i < bp->nent; i++)
		if (!(*cp->cfunc)((void *)bp->itempp[i]->key, datap, datalen))
			    return (bp->itempp[i]);
	return (Null_Item);
}

Item *
first_item(Cache *cp, int *bidx, int *iidx)
{
	Item			*itemp = Null_Item;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "first_item(): init_cache() not called.\n");
		return (Null_Item);
	}

	for (*bidx = 0; *bidx < cp->hsz && (cp->bp[*bidx].nalloc == 0 ||
	    cp->bp[*bidx].nent == 0); (*bidx)++)
		/* void */;

	if (*bidx < cp->hsz && cp->bp[*bidx].nent > 0) {
		itemp = cp->bp[*bidx].itempp[0];
		*iidx = 0;
	} else {
		*bidx = -1;
		*iidx = -1;
	}
	return (itemp);
}

Item *
next_item(Cache *cp, int *bidx, int *iidx)
{
	Item			*itemp = Null_Item;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "next_item(): init_cache() not called.\n");
		return (Null_Item);
	}

	if (*bidx < cp->hsz && *bidx >= 0) {
		if ((*iidx + 1) < cp->bp[*bidx].nent) {
			itemp = cp->bp[*bidx].itempp[++(*iidx)];
		} else {
			for (++(*bidx);
			    *bidx < cp->hsz && (cp->bp[*bidx].nalloc == 0 ||
			    cp->bp[*bidx].nent == 0);
			    (*bidx)++)
				/* void */;
			if (*bidx < cp->hsz && cp->bp[*bidx].nent > 0) {
				*iidx = 0;
				itemp = cp->bp[*bidx].itempp[(*iidx)++];
			} else {
				*bidx = -1;
				*iidx = -1;
			}
		}
	} else {
		*bidx = -1;
		*iidx = -1;
	}
	return (itemp);
}

void
des_cache(Cache **cpp)
{
	Cache			*cp = *cpp;
	Bucket			*bp;
	Item			*itemp;
	int			i;
	int			j;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "des_cache(): init_cache() not called.\n");
		return;
	}

	for (i = 0; i < cp->hsz; i++) {
		bp = &cp->bp[i];
		if (bp->nalloc > 0) {
			for (j = 0; j < bp->nent; j++) {
				itemp = bp->itempp[j];
				if (itemp->key)
					(void) (*cp->kffunc)(itemp->key);
				if (itemp->data)
					(void) (*cp->dffunc)(itemp->data);
			}
		}
		(void) Free(bp->itempp);
	}
	(void) Free(cp->bp);
	(void) Free(cp);
	*cpp = NULL;
}

int
del_cache(Cache *cp, Item *itemp)
{
	Bucket			*bp;
	int			bidx;
	int			iidx;
	int			tidx;
	int			retval = 0;
	void			*datap = itemp->key;
	int			datalen = itemp->keyl;
	Item			*titemp;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "del_cache(): init_cache() not called.\n");
		return (-1);
	}

	bidx = (*cp->hfunc)(datap, datalen, cp->hsz);
	bp = &cp->bp[bidx];

	for (iidx = 0; iidx < bp->nent; iidx++)
		if (!(*cp->cfunc)((void *)bp->itempp[iidx]->key, datap,
		    datalen)) {
			titemp = bp->itempp[iidx];
			break;
		}
	if (iidx < bp->nent) {
		if (titemp->key)
			(void) (*cp->kffunc)(titemp->key);
		if (titemp->data)
			(void) (*cp->dffunc)(titemp->data);
		titemp->keyl = 0;
		titemp->datal = 0;
		bp->nent--;
		if (bp->nent == 0) {
			(void) Free(bp->itempp);
			bp->itempp = NULL;
			bp->nalloc = 0;
		} else {
			for (tidx = iidx + 1; tidx < (bp->nent + 1); tidx++) {
				bp->itempp[iidx] = bp->itempp[tidx];
				iidx = tidx;
			}
		}
	} else {
		(void) fprintf(stderr,
		    "del_cache(): item not found.\n");
		retval = -1;
	}
	return (retval);
}

#ifdef DEBUG
void
cache_stat(Cache *cp, char *tag)
{
	Bucket			*bp;
	int			bidx;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "cache_stat(): init_cache() not called.\n");
		return;
	}

	if (tag && *tag)
		(void) printf("%s", tag);

	for (bidx = 0; bidx < cp->hsz; bidx++) {
		bp = &cp->bp[bidx];
		if (bp->nalloc > 0) {
			(void) printf("Bucket #%d Alloc %d", bidx, bp->nalloc);
			if (bp->nent > 0) {
				(void) printf(
				    " Entries %d Reallocs %d", bp->nent,
				    (bp->nalloc / cp->hsz));
				(void) printf(
				    " Utilization %d%%",
				    ((bp->nent * 100)/bp->nalloc));
			}
			(void) printf("\n");
			(void) fflush(stdout);
		}
	}
}

void
pr_cache(Cache *cp, char *tag, void (*pfunc)(void *, int, void *, int))
{
	int			bidx;
	int			iidx;
	Bucket			*bp;
	Item			*itemp;

	if (cp == NULL) {
		(void) fprintf(stderr,
		    "pr_cache(): init_cache() not called.\n");
		return;
	}

	if (tag && *tag)
		(void) printf("%s", tag);

	for (bidx = 0; bidx < cp->hsz; bidx++) {
		bp = &cp->bp[bidx];
		if (bp->nent > 0)
			for (iidx = 0; iidx < bp->nent; iidx++) {
				itemp = bp->itempp[iidx];
				(*pfunc)(itemp->key, itemp->keyl,
				    itemp->data, itemp->datal);
			}
	}
}
#endif	/* DEBUG */
