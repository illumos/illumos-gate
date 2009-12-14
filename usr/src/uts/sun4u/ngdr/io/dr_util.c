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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/param.h>		/* for NULL */
#include <sys/sbd_ioctl.h>
#include <sys/dr_util.h>
#include <sys/varargs.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>

/* sbd_etab[] and sbd_etab_len provided by sbdgenerr.pl */
extern sbd_etab_t sbd_etab[];
extern int sbd_etab_len;

sbd_error_t *
sbd_err_new(int e_code, char *fmt, va_list args)
{
	sbd_error_t	*new;

	new = GETSTRUCT(sbd_error_t, 1);
	new->e_code = e_code;

	if (fmt)
		(void) vsnprintf(new->e_rsc, sizeof (new->e_rsc), fmt, args);

	return (new);
}

void
sbd_err_log(sbd_error_t *ep, int ce)
{
	char		 buf[32];
	char		*fmt;
	char		*txt;
	int		 i;
	sbd_etab_t	*tp;

	if (!ep)
		return;

	if (ep->e_rsc[0] == '\0')
		fmt = "%s";
	else
		fmt = "%s: %s";

	for (tp = sbd_etab, i = 0; i < sbd_etab_len; i++, tp++)
		if (ep->e_code >= tp->t_base && ep->e_code <= tp->t_bnd)
			break;

	if (i < sbd_etab_len)
		txt = tp->t_text[ep->e_code - tp->t_base];
	else {
		(void) snprintf(buf, sizeof (buf), "error %d", ep->e_code);
		txt = buf;
	}

	cmn_err(ce, fmt, txt, ep->e_rsc);
}

void
sbd_err_clear(sbd_error_t **ep)
{
	FREESTRUCT(*ep, sbd_error_t, 1);
	*ep = NULL;
}

void
sbd_err_set_c(sbd_error_t **ep, int ce, int e_code, char *fmt, ...)
{
	sbd_error_t	*tmp;
	va_list		args;

	va_start(args, fmt);

	tmp = sbd_err_new(e_code, fmt, args);

	sbd_err_log(tmp, ce);

	if (*ep == NULL)
		*ep = tmp;
	else
		sbd_err_clear(&tmp);

	va_end(args);
}

void
sbd_err_set(sbd_error_t **ep, int ce, int e_code, char *fmt, ...)
{
	sbd_error_t	*tmp;
	va_list		args;

	va_start(args, fmt);

	tmp = sbd_err_new(e_code, fmt, args);

	sbd_err_log(tmp, ce);

	*ep = tmp;

	va_end(args);
}

sbd_error_t *
drerr_new_v(int e_code, char *fmt, va_list args)
{
	return (sbd_err_new(e_code, fmt, args));
}

sbd_error_t *
drerr_new(int log, int e_code, char *fmt, ...)
{
	sbd_error_t	*ep;
	va_list		 args;

	va_start(args, fmt);
	ep = sbd_err_new(e_code, fmt, args);
	va_end(args);

	if (log)
		sbd_err_log(ep, CE_WARN);

	return (ep);
}

void
drerr_set_c(int log, sbd_error_t **ep, int e_code, char *fmt, ...)
{
	sbd_error_t	*err;
	va_list		 args;

	va_start(args, fmt);
	err = sbd_err_new(e_code, fmt, args);
	va_end(args);

	if (log)
		sbd_err_log(err, CE_WARN);

	if (*ep == NULL)
		*ep = err;
	else
		sbd_err_clear(&err);
}


/*
 * Memlist support.
 */
void
dr_memlist_delete(struct memlist *mlist)
{
	register struct memlist	*ml;

	for (ml = mlist; ml; ml = mlist) {
		mlist = ml->next;
		FREESTRUCT(ml, struct memlist, 1);
	}
}

int
dr_memlist_intersect(struct memlist *al, struct memlist *bl)
{
	uint64_t	astart, aend, bstart, bend;

	if ((al == NULL) || (bl == NULL))
		return (0);

	aend = al->address + al->size;
	bstart = bl->address;
	bend = bl->address + bl->size;

	while (al && bl) {
		while (al && (aend <= bstart))
			if ((al = al->next) != NULL)
				aend = al->address + al->size;
		if (al == NULL)
			return (0);

		if ((astart = al->address) <= bstart)
			return (1);

		while (bl && (bend <= astart))
			if ((bl = bl->next) != NULL)
				bend = bl->address + bl->size;
		if (bl == NULL)
			return (0);

		if ((bstart = bl->address) <= astart)
			return (1);
	}

	return (0);
}

void
dr_memlist_coalesce(struct memlist *mlist)
{
	uint64_t	end, nend;

	if ((mlist == NULL) || (mlist->next == NULL))
		return;

	while (mlist->next) {
		end = mlist->address + mlist->size;
		if (mlist->next->address <= end) {
			struct memlist 	*nl;

			nend = mlist->next->address + mlist->next->size;
			if (nend > end)
				mlist->size += (nend - end);
			nl = mlist->next;
			mlist->next = mlist->next->next;
			if (nl) {
				FREESTRUCT(nl, struct memlist, 1);
			}
			if (mlist->next)
				mlist->next->prev = mlist;
		} else {
			mlist = mlist->next;
		}
	}
}

#ifdef DEBUG
void
memlist_dump(struct memlist *mlist)
{
	register struct memlist *ml;

	if (mlist == NULL)
		printf("memlist> EMPTY\n");
	else for (ml = mlist; ml; ml = ml->next)
		printf("memlist> 0x%lx, 0x%lx\n", ml->address, ml->size);
}
#endif

struct memlist *
dr_memlist_dup(struct memlist *mlist)
{
	struct memlist *hl = NULL, *tl, **mlp;

	if (mlist == NULL)
		return (NULL);

	mlp = &hl;
	tl = *mlp;
	for (; mlist; mlist = mlist->next) {
		*mlp = GETSTRUCT(struct memlist, 1);
		(*mlp)->address = mlist->address;
		(*mlp)->size = mlist->size;
		(*mlp)->prev = tl;
		tl = *mlp;
		mlp = &((*mlp)->next);
	}
	*mlp = NULL;

	return (hl);
}

struct memlist *
dr_memlist_add_span(struct memlist *mlist, uint64_t base, uint64_t len)
{
	struct memlist	*ml, *tl, *nl;

	if (len == 0ull)
		return (NULL);

	if (mlist == NULL) {
		mlist = GETSTRUCT(struct memlist, 1);
		mlist->address = base;
		mlist->size = len;
		mlist->next = mlist->prev = NULL;

		return (mlist);
	}

	for (tl = ml = mlist; ml; tl = ml, ml = ml->next) {
		if (base < ml->address) {
			if ((base + len) < ml->address) {
				nl = GETSTRUCT(struct memlist, 1);
				nl->address = base;
				nl->size = len;
				nl->next = ml;
				if ((nl->prev = ml->prev) != NULL)
					nl->prev->next = nl;
				ml->prev = nl;
				if (mlist == ml)
					mlist = nl;
			} else {
				ml->size = MAX((base + len),
				    (ml->address + ml->size)) - base;
				ml->address = base;
			}
			break;

		} else if (base <= (ml->address + ml->size)) {
			ml->size = MAX((base + len),
			    (ml->address + ml->size)) -
			    MIN(ml->address, base);
			ml->address = MIN(ml->address, base);
			break;
		}
	}
	if (ml == NULL) {
		nl = GETSTRUCT(struct memlist, 1);
		nl->address = base;
		nl->size = len;
		nl->next = NULL;
		nl->prev = tl;
		tl->next = nl;
	}

	dr_memlist_coalesce(mlist);

	return (mlist);
}

struct memlist *
dr_memlist_del_span(struct memlist *mlist, uint64_t base, uint64_t len)
{
	uint64_t	end;
	struct memlist	*ml, *tl, *nlp;

	if (mlist == NULL)
		return (NULL);

	end = base + len;
	if ((end <= mlist->address) || (base == end))
		return (mlist);

	for (tl = ml = mlist; ml; tl = ml, ml = nlp) {
		uint64_t	mend;

		nlp = ml->next;

		if (end <= ml->address)
			break;

		mend = ml->address + ml->size;
		if (base < mend) {
			if (base <= ml->address) {
				ml->address = end;
				if (end >= mend)
					ml->size = 0ull;
				else
					ml->size = mend - ml->address;
			} else {
				ml->size = base - ml->address;
				if (end < mend) {
					struct memlist	*nl;
					/*
					 * splitting an memlist entry.
					 */
					nl = GETSTRUCT(struct memlist, 1);
					nl->address = end;
					nl->size = mend - nl->address;
					if ((nl->next = nlp) != NULL)
						nlp->prev = nl;
					nl->prev = ml;
					ml->next = nl;
					nlp = nl;
				}
			}
			if (ml->size == 0ull) {
				if (ml == mlist) {
					if ((mlist = nlp) != NULL)
						nlp->prev = NULL;
					FREESTRUCT(ml, struct memlist, 1);
					if (mlist == NULL)
						break;
					ml = nlp;
				} else {
					if ((tl->next = nlp) != NULL)
						nlp->prev = tl;
					FREESTRUCT(ml, struct memlist, 1);
					ml = tl;
				}
			}
		}
	}

	return (mlist);
}

/*
 * add span without merging
 */
struct memlist *
dr_memlist_cat_span(struct memlist *mlist, uint64_t base, uint64_t len)
{
	struct memlist	*ml, *tl, *nl;

	if (len == 0ull)
		return (NULL);

	if (mlist == NULL) {
		mlist = GETSTRUCT(struct memlist, 1);
		mlist->address = base;
		mlist->size = len;
		mlist->next = mlist->prev = NULL;

		return (mlist);
	}

	for (tl = ml = mlist; ml; tl = ml, ml = ml->next) {
		if (base < ml->address) {
			nl = GETSTRUCT(struct memlist, 1);
			nl->address = base;
			nl->size = len;
			nl->next = ml;
			if ((nl->prev = ml->prev) != NULL)
				nl->prev->next = nl;
			ml->prev = nl;
			if (mlist == ml)
				mlist = nl;
			break;
		}
	}

	if (ml == NULL) {
		nl = GETSTRUCT(struct memlist, 1);
		nl->address = base;
		nl->size = len;
		nl->next = NULL;
		nl->prev = tl;
		tl->next = nl;
	}

	return (mlist);
}
