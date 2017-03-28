/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1995 Alex Tatmanjants <alex@elvisti.kiev.ua>
 *		at Electronni Visti IA, Kiev, Ukraine.
 *			All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "collate.h"
#include "localeimpl.h"

/* Check file format vs libc runtime. (See collatefile.h) */
#if COLL_WEIGHTS_MAX != COLLATE_WEIGHTS_MAX
#error "COLL_WEIGHTS_MAX != COLLATE_WEIGHTS_MAX"
#endif

/*
 * See the comments in usr/src/cmd/localedef/collate.c for further
 * information.  It would also be very helpful to have a copy of the
 * POSIX standard for collation (in the locale format manual page)
 * handy (www.opengroup.org).
 */

/*
 * POSIX uses empty tables and falls down to strcmp.
 */
struct lc_collate lc_collate_posix = {
	.lc_is_posix = 1,
};

struct locdata __posix_collate_locdata = {
	.l_lname = "C",
	.l_data = { &lc_collate_posix }
};


struct locdata *
__lc_collate_load(const char *locname)
{
	int i, chains, z;
	char buf[PATH_MAX];
	char *TMP;
	char *map;
	collate_info_t *info;
	struct stat sbuf;
	int fd;
	struct locdata *ldata;
	struct lc_collate *lcc;

	/*
	 * Slurp the locale file into the cache.
	 */

	(void) snprintf(buf, sizeof (buf), "%s/%s/LC_COLLATE/LCL_DATA",
	    _PathLocale, locname);

	if ((fd = open(buf, O_RDONLY)) < 0) {
		errno = EINVAL;
		return (NULL);
	}
	if (fstat(fd, &sbuf) < 0) {
		(void) close(fd);
		errno = EINVAL;
		return (NULL);
	}
	if (sbuf.st_size < (COLLATE_STR_LEN + sizeof (info))) {
		(void) close(fd);
		errno = EINVAL;
		return (NULL);
	}
	map = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	(void) close(fd);
	if ((TMP = map) == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (strncmp(TMP, COLLATE_VERSION, COLLATE_STR_LEN) != 0) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (NULL);
	}
	TMP += COLLATE_STR_LEN;

	info = (void *)TMP;
	TMP += sizeof (*info);

	if ((info->directive_count < 1) ||
	    (info->directive_count >= COLL_WEIGHTS_MAX) ||
	    ((chains = info->chain_count) < 0)) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (NULL);
	}

	i = (sizeof (collate_char_t) * (UCHAR_MAX + 1)) +
	    (sizeof (collate_chain_t) * chains) +
	    (sizeof (collate_large_t) * info->large_count);
	for (z = 0; z < info->directive_count; z++) {
		i += sizeof (collate_subst_t) * info->subst_count[z];
	}
	if (i != (sbuf.st_size - (TMP - map))) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (NULL);
	}


	if ((ldata = __locdata_alloc(locname, sizeof (*lcc))) == NULL) {
		(void) munmap(map, sbuf.st_size);
		return (NULL);
	}
	lcc = ldata->l_data[0];
	ldata->l_map = map;
	ldata->l_map_len = sbuf.st_size;

	lcc->lc_info = info;
	lcc->lc_directive_count = info->directive_count;
	lcc->lc_large_count = info->large_count;

	for (z = 0; z < COLL_WEIGHTS_MAX; z++) {
		lcc->lc_directive[z] = info->directive[z];
		lcc->lc_subst_count[z] = info->subst_count[z];
		lcc->lc_pri_count[z] = info->pri_count[z];
		lcc->lc_undef_pri[z] = info->undef_pri[z];
	}

	lcc->lc_char_table = (void *)TMP;
	TMP += sizeof (collate_char_t) * (UCHAR_MAX + 1);

	for (z = 0; z < lcc->lc_directive_count; z++) {
		int count;
		if ((count = lcc->lc_subst_count[z]) > 0) {
			lcc->lc_subst_table[z] = (void *)TMP;
			TMP += count * sizeof (collate_subst_t);
		} else {
			lcc->lc_subst_table[z] = NULL;
		}
	}

	if (chains > 0) {
		lcc->lc_chain_table = (void *)TMP;
		TMP += chains * sizeof (collate_chain_t);
	} else
		lcc->lc_chain_table = NULL;
	lcc->lc_chain_count = chains;
	if (lcc->lc_large_count > 0)
		lcc->lc_large_table = (void *)TMP;
	else
		lcc->lc_large_table = NULL;

	return (ldata);
}

static const int32_t *
substsearch(const struct lc_collate *lcc, const wchar_t key, int pass)
{
	const collate_subst_t *p;
	int n = lcc->lc_subst_count[pass];

	if (n == 0)
		return (NULL);

	if (pass >= lcc->lc_directive_count)
		return (NULL);

	if (!(key & COLLATE_SUBST_PRIORITY))
		return (NULL);

	p = lcc->lc_subst_table[pass] + (key & ~COLLATE_SUBST_PRIORITY);
	assert(p->key == key);
	return (p->pri);
}

static collate_chain_t *
chainsearch(const struct lc_collate *lcc, const wchar_t *key, int *len)
{
	int low = 0;
	int high = lcc->lc_info->chain_count - 1;
	int next, compar, l;
	collate_chain_t *p;
	collate_chain_t *tab = lcc->lc_chain_table;

	if (high < 0)
		return (NULL);

	while (low <= high) {
		next = (low + high) / 2;
		p = tab + next;
		compar = *key - *p->str;
		if (compar == 0) {
			l = wcsnlen(p->str, COLLATE_STR_LEN);
			compar = wcsncmp(key, p->str, l);
			if (compar == 0) {
				*len = l;
				return (p);
			}
		}
		if (compar > 0)
			low = next + 1;
		else
			high = next - 1;
	}
	return (NULL);
}

static collate_large_t *
largesearch(const struct lc_collate *lcc, const wchar_t key)
{
	int low = 0;
	int high = lcc->lc_info->large_count - 1;
	int next, compar;
	collate_large_t *p;
	collate_large_t *tab = lcc->lc_large_table;

	if (high < 0)
		return (NULL);

	while (low <= high) {
		next = (low + high) / 2;
		p = tab + next;
		compar = key - p->val;
		if (compar == 0)
			return (p);
		if (compar > 0)
			low = next + 1;
		else
			high = next - 1;
	}
	return (NULL);
}

void
_collate_lookup(const struct lc_collate *lcc, const wchar_t *t,
    int *len, int *pri, int which, const int **state)
{
	collate_chain_t *p2;
	collate_large_t *match;
	int p, l;
	const int *sptr;

	/*
	 * If this is the "last" pass for the UNDEFINED, then
	 * we just return the priority itself.
	 */
	if (which >= lcc->lc_directive_count) {
		*pri = *t;
		*len = 1;
		*state = NULL;
		return;
	}

	/*
	 * If we have remaining substitution data from a previous
	 * call, consume it first.
	 */
	if ((sptr = *state) != NULL) {
		*pri = *sptr;
		sptr++;
		if ((sptr == *state) || (sptr == NULL))
			*state = NULL;
		else
			*state = sptr;
		*len = 0;
		return;
	}

	/* No active substitutions */
	*len = 1;

	/*
	 * Check for composites such as dipthongs that collate as a
	 * single element (aka chains or collating-elements).
	 */
	if (((p2 = chainsearch(lcc, t, &l)) != NULL) &&
	    ((p = p2->pri[which]) >= 0)) {

		*len = l;
		*pri = p;

	} else if (*t <= UCHAR_MAX) {

		/*
		 * Character is a small (8-bit) character.
		 * We just look these up directly for speed.
		 */
		*pri = lcc->lc_char_table[*t].pri[which];

	} else if ((lcc->lc_info->large_count > 0) &&
	    ((match = largesearch(lcc, *t)) != NULL)) {

		/*
		 * Character was found in the extended table.
		 */
		*pri = match->pri.pri[which];

	} else {
		/*
		 * Character lacks a specific definition.
		 */
		if (lcc->lc_directive[which] & DIRECTIVE_UNDEFINED) {
			/* Mask off sign bit to prevent ordering confusion. */
			*pri = (*t & COLLATE_MAX_PRIORITY);
		} else {
			*pri = lcc->lc_undef_pri[which];
		}
		/* No substitutions for undefined characters! */
		return;
	}

	/*
	 * Try substituting (expanding) the character.  We are
	 * currently doing this *after* the chain compression.  I
	 * think it should not matter, but this way might be slightly
	 * faster.
	 *
	 * We do this after the priority search, as this will help us
	 * to identify a single key value.  In order for this to work,
	 * its important that the priority assigned to a given element
	 * to be substituted be unique for that level.  The localedef
	 * code ensures this for us.
	 */
	if ((sptr = substsearch(lcc, *pri, which)) != NULL) {
		if ((*pri = *sptr) > 0) {
			sptr++;
			*state = *sptr ? sptr : NULL;
		}
	}

}

/*
 * This is the meaty part of wcsxfrm & strxfrm.  Note that it does
 * NOT NULL terminate.  That is left to the caller.
 */
size_t
_collate_wxfrm(const struct lc_collate *lcc, const wchar_t *src, wchar_t *xf,
    size_t room)
{
	int		pri;
	int		len;
	const wchar_t	*t;
	wchar_t		*tr = NULL;
	int		direc;
	int		pass;
	const int32_t 	*state;
	size_t		want = 0;
	size_t		need = 0;
	int		ndir = lcc->lc_directive_count;

	assert(src);

	for (pass = 0; pass <= ndir; pass++) {

		state = NULL;

		if (pass != 0) {
			/* insert level separator from the previous pass */
			if (room) {
				*xf++ = 1;
				room--;
			}
			want++;
		}

		/* special pass for undefined */
		if (pass == ndir) {
			direc = DIRECTIVE_FORWARD | DIRECTIVE_UNDEFINED;
		} else {
			direc = lcc->lc_directive[pass];
		}

		t = src;

		if (direc & DIRECTIVE_BACKWARD) {
			wchar_t *bp, *fp, c;
			if (tr)
				free(tr);
			if ((tr = wcsdup(t)) == NULL) {
				errno = ENOMEM;
				goto fail;
			}
			bp = tr;
			fp = tr + wcslen(tr) - 1;
			while (bp < fp) {
				c = *bp;
				*bp++ = *fp;
				*fp-- = c;
			}
			t = (const wchar_t *)tr;
		}

		if (direc & DIRECTIVE_POSITION) {
			while (*t || state) {
				_collate_lookup(lcc, t, &len, &pri, pass,
				    &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					state = NULL;
					pri = COLLATE_MAX_PRIORITY;
				}
				if (room) {
					*xf++ = pri;
					room--;
				}
				want++;
				need = want;
			}
		} else {
			while (*t || state) {
				_collate_lookup(lcc, t, &len, &pri, pass,
				    &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					state = NULL;
					continue;
				}
				if (room) {
					*xf++ = pri;
					room--;
				}
				want++;
				need = want;
			}
		}
	}

end:
	if (tr)
		free(tr);
	return (need);

fail:
	if (tr)
		free(tr);
	return ((size_t)(-1));
}

/*
 * In the non-POSIX case, we transform each character into a string of
 * characters representing the character's priority.  Since char is usually
 * signed, we are limited by 7 bits per byte.  To avoid zero, we need to add
 * XFRM_OFFSET, so we can't use a full 7 bits.  For simplicity, we choose 6
 * bits per byte.
 *
 * It turns out that we sometimes have real priorities that are
 * 31-bits wide.  (But: be careful using priorities where the high
 * order bit is set -- i.e. the priority is negative.  The sort order
 * may be surprising!)
 *
 * TODO: This would be a good area to optimize somewhat.  It turns out
 * that real prioririties *except for the last UNDEFINED pass* are generally
 * very small.  We need the localedef code to precalculate the max
 * priority for us, and ideally also give us a mask, and then we could
 * severely limit what we expand to.
 */
#define	XFRM_BYTES	6
#define	XFRM_OFFSET	('0')	/* make all printable characters */
#define	XFRM_SHIFT	6
#define	XFRM_MASK	((1 << XFRM_SHIFT) - 1)
#define	XFRM_SEP	('.')	/* chosen to be less than XFRM_OFFSET */

static int
xfrm(locale_t loc, unsigned char *p, int pri, int pass)
{
	/* we use unsigned to ensure zero fill on right shift */
	uint32_t val = (uint32_t)loc->collate->lc_pri_count[pass];
	int nc = 0;

	while (val) {
		*p = (pri & XFRM_MASK) + XFRM_OFFSET;
		pri >>= XFRM_SHIFT;
		val >>= XFRM_SHIFT;
		p++;
		nc++;
	}
	return (nc);
}

size_t
_collate_sxfrm(const wchar_t *src, char *xf, size_t room, locale_t loc)
{
	int		pri;
	int		len;
	const wchar_t	*t;
	wchar_t		*tr = NULL;
	int		direc;
	int		pass;
	const int32_t 	*state;
	size_t		want = 0;
	size_t		need = 0;
	int		b;
	uint8_t		buf[XFRM_BYTES];
	const struct lc_collate *lcc = loc->collate;
	int		ndir = lcc->lc_directive_count;

	assert(src);

	for (pass = 0; pass <= ndir; pass++) {

		state = NULL;

		if (pass != 0) {
			/* insert level separator from the previous pass */
			if (room) {
				*xf++ = XFRM_SEP;
				room--;
			}
			want++;
		}

		/* special pass for undefined */
		if (pass == ndir) {
			direc = DIRECTIVE_FORWARD | DIRECTIVE_UNDEFINED;
		} else {
			direc = lcc->lc_directive[pass];
		}

		t = src;

		if (direc & DIRECTIVE_BACKWARD) {
			wchar_t *bp, *fp, c;
			if (tr)
				free(tr);
			if ((tr = wcsdup(t)) == NULL) {
				errno = ENOMEM;
				goto fail;
			}
			bp = tr;
			fp = tr + wcslen(tr) - 1;
			while (bp < fp) {
				c = *bp;
				*bp++ = *fp;
				*fp-- = c;
			}
			t = (const wchar_t *)tr;
		}

		if (direc & DIRECTIVE_POSITION) {
			while (*t || state) {

				_collate_lookup(lcc, t, &len, &pri, pass,
				    &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					state = NULL;
					pri = COLLATE_MAX_PRIORITY;
				}

				b = xfrm(loc, buf, pri, pass);
				want += b;
				if (room) {
					while (b) {
						b--;
						if (room) {
							*xf++ = buf[b];
							room--;
						}
					}
				}
				need = want;
			}
		} else {
			while (*t || state) {
				_collate_lookup(lcc, t, &len, &pri, pass,
				    &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					state = NULL;
					continue;
				}

				b = xfrm(loc, buf, pri, pass);
				want += b;
				if (room) {

					while (b) {
						b--;
						if (room) {
							*xf++ = buf[b];
							room--;
						}
					}
				}
				need = want;
			}
		}
	}

end:
	if (tr)
		free(tr);
	return (need);

fail:
	if (tr)
		free(tr);
	return ((size_t)(-1));
}
