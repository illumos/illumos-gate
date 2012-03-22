/*
 * Copright 2010 Nexenta Systems, Inc.  All rights reserved.
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
#include "setlocale.h"
#include "ldpart.h"

/*
 * See the comments in usr/src/cmd/localedef/collate.c for further
 * information.  It would also be very helpful to have a copy of the
 * POSIX standard for collation (in the locale format manual page)
 * handy (www.opengroup.org).
 */

static collate_subst_t		*subst_table[COLL_WEIGHTS_MAX];
static collate_char_t		*char_pri_table;
static collate_large_t		*large_pri_table;
static collate_chain_t		*chain_pri_table;
static char			*cache = NULL;
static size_t			cachesz;
static char			collate_encoding[ENCODING_LEN + 1];

/* Exposed externally to other parts of libc. */
collate_info_t			*_collate_info;
int _collate_load_error = 1;


int
_collate_load_tables(const char *encoding)
{
	int i, chains, z;
	char buf[PATH_MAX];
	char *TMP;
	char *map;
	collate_info_t *info;
	struct stat sbuf;
	int fd;

	/* 'encoding' must be already checked. */
	if (strcmp(encoding, "C") == 0 || strcmp(encoding, "POSIX") == 0) {
		_collate_load_error = 1;
		return (_LDP_CACHE);
	}

	/*
	 * If the locale name is the same as our cache, use the cache.
	 */
	if (cache && (strncmp(encoding, collate_encoding, ENCODING_LEN) == 0)) {
		_collate_load_error = 0;
		return (_LDP_CACHE);
	}

	/*
	 * Slurp the locale file into the cache.
	 */

	(void) snprintf(buf, sizeof (buf), "%s/%s/LC_COLLATE/LCL_DATA",
	    _PathLocale, encoding);

	if ((fd = open(buf, O_RDONLY)) < 0)
		return (_LDP_ERROR);
	if (fstat(fd, &sbuf) < 0) {
		(void) close(fd);
		return (_LDP_ERROR);
	}
	if (sbuf.st_size < (COLLATE_STR_LEN + sizeof (info))) {
		(void) close(fd);
		errno = EINVAL;
		return (_LDP_ERROR);
	}
	map = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	(void) close(fd);
	if ((TMP = map) == NULL) {
		return (_LDP_ERROR);
	}

	if (strncmp(TMP, COLLATE_VERSION, COLLATE_STR_LEN) != 0) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (_LDP_ERROR);
	}
	TMP += COLLATE_STR_LEN;

	info = (void *)TMP;
	TMP += sizeof (*info);

	if ((info->directive_count < 1) ||
	    (info->directive_count >= COLL_WEIGHTS_MAX) ||
	    ((chains = info->chain_count) < 0)) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (_LDP_ERROR);
	}

	i = (sizeof (collate_char_t) * (UCHAR_MAX + 1)) +
	    (sizeof (collate_chain_t) * chains) +
	    (sizeof (collate_large_t) * info->large_count);
	for (z = 0; z < (info->directive_count); z++) {
		i += sizeof (collate_subst_t) * info->subst_count[z];
	}
	if (i != (sbuf.st_size - (TMP - map))) {
		(void) munmap(map, sbuf.st_size);
		errno = EINVAL;
		return (_LDP_ERROR);
	}

	char_pri_table = (void *)TMP;
	TMP += sizeof (collate_char_t) * (UCHAR_MAX + 1);

	for (z = 0; z < info->directive_count; z++) {
		if (info->subst_count[z] > 0) {
			subst_table[z] = (void *)TMP;
			TMP += info->subst_count[z] * sizeof (collate_subst_t);
		} else {
			subst_table[z] = NULL;
		}
	}

	if (chains > 0) {
		chain_pri_table = (void *)TMP;
		TMP += chains * sizeof (collate_chain_t);
	} else
		chain_pri_table = NULL;
	if (info->large_count > 0)
		large_pri_table = (void *)TMP;
	else
		large_pri_table = NULL;

	(void) strlcpy(collate_encoding, encoding, ENCODING_LEN);
	_collate_info = info;

	if (cache)
		(void) munmap(cache, cachesz);

	cache = map;
	cachesz = sbuf.st_size;
	_collate_load_error = 0;

	return (_LDP_LOADED);
}

static int32_t *
substsearch(const wchar_t key, int pass)
{
	collate_subst_t *p;
	int n = _collate_info->subst_count[pass];

	if (n == 0)
		return (NULL);

	if (pass >= _collate_info->directive_count)
		return (NULL);

	if (!(key & COLLATE_SUBST_PRIORITY))
		return (NULL);

	p = subst_table[pass] + (key & ~COLLATE_SUBST_PRIORITY);
	assert(p->key == key);
	return (p->pri);
}

/*
 * Note: for performance reasons, we have expanded bsearch here.  This avoids
 * function call overhead with each comparison.
 */

static collate_chain_t *
chainsearch(const wchar_t *key, int *len)
{
	int low;
	int high;
	int next, compar, l;
	collate_chain_t *p;
	collate_chain_t *tab;

	if (_collate_info->chain_count == 0)
		return (NULL);

	low = 0;
	high = _collate_info->chain_count - 1;
	tab = chain_pri_table;

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
largesearch(const wchar_t key)
{
	int low = 0;
	int high = _collate_info->large_count - 1;
	int next, compar;
	collate_large_t *p;
	collate_large_t *tab = large_pri_table;

	if (_collate_info->large_count == 0)
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
_collate_lookup(const wchar_t *t, int *len, int *pri, int which, int **state)
{
	collate_chain_t *p2;
	collate_large_t *match;
	collate_info_t *info = _collate_info;
	int p, l;
	int *sptr;

	/*
	 * If this is the "last" pass for the UNDEFINED, then
	 * we just return the priority itself.
	 */
	if (which >= info->directive_count) {
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
		*state = *sptr ? sptr : NULL;
		*len = 0;
		return;
	}

	/* No active substitutions */
	*len = 1;

	/*
	 * Check for composites such as dipthongs that collate as a
	 * single element (aka chains or collating-elements).
	 */
	if (((p2 = chainsearch(t, &l)) != NULL) &&
	    ((p = p2->pri[which]) >= 0)) {

		*len = l;
		*pri = p;

	} else if (*t <= UCHAR_MAX) {

		/*
		 * Character is a small (8-bit) character.
		 * We just look these up directly for speed.
		 */
		*pri = char_pri_table[*t].pri[which];

	} else if ((info->large_count > 0) &&
	    ((match = largesearch(*t)) != NULL)) {

		/*
		 * Character was found in the extended table.
		 */
		*pri = match->pri.pri[which];

	} else {
		/*
		 * Character lacks a specific definition.
		 */
		if (info->directive[which] & DIRECTIVE_UNDEFINED) {
			/* Mask off sign bit to prevent ordering confusion. */
			*pri = (*t & COLLATE_MAX_PRIORITY);
		} else {
			*pri = info->undef_pri[which];
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
	if ((sptr = substsearch(*pri, which)) != NULL) {
		if ((*pri = *sptr) != 0) {
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
_collate_wxfrm(const wchar_t *src, wchar_t *xf, size_t room)
{
	int		pri;
	int		len;
	const wchar_t	*t;
	wchar_t		*tr = NULL;
	int		direc;
	int		pass;
	int32_t 	*state;
	size_t		want = 0;
	size_t		need = 0;

	assert(src);

	for (pass = 0; pass <= _collate_info->directive_count; pass++) {

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
		if (pass == _collate_info->directive_count) {
			direc = DIRECTIVE_FORWARD | DIRECTIVE_UNDEFINED;
		} else {
			direc = _collate_info->directive[pass];
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
				_collate_lookup(t, &len, &pri, pass, &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
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
				_collate_lookup(t, &len, &pri, pass, &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
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
xfrm(unsigned char *p, int pri, int pass)
{
	/* we use unsigned to ensure zero fill on right shift */
	uint32_t val = (uint32_t)_collate_info->pri_count[pass];
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
_collate_sxfrm(const wchar_t *src, char *xf, size_t room)
{
	int		pri;
	int		len;
	const wchar_t	*t;
	wchar_t		*tr = NULL;
	int		direc;
	int		pass;
	int32_t 	*state;
	size_t		want = 0;
	size_t		need = 0;
	int		b;
	uint8_t		buf[XFRM_BYTES];

	assert(src);

	for (pass = 0; pass <= _collate_info->directive_count; pass++) {

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
		if (pass == _collate_info->directive_count) {
			direc = DIRECTIVE_FORWARD | DIRECTIVE_UNDEFINED;
		} else {
			direc = _collate_info->directive[pass];
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

				_collate_lookup(t, &len, &pri, pass, &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					pri = COLLATE_MAX_PRIORITY;
				}

				b = xfrm(buf, pri, pass);
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
				_collate_lookup(t, &len, &pri, pass, &state);
				t += len;
				if (pri <= 0) {
					if (pri < 0) {
						errno = EINVAL;
						goto fail;
					}
					continue;
				}

				b = xfrm(buf, pri, pass);
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
