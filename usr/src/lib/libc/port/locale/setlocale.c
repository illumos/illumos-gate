/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1996 - 2002 FreeBSD Project
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "mtlib.h"
#include "collate.h"
#include "lnumeric.h"	/* for struct lc_numeric */
#include "lctype.h"	/* for struct lc_ctype */
#include "setlocale.h"
#include "../i18n/_loc_path.h"
#include "localeimpl.h"
#include "../i18n/_locale.h"
#include "libc.h"

/*
 * Path to locale storage directory.  See ../i18n/_loc_path.h
 */
char	*_PathLocale = _DFLT_LOC_PATH;

static void	install_legacy(locale_t, int);

static mutex_t setlocale_lock = DEFAULTMUTEX;
static locale_t setlocale_list = NULL;

char *
setlocale(int category, const char *locname)
{
	locale_t loc;
	locale_t srch;
	int mask;

	if (category < 0 || category > LC_ALL) {
		errno = EINVAL;
		return (NULL);
	}

	if (locname == NULL)
		return (current_locale(___global_locale, category));

	mask = (category == LC_ALL ? LC_ALL_MASK : (1 << category));

	loc = newlocale(mask, locname, NULL);
	if (loc == NULL) {
		return (NULL);
	}

	/*
	 * This next logic looks to see if we have ever used the same locale
	 * settings before.  If so, we reuse it.  We avoid ever calling
	 * freelocale() on a locale setting built up by setlocale, this
	 * ensures that consumers (uselocale) will always be thread safe;
	 * the actual locale data objects are never freed, and unique
	 * locale objects are also never freed.  We reuse to avoid leaking
	 * memory in applications that call setlocale repeatedly.
	 */
	lmutex_lock(&setlocale_lock);
	for (srch = setlocale_list; srch != NULL; srch = srch->next) {
		if (strcmp(srch->locname, loc->locname) == 0) {
			break;
		}
	}

	if (srch == NULL) {
		/* this is a new locale, save it for reuse later */
		loc->next = setlocale_list;
		loc->on_list = 1;
		setlocale_list = loc;
	} else {
		/* we already had it, toss the new, and use what we found */
		freelocale(loc);
		loc = srch;
	}
	___global_locale = loc;

	install_legacy(loc, mask);
	lmutex_unlock(&setlocale_lock);

	return (current_locale(loc, category));
}

char *
current_locale(locale_t loc, int cat)
{
	switch (cat) {
	case LC_CTYPE:
	case LC_COLLATE:
	case LC_MESSAGES:
	case LC_MONETARY:
	case LC_NUMERIC:
	case LC_TIME:
		return (loc->locdata[cat]->l_lname);
	case LC_ALL:
		return (loc->locname);
	default:
		return (NULL);
	}
}

static void
install_legacy(locale_t loc, int mask)
{
	/*
	 * Update the legacy fixed variables that may be baked into
	 * legacy programs.  This is really unfortunate, but we can't
	 * solve for them otherwise.  Note that such legacy programs
	 * are only going to see the global locale settings, and cannot
	 * benefit from uselocale().
	 */
	if (mask & LC_NUMERIC_MASK) {
		struct lc_numeric *lnum;
		lnum = loc->locdata[LC_NUMERIC]->l_data[0];
		_numeric[0] = *lnum->decimal_point;
		_numeric[1] = *lnum->thousands_sep;
	}

	if (mask & LC_CTYPE_MASK) {
		struct lc_ctype *lct;
		lct = loc->locdata[LC_CTYPE]->l_data[0];
		for (int i = 0; i < _CACHED_RUNES; i++) {
			/* ctype can only encode the lower 8 bits. */
			__ctype[i+1] = lct->lc_ctype_mask[i] & 0xff;
			__ctype_mask[i] = lct->lc_ctype_mask[i];
		}

		/* The bottom half is the toupper/lower array */
		for (int i = 0; i < _CACHED_RUNES; i++) {
			int u, l;
			__ctype[258 + i] = i;
			u = lct->lc_trans_upper[i];
			l = lct->lc_trans_lower[i];
			if (u && u != i)
				__ctype[258+i] = u;
			if (l && l != i)
				__ctype[258+i] = l;

			/* Don't forget these annoyances either! */
			__trans_upper[i] = u;
			__trans_lower[i] = l;
		}

		/* Maximum mblen, cswidth, weird legacy */
		__ctype[520] = lct->lc_max_mblen;
	}
}
