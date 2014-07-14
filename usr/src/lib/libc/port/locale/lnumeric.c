/*
 * Copyright 2014 Garrett D'Amore.
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2000, 2001 Alexey Zelkin <phantom@FreeBSD.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <limits.h>
#include <errno.h>
#include "ldpart.h"
#include "lnumeric.h"
#include "localeimpl.h"

extern const char *__fix_locale_grouping_str(const char *);

#define	LCNUMERIC_SIZE (sizeof (struct lc_numeric) / sizeof (char *))

static char	numempty[] = { CHAR_MAX, '\0' };

struct lc_numeric lc_numeric_posix = {
	".",		/* decimal_point */
	"",		/* thousands_sep */
	numempty	/* grouping */
};

struct locdata __posix_numeric_locdata = {
	.l_lname = "C",
	.l_data = { &lc_numeric_posix }
};


/*
 * Return the locale's numeric locdata structure.
 */
struct locdata *
__lc_numeric_load(const char *name)
{
	struct locdata *ldata;
	struct lc_numeric *lnum;
	int ret;

	if ((ldata = __locdata_alloc(name, sizeof (*lnum))) == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	lnum = ldata->l_data[0];

	ret = __part_load_locale(name, (char **)&ldata->l_data[1],
	    "LC_NUMERIC", LCNUMERIC_SIZE, LCNUMERIC_SIZE, (const char **)lnum);

	if (ret != _LDP_LOADED) {
		__locdata_free(ldata);
		return (NULL);
	}

	/* Can't be empty according to C99 */
	if (*lnum->decimal_point == '\0')
		lnum->decimal_point = lc_numeric_posix.decimal_point;
	lnum->grouping = __fix_locale_grouping_str(lnum->grouping);

	return (ldata);
}
