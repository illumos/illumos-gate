/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
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
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "ldpart.h"
#include "lmonetary.h"
#include "localeimpl.h"

extern const char *__fix_locale_grouping_str(const char *);

#define	LCMONETARY_SIZE_FULL (sizeof (struct lc_monetary) / sizeof (char *))
#define	LCMONETARY_SIZE_MIN \
	(offsetof(struct lc_monetary, int_p_cs_precedes) / sizeof (char *))

static char	empty[] = "";
static char	numempty[] = { CHAR_MAX, '\0' };

struct lc_monetary lc_monetary_posix = {
	empty,		/* int_curr_symbol */
	empty,		/* currency_symbol */
	empty,		/* mon_decimal_point */
	empty,		/* mon_thousands_sep */
	numempty,	/* mon_grouping */
	empty,		/* positive_sign */
	empty,		/* negative_sign */
	numempty,	/* int_frac_digits */
	numempty,	/* frac_digits */
	numempty,	/* p_cs_precedes */
	numempty,	/* p_sep_by_space */
	numempty,	/* n_cs_precedes */
	numempty,	/* n_sep_by_space */
	numempty,	/* p_sign_posn */
	numempty,	/* n_sign_posn */
	numempty,	/* int_p_cs_precedes */
	numempty,	/* int_n_cs_precedes */
	numempty,	/* int_p_sep_by_space */
	numempty,	/* int_n_sep_by_space */
	numempty,	/* int_p_sign_posn */
	numempty,	/* int_n_sign_posn */
	empty		/* crncystr */
};

struct locdata __posix_monetary_locdata = {
	.l_lname = "C",
	.l_data = { &lc_monetary_posix }
};

static char
cnv(const char *str)
{
	int i = strtol(str, NULL, 10);

	if (i == -1)
		i = CHAR_MAX;
	return ((char)i);
}

struct locdata *
__lc_monetary_load(const char *name)
{
	int ret;
	int clen;
	struct lc_monetary	*lmon;
	struct locdata		*ldata;

	if ((ldata = __locdata_alloc(name, sizeof (*lmon))) == NULL) {
		return (NULL);
	}
	lmon = ldata->l_data[0];

	ret = __part_load_locale(name, (char **)&ldata->l_data[1],
	    "LC_MONETARY", LCMONETARY_SIZE_FULL, LCMONETARY_SIZE_MIN,
	    (const char **)lmon);

	if (ret != _LDP_LOADED) {
		__locdata_free(ldata);
		errno = EINVAL;
		return (NULL);
	}

	/* special storage for currency string */
	clen = strlen(lmon->currency_symbol) + 2;
	ldata->l_data[2] = libc_malloc(clen);
	lmon->crncystr = ldata->l_data[2];

	lmon->mon_grouping = __fix_locale_grouping_str(lmon->mon_grouping);

#define	M_ASSIGN_CHAR(NAME) \
	(((char *)lmon->NAME)[0] = cnv(lmon->NAME))

	M_ASSIGN_CHAR(int_frac_digits);
	M_ASSIGN_CHAR(frac_digits);
	M_ASSIGN_CHAR(p_cs_precedes);
	M_ASSIGN_CHAR(p_sep_by_space);
	M_ASSIGN_CHAR(n_cs_precedes);
	M_ASSIGN_CHAR(n_sep_by_space);
	M_ASSIGN_CHAR(p_sign_posn);
	M_ASSIGN_CHAR(n_sign_posn);

	/*
	 * The six additional C99 international monetary formatting
	 * parameters default to the national parameters when
	 * reading FreeBSD LC_MONETARY data files.
	 */
#define	M_ASSIGN_ICHAR(NAME)				\
	if (lmon->int_##NAME == NULL)			\
		lmon->int_##NAME = lmon->NAME;		\
	else						\
		M_ASSIGN_CHAR(int_##NAME);

	M_ASSIGN_ICHAR(p_cs_precedes);
	M_ASSIGN_ICHAR(n_cs_precedes);
	M_ASSIGN_ICHAR(p_sep_by_space);
	M_ASSIGN_ICHAR(n_sep_by_space);
	M_ASSIGN_ICHAR(p_sign_posn);
	M_ASSIGN_ICHAR(n_sign_posn);

	/*
	 * Now calculate the currency string (CRNCYSTR) for nl_langinfo.
	 * This is a legacy SUSv2 interface.
	 */
	if ((lmon->p_cs_precedes[0] == lmon->n_cs_precedes[0]) &&
	    (lmon->currency_symbol[0] != '\0')) {
		char sign = '\0';
		switch (lmon->p_cs_precedes[0]) {
		case 0:
			sign = '-';
			break;
		case 1:
			sign = '+';
			break;
		case CHAR_MAX:
			/*
			 * Substitute currency string for radix character.
			 * To the best of my knowledge, no locale uses this.
			 */
			if (strcmp(lmon->mon_decimal_point,
			    lmon->currency_symbol) == 0)
				sign = '.';
			break;
		}
		(void) snprintf(lmon->crncystr, clen, "%c%s", sign,
		    lmon->currency_symbol);
	}

	return (ldata);
}
