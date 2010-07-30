/*
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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include "ldpart.h"
#include "lmonetary.h"

extern int __mlocale_changed;
extern const char *__fix_locale_grouping_str(const char *);

#define	LCMONETARY_SIZE_FULL (sizeof (struct lc_monetary_T) / sizeof (char *))
#define	LCMONETARY_SIZE_MIN \
	(offsetof(struct lc_monetary_T, int_p_cs_precedes) / sizeof (char *))

static char	empty[] = "";
static char	numempty[] = { CHAR_MAX, '\0' };

static const struct lc_monetary_T _C_monetary_locale = {
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
	numempty	/* int_n_sign_posn */
};

static struct lc_monetary_T _monetary_locale;
static int	_monetary_using_locale;
static char	*_monetary_locale_buf;

static char
cnv(const char *str)
{
	int i = strtol(str, NULL, 10);

	if (i == -1)
		i = CHAR_MAX;
	return ((char)i);
}

int
__monetary_load_locale(const char *name)
{
	int ret;

	ret = __part_load_locale(name, &_monetary_using_locale,
	    &_monetary_locale_buf, "LC_MONETARY",
	    LCMONETARY_SIZE_FULL, LCMONETARY_SIZE_MIN,
	    (const char **)&_monetary_locale);
	if (ret != _LDP_ERROR)
		__mlocale_changed = 1;
	if (ret == _LDP_LOADED) {
		_monetary_locale.mon_grouping =
		    __fix_locale_grouping_str(_monetary_locale.mon_grouping);

#define	M_ASSIGN_CHAR(NAME) \
		(((char *)_monetary_locale.NAME)[0] = \
			cnv(_monetary_locale.NAME))

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
#define	M_ASSIGN_ICHAR(NAME)					\
		if (_monetary_locale.int_##NAME == NULL)	\
			_monetary_locale.int_##NAME =		\
			    _monetary_locale.NAME;		\
		else						\
			M_ASSIGN_CHAR(int_##NAME);

		M_ASSIGN_ICHAR(p_cs_precedes);
		M_ASSIGN_ICHAR(n_cs_precedes);
		M_ASSIGN_ICHAR(p_sep_by_space);
		M_ASSIGN_ICHAR(n_sep_by_space);
		M_ASSIGN_ICHAR(p_sign_posn);
		M_ASSIGN_ICHAR(n_sign_posn);
	}
	return (ret);
}

struct lc_monetary_T *
__get_current_monetary_locale(void)
{
	return (_monetary_using_locale ? &_monetary_locale :
	    (struct lc_monetary_T *)&_C_monetary_locale);
}
