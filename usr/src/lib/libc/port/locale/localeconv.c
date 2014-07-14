/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2001 Alexey Zelkin <phantom@FreeBSD.org>
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#ifndef	_LCONV_C99
#define	_LCONV_C99	/* so we get all the extensions */
#endif

#include "lint.h"
#include <locale.h>
#include "lmonetary.h"
#include "lnumeric.h"
#include "localeimpl.h"

/*
 * Return the current locale conversion.
 *
 * Note that XPG7 specifically states that localeconv's return value may
 * be invalidated if the application calls setlocale() or uselocale() within
 * the same thread.
 *
 * Because localeconv() may be called many times (especially by library
 * routines like printf() & strtod()), the approprate members of the
 * lconv structure are computed only when the monetary or numeric
 * locale has been changed.
 */
struct lconv *
localeconv(void)
{
	struct lconv	*lconv;
	locale_t	loc;
	struct lc_monetary	*mptr;
	struct lc_numeric	*nptr;

	loc = uselocale(NULL);
	lconv = &loc->lconv;

	if (loc->loaded[LC_MONETARY] == 0) {
		mptr = loc->locdata[LC_MONETARY]->l_data[0];

#define	M_ASSIGN_STR(NAME) (lconv->NAME = (char *)mptr->NAME)
#define	M_ASSIGN_CHAR(NAME) (lconv->NAME = mptr->NAME[0])

		M_ASSIGN_STR(int_curr_symbol);
		M_ASSIGN_STR(currency_symbol);
		M_ASSIGN_STR(mon_decimal_point);
		M_ASSIGN_STR(mon_thousands_sep);
		M_ASSIGN_STR(mon_grouping);
		M_ASSIGN_STR(positive_sign);
		M_ASSIGN_STR(negative_sign);
		M_ASSIGN_CHAR(int_frac_digits);
		M_ASSIGN_CHAR(frac_digits);
		M_ASSIGN_CHAR(p_cs_precedes);
		M_ASSIGN_CHAR(p_sep_by_space);
		M_ASSIGN_CHAR(n_cs_precedes);
		M_ASSIGN_CHAR(n_sep_by_space);
		M_ASSIGN_CHAR(p_sign_posn);
		M_ASSIGN_CHAR(n_sign_posn);
		M_ASSIGN_CHAR(int_p_cs_precedes);
		M_ASSIGN_CHAR(int_n_cs_precedes);
		M_ASSIGN_CHAR(int_p_sep_by_space);
		M_ASSIGN_CHAR(int_n_sep_by_space);
		M_ASSIGN_CHAR(int_p_sign_posn);
		M_ASSIGN_CHAR(int_n_sign_posn);
		loc->loaded[LC_MONETARY] = 1;
	}

	if (loc->loaded[LC_NUMERIC] == 0) {
		nptr = loc->locdata[LC_NUMERIC]->l_data[0];

#define	N_ASSIGN_STR(NAME) (lconv->NAME = (char *)nptr->NAME)

		N_ASSIGN_STR(decimal_point);
		N_ASSIGN_STR(thousands_sep);
		N_ASSIGN_STR(grouping);
		loc->loaded[LC_NUMERIC] = 1;
	}

	return (lconv);
}
