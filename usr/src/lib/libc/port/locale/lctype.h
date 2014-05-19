/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_LCTYPE_H_
#define	_LCTYPE_H_

#include <wchar.h>

/* private LC_CTYPE related structures */

/* encoding callbacks */
struct lc_ctype {

	size_t (*lc_mbrtowc)(wchar_t *_RESTRICT_KYWD,
	    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD);

	int (*lc_mbsinit)(const mbstate_t *);

	size_t (*lc_mbsnrtowcs)(wchar_t *_RESTRICT_KYWD,
	    const char **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);

	size_t (*lc_wcrtomb)(char *_RESTRICT_KYWD, wchar_t,
	    mbstate_t *_RESTRICT_KYWD);

	size_t (*lc_wcsnrtombs)(char *_RESTRICT_KYWD,
	    const wchar_t **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);

	unsigned char lc_is_ascii;
	unsigned char lc_max_mblen;

	const int *lc_trans_upper;
	const int *lc_trans_lower;
	const unsigned *lc_ctype_mask;
};

/*
 * Default implementation (C locale, i.e. ASCII).
 */
size_t	__mbrtowc_ascii(wchar_t *_RESTRICT_KYWD,
    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD);
int	__mbsinit_ascii(const mbstate_t *);
size_t	__mbsnrtowcs_ascii(wchar_t *_RESTRICT_KYWD dst,
    const char **_RESTRICT_KYWD src, size_t nms, size_t len,
    mbstate_t *_RESTRICT_KYWD);
size_t	__wcrtomb_ascii(char *_RESTRICT_KYWD, wchar_t,
    mbstate_t *_RESTRICT_KYWD);
size_t	__wcsnrtombs_ascii(char *_RESTRICT_KYWD,
    const wchar_t **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD);


#endif /* !_LCTYPE_H_ */
