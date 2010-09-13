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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*LINTLIBRARY*/
#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <wchar.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "libadm.h"

#define	MWIDTH	256
#define	WIDTH	60

int
puttext(FILE *fp, char *str, int lmarg, int rmarg)
{
	wchar_t	*wstr, *wp;
	wchar_t	*copy, *lastword, *lastend, temp[MWIDTH+1];
	size_t	len, ret;
	int	width, i, n, force, wordcnt;
	int	wlen, mlen, bdg;
	char	mbs[MB_LEN_MAX];
	char	mbtemp[(MWIDTH+1) * MB_LEN_MAX];

	width = rmarg ? (rmarg - lmarg) : (WIDTH - lmarg);
	if (width > MWIDTH)
		width = MWIDTH;

	if (!str || !*str)
		return (width);

	len = strlen(str);
	wstr = (wchar_t *)malloc(sizeof (wchar_t) * (len + 1));
	if (wstr == NULL)
		return (width);

	ret = mbstowcs(wstr, (const char *)str, len + 1);
	if (ret == (size_t)-1) {
		free(wstr);
		return (width);
	}

	wp = wstr;

	if (*wp == L'!') {
		wp++;
		force = 1;
		for (i = 0; i < lmarg; i++)
			(void) putc(' ', fp);
	} else {
		while (iswspace(*wp))
			++wp;	/* eat leading white space */
		force = 0;
	}

	wordcnt = 0;
	n = 0;
	copy = temp;
	lastword = wp;
	lastend = NULL;
	do {
		if (force) {
			if (*wp == L'\n') {
				(void) putc('\n', fp);
				for (i = 0; i < lmarg; i++)
					(void) putc(' ', fp);
				wp++;
				n = 0;
			} else {
				wlen = wcwidth(*wp);
		/*
		 * Using putc instead of fputwc here to avoid
		 * mixing up the byte stream and the wide stream
		 * for fp.
		 */
				mlen = wctomb(mbs, *wp);
				if (mlen == -1) {
		/*
		 * wctomb failed
		 * nothing will be outputted
		 */
					wp++;
				} else {
					for (i = 0; i < mlen; i++)
						(void) putc(mbs[i], fp);
					wp++;
		/*
		 * if wlen is a negative value (*wp is not printable),
		 * add 1 to n. (non-printable char shares 1 column.
		 */
					if (wlen >= 0)
						n += wlen;
					else
						n++;
				}
			}
			continue;
		}
		if (iswspace(*wp)) {
			/* eat multiple tabs/nl after whitespace */
			while ((*++wp == L'\t') || (*wp == '\n'));
			wordcnt++;
			lastword = wp;
			lastend = copy;
			*copy++ = L' ';
			n++;
		} else if (*wp == L'\\') {
			if (*(wp + 1) == L'n') {
				wordcnt++;
				n = width + 1;
				wp += 2;
				lastword = wp;
				lastend = copy;
			} else if (*(wp + 1) == L't') {
				wordcnt++;
				do {
					*copy++ = L' ';
				} while (++n % 8);
				n++;
				wp += 2;
				lastword = wp;
				lastend = copy;
			} else if (*(wp + 1) == L' ') {
				*copy++ = L' ';
				wp += 2;
				n++;
			} else {
				if (iswprint(*wp) && iswprint(*(wp + 1))) {
		/*
		 * Only if both *wp and *(wp +1) are printable,
		 * tries to check the binding weight between them.
		 */
					wlen = wcwidth(*wp);
					if (n + wlen > width) {
		/*
		 * if (n + wlen) is larger than width, *wp will be
		 * put to the next line.
		 */
						*copy++ = *wp++;
						n = width + 1;
						goto fold;
					} else {
						n += wlen;
						bdg = wdbindf(*wp,
							*(wp + 1), 1);
						*copy++ = *wp++;
						if (bdg < 5) {
		/*
		 * binding weight between *wp and *(wp + 1) is
		 * enough small to fold the line there.
		 */
							lastword = wp;
							lastend = copy;
							wordcnt++;
						}
					}
				} else {
					wlen = wcwidth(*wp);
					if (wlen > 0) {
		/*
		 * *wp is printable
		 */
						if (n + wlen > width) {
		/*
		 * if (n + wlen) is larger than width, *wp will
		 * be put to the next line.
		 */
							*copy++ = *wp++;
							n = width + 1;
							goto fold;
						} else {
							n += wlen;
						}
					} else {
		/*
		 * *wp is not printable, and shares 1 column.
		 */
						n++;
					}
					*copy++ = *wp++;
				}
			}
		} else {
			if (iswprint(*wp) && iswprint(*(wp + 1))) {
		/*
		 * Only if both *wp and *(wp + 1) are printable,
		 * tries to check the binding weight between them.
		 */
				wlen = wcwidth(*wp);
				if (n + wlen > width) {
		/*
		 * if (n + wlen) is larger than width, *wp will be
		 * put to the next line.
		 */
					*copy++ = *wp++;
					n = width + 1;
					goto fold;
				}
				n += wlen;
				bdg = wdbindf(*wp, *(wp + 1), 1);
				*copy++ = *wp++;
				if (bdg < 5) {
		/*
		 * binding weight between *wp and *(wp + 1) is
		 * enough small to fold the line there.
		 */
					lastword = wp;
					lastend = copy;
					wordcnt++;
				}
			} else {
				wlen = wcwidth(*wp);
				if (wlen > 0) {
		/*
		 * *wp is printable
		 */
					if (n + wlen > width) {
		/*
		 * if (n + wlen) is larger than width, *wp will
		 * be put to the next line.
		 */
						*copy++ = *wp++;
						n = width + 1;
						goto fold;
					} else {
						n += wlen;
					}
				} else {
		/*
		 * *wp is not printable, and shares 1 column.
		 */
					n++;
				}
				*copy++ = *wp++;
			}
		}

fold:
		if (n >= width) {
			if (lastend)
				*lastend = L'\0';
			else
				*copy = L'\0';
			for (i = 0; i < lmarg; i++)
				(void) putc(' ', fp);
			mlen = wcstombs(mbtemp, temp, MWIDTH+1);
			for (i = 0; i < mlen; i++)
				(void) putc(mbtemp[i], fp);
			(void) putc('\n', fp);

			lastend = NULL;
			copy = temp;
			if (wordcnt)
				wp = lastword;

			wordcnt = 0;
			n = 0;
			if (!force) {
				while (iswspace(*wp))
					wp++;
			}
		}
	} while (*wp != L'\0');
	if (!force) {
		*copy = L'\0';
		for (i = 0; i < lmarg; i++)
			(void) putc(' ', fp);
		mlen = wcstombs(mbtemp, temp, MWIDTH+1);
		for (i = 0; i < mlen; i++)
			(void) putc(mbtemp[i], fp);
	}
	free(wstr);
	return (width - n - !force);
}
