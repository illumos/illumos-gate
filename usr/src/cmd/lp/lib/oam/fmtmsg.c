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
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

#include "stdio.h"
#include "string.h"

#include "oam.h"
#include <stdlib.h>
#include <widec.h>
#include <libintl.h>
#include <locale.h>

#define LINE_LEN 70

#define SHORT_S 80
#define LONG_S  2000

static char		*severity_names[MAX_SEVERITY-MIN_SEVERITY+1] = {
	"HALT",
	"ERROR",
	"WARNING",
	"INFO"
};

static const char	*TOFIX	= "TO FIX";

static int		wrap(wchar_t *, wchar_t *, int, wchar_t *);

/**
 ** fmtmsg()
 **/

void
fmtmsg(char *label, int severity, char *text, char *action)
{
	int	tofix_len, indent_len;
	wchar_t	wtofix[SHORT_S], wlabel[SHORT_S], wsev[SHORT_S], wtext[LONG_S],
		null[1] = {0};

	/*
	 * Return if the severity isn't recognized.
	 */
	if (severity < MIN_SEVERITY || MAX_SEVERITY < severity)
		return;

	mbstowcs(wtofix, gettext(TOFIX), SHORT_S);
	mbstowcs(wlabel, label, SHORT_S);
	mbstowcs(wsev, gettext(severity_names[severity]), SHORT_S);
	mbstowcs(wtext, text, LONG_S);

	tofix_len = wscol(wtofix),
	indent_len = wscol(wlabel) + wscol(wsev) + 2;
	if (indent_len < tofix_len)
		indent_len = tofix_len;

	if (wrap(wlabel, wsev, indent_len, wtext) <= 0)
		return;

	if (action && *action) {
		if (fputc('\n', stderr) == EOF)
			return;

		mbstowcs(wtext, action, LONG_S);
		if (wrap(wtofix, null, indent_len, wtext) <= 0)
			return;
	}

	if (fputc('\n', stderr) == EOF)
		return;

	fflush (stderr);
}

/**
 ** wrap() - PUT OUT "STUFF: string", WRAPPING string AS REQUIRED
 **/

static int
wrap(wchar_t *prefix, wchar_t *suffix, int indent_len, wchar_t *str)
{
	int	len, n, col;
	int	maxlen, tmpcol;
	wchar_t	*p, *pw, *ppw;
	static const wchar_t	eol[] = {L'\r', L'\n', L'\0'};

	/*
	 * Display the initial stuff followed by a colon.
	 */
	if ((len = wscol(suffix)))
		n = fprintf(stderr, gettext("%*ws: %ws: "),
			indent_len - len - 2, prefix, suffix);
	else
		n = fprintf(stderr, gettext("%*ws: "), indent_len, prefix);
	if (n <= 0)
		return (-1);

	maxlen = LINE_LEN - indent_len - 1;

	/* Check for bogus indent_len */
	if (maxlen < 1) {
		return (-1);
	}

	/*
	 * Loop once for each line of the string to display.
	 */
	for (p = str; *p; ) {

		/*
		 * Display the next "len" bytes of the string, where
		 * "len" is the smallest of:
		 *
		 *	- LINE_LEN
		 *	- # bytes before control character
		 *	- # bytes left in string
		 *
		 */

		len = wcscspn(p, eol);
		/* calc how many columns the string will take */
		col = wcswidth(p, len);
		if (col > maxlen) {
			/*
			 * How many characters fit into our desired line length
			 */
			pw = p;
			tmpcol = 0;
			while (*pw) {
				if (iswprint(*pw))
					tmpcol += wcwidth(*pw);
				if (tmpcol > maxlen)
					break;
				else
					pw++;
			}
			/*
			 * At this point, pw may point to:
			 * A null character:  EOL found (should never happen, though)
			 * The character that just overruns the maxlen.
			 */
			if (!*pw) {
				/*
				 * Found a EOL.
				 * This should never happen.
				 */
				len = pw - p;
				goto printline;
			}
			ppw = pw;
			/*
			 * Don't split words
			 *
			 * Bugid 4202307 - liblpoam in lp internal library doesn't
			 * handle multibyte character.
			 */
			while (pw > p) {
				if (iswspace(*pw) ||
				    (wdbindf(*(pw - 1), *pw, 1) < 5)) {
					break;
				} else {
					pw--;
				}
			}
			if (pw != p) {
				len = pw - p;
			} else {
				/*
				 * Failed to find the best place to fold.
				 * So, prints as much characters as maxlen allows
				 */
				len = ppw - p;
			}
		}

printline:
		for (n = 0; n < len; n++, p++) {
			if (iswprint(*p)) {
				if (fputwc(*p, stderr) == WEOF) {
					return (-1);
				}
			}
		}

		/*
		 * If we displayed up to a control character,
		 * put out the control character now; otherwise,
		 * put out a newline unless we've put out all
		 * the text.
		 */

		if (*p == L'\r' || *p == L'\n') {
			while (*p == L'\r' || *p == L'\n') {
				if (fputwc(*p, stderr) == WEOF)
					return (-1);
				p++;
			}
		} else if (*p) {
			if (fputwc(L'\n', stderr) == WEOF)
				return (-1);
		}

		while (iswspace(*p))
			p++;

		/*
		 * If the loop won't end this time (because we
		 * have more stuff to display) put out leading
		 * blanks to align the next line with the previous
		 * lines.
		 */
		if (*p) {
			for (n = 0; n < indent_len + 2; n++)
				(void) fputwc(L' ', stderr);
		}
	}

	return (1);
}
