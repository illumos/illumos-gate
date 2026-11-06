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
 * Copyright 2018 Nexenta Systems, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

#include <err.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct {
	const char *locale;
	const char *convspec;
	const unsigned ptr;
	const char *expected;
} pconv[] = {
	"C", "%#20p", 0xffffffff, "          0xffffffff",
	"C", "%-#20p", 0xffffffff, "0xffffffff          ",
	"C", "%#020p", 0xffffffff, "0x0000000000ffffffff",
	"C", "%#.20p", 0xffffffff, "0x000000000000ffffffff",
	NULL, NULL, 0, NULL
};

struct {
	const char *locale;
	const wchar_t *convspec;
	const unsigned ptr;
	const wchar_t *expected;
} wpconv[] = {
	"C", L"%#20p", 0xffffffff, L"          0xffffffff",
	"C", L"%-#20p", 0xffffffff, L"0xffffffff          ",
	"C", L"%#020p", 0xffffffff, L"0x0000000000ffffffff",
	"C", L"%#.20p", 0xffffffff, L"0x000000000000ffffffff",
	NULL, NULL, 0, NULL
};

int
main(void)
{
	char buf[100];
	wchar_t wbuf[100];
	int i;

	for (i = 0; pconv[i].locale != NULL; i++) {
		if (setlocale(LC_ALL, pconv[i].locale) == NULL)
			err(1, "failed to set locale to %s", pconv[i].locale);

		(void) sprintf(buf, pconv[i].convspec, pconv[i].ptr);
		if (strcmp(pconv[i].expected, buf) != 0) {
			errx(1,
			    "locale=%s, convspec=%s, expected='%s', got='%s'",
			    pconv[i].locale, pconv[i].convspec,
			    pconv[i].expected, buf);
		}
	}

	for (i = 0; wpconv[i].locale != NULL; i++) {
		if (setlocale(LC_ALL, wpconv[i].locale) == NULL)
			err(1, "failed to set locale to %s", wpconv[i].locale);

		(void) swprintf(wbuf, sizeof (wbuf),
		    wpconv[i].convspec, wpconv[i].ptr);
		if (wcscmp(wpconv[i].expected, wbuf) != 0) {
			errx(1,
			    "locale=%s, convspec=%ls, expected='%ls', "
			    "got='%ls'",
			    wpconv[i].locale, wpconv[i].convspec,
			    wpconv[i].expected, wbuf);
		}
	}
	return (0);
}
