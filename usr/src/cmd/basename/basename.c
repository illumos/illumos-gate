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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef	XPG4
#include <unistd.h>
#include <regex.h>
#include <libintl.h>
#endif

int
main(int argc, char **argv)
{
	char	*p;
	char	*string;
	char	*suffix;
#ifndef	XPG4
	int	r;
	char	suf_buf[256];
	char	*suf_pat;
	size_t	suf_len;
	regex_t	reg;
	regmatch_t	pmatch[2];
#endif

	/*
	 * For better performance, defer the setlocale()/textdomain()
	 * calls until they get really required.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	if (argc == 1) {
		(void) puts(".");
		return (0);
	}

#ifdef	XPG4
	if (strcmp(argv[1], "--") == 0) {
		argv++;
		argc--;
		if (argc == 1) {
			(void) puts(".");
			return (0);
		}
	}
#endif
	if (argc > 3) {
		(void) setlocale(LC_ALL, "");
		(void) textdomain(TEXT_DOMAIN);
		(void) fputs(gettext("Usage: basename string [ suffix ]\n"),
		    stderr);
		return (1);
	}

	string = argv[1];
	suffix = (argc == 2) ? NULL : argv[2];

	if (*string == '\0') {
		(void) puts(".");
		return (0);
	}

	/* remove trailing slashes */
	p = string + strlen(string) - 1;
	while (p >= string && *p == '/')
		*p-- = '\0';

	if (*string == '\0') {
		(void) puts("/");
		return (0);
	}

	/* skip to one past last slash */
	if ((p = strrchr(string, '/')) != NULL)
		string = p + 1;

	if (suffix == NULL) {
		(void) puts(string);
		return (0);
	}

#ifdef	XPG4
	/*
	 * if a suffix is present and is not the same as the remaining
	 * string and is identical to the last characters in the remaining
	 * string, remove those characters from the string.
	 */
	if (strcmp(string, suffix) != 0) {
		p = string + strlen(string) - strlen(suffix);
		if (strcmp(p, suffix) == 0)
			*p = '\0';
	}
	(void) puts(string);
	return (0);
#else
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	suf_len = 6 + strlen(suffix) + 1 + 1; /* \(.*\)suffix$ */
	if (suf_len > sizeof (suf_buf)) {
		suf_pat = malloc(suf_len);
		if (suf_pat == NULL) {
			(void) fputs("malloc failed\n", stderr);
			return (1);
		}
	} else {
		suf_pat = suf_buf;
	}
	(void) strcpy(suf_pat, "\\(.*\\)");
	(void) strcpy(suf_pat + 6, suffix);
	*(suf_pat + suf_len - 1 - 1) = '$';
	*(suf_pat + suf_len - 1) = '\0';

	r = regcomp(&reg, suf_pat, 0);
	if (r != 0) {
		(void) fprintf(stderr,
		    "Internal error: regcomp failed for \"%s\"\n",
		    suf_pat);
		return (1);
	}
	r = regexec(&reg, string, 2, pmatch, 0);
	if (r == 0) {
		if (pmatch[0].rm_so == (regoff_t)-1 ||
		    pmatch[1].rm_so == (regoff_t)-1 ||
		    pmatch[1].rm_so != 0) {
			(void) fprintf(stderr, "Internal error: regexec did "
			    "not set sub-expression for:\n");
			(void) fprintf(stderr, "path: \"%s\"\n", string);
			(void) fprintf(stderr, "pattern: \"%s\"", suf_pat);
			return (1);
		}
		if (pmatch[1].rm_so == pmatch[1].rm_eo) {
			/* a null string matched */
			(void) printf("%s\n", string);
			return (0);
		}
		string[pmatch[1].rm_eo] = '\0';
	}
	(void) puts(string);
	return (0);
#endif
}
