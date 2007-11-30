/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <locale.h>
#include <langinfo.h>
#include <iconv.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "includes.h"
#include "xmalloc.h"
#include "xlist.h"

#ifdef MIN
#undef MIN
#endif /* MIN */

#define	MIN(x, y)	((x) < (y) ? (x) : (y))

#define	LOCALE_PATH	"/usr/bin/locale"

/* two-char country code, '-' and two-char region code */
#define	LANGTAG_MAX	5

static uchar_t *do_iconv(iconv_t cd, uint_t *mul_ptr, const void *buf,
    uint_t len, uint_t *outlen, int *err, uchar_t **err_str);

static int locale_cmp(const void *d1, const void *d2);
static char *g11n_locale2langtag(char *locale);

uint_t g11n_validate_ascii(const char *str, uint_t len, uchar_t **error_str);
uint_t g11n_validate_utf8(const uchar_t *str, uint_t len, uchar_t **error_str);

/*
 * Convert locale string name into a language tag. The caller is responsible for
 * freeing the memory allocated for the result.
 */
static char *
g11n_locale2langtag(char *locale)
{
	char *langtag;

	/* base cases */
	if (!locale || !*locale)
		return (NULL);

	if (strcmp(locale, "POSIX") == 0 || strcmp(locale, "C") == 0)
		return (xstrdup("i-default"));

	/* punt for language codes which are not exactly 2 letters */
	if (strlen(locale) < 2 ||
	    !isalpha(locale[0]) ||
	    !isalpha(locale[1]) ||
	    (locale[2] != '\0' &&
	    locale[2] != '_' &&
	    locale[2] != '.' &&
	    locale[2] != '@'))
		return (NULL);


	/* we have a primary language sub-tag */
	langtag = (char *)xmalloc(LANGTAG_MAX + 1);

	strncpy(langtag, locale, 2);
	langtag[2] = '\0';

	/* do we have country sub-tag? For example: cs_CZ */
	if (locale[2] == '_') {
		if (strlen(locale) < 5 ||
		    !isalpha(locale[3]) ||
		    !isalpha(locale[4]) ||
		    (locale[5] != '\0' && (locale[5] != '.' &&
		    locale[5] != '@'))) {
			return (langtag);
		}

		/* example: create cs-CZ from cs_CZ */
		if (snprintf(langtag, 6, "%.*s-%.*s", 2, locale, 2,
		    locale + 3) == 5)
			return (langtag);
	}

	/* in all other cases we just use the primary language sub-tag */
	return (langtag);
}

uint_t
g11n_langtag_is_default(char *langtag)
{
	return (strcmp(langtag, "i-default") == 0);
}

/*
 * This lang tag / locale matching function works only for two-character
 * language primary sub-tags and two-character country sub-tags.
 */
uint_t
g11n_langtag_matches_locale(char *langtag, char *locale)
{
	/* match "i-default" to the process' current locale if possible */
	if (g11n_langtag_is_default(langtag)) {
		if (strcasecmp(locale, "POSIX") == 0 ||
		    strcasecmp(locale, "C") == 0)
			return (1);
		else
			return (0);
	}

	/*
	 * locale must be at least 2 chars long and the lang part must be
	 * exactly two characters
	 */
	if (strlen(locale) < 2 ||
	    (!isalpha(locale[0]) || !isalpha(locale[1]) ||
	    (locale[2] != '\0' && locale[2] != '_' &&
	    locale[2] != '.' && locale[2] != '@')))
		return (0);

	/* same thing with the langtag */
	if (strlen(langtag) < 2 ||
	    (!isalpha(langtag[0]) || !isalpha(langtag[1]) ||
	    (langtag[2] != '\0' && langtag[2] != '-')))
		return (0);

	/* primary language sub-tag and the locale's language part must match */
	if (strncasecmp(langtag, locale, 2) != 0)
		return (0);

	/*
	 * primary language sub-tag and the locale's language match, now
	 * fuzzy check country part
	 */

	/* neither langtag nor locale have more than one component */
	if (langtag[2] == '\0' &&
	    (locale[2] == '\0' || locale[2] == '.' || locale[2] == '@'))
		return (2);

	/* langtag has only one sub-tag... */
	if (langtag[2] == '\0')
		return (1);

	/* locale has no country code... */
	if (locale[2] == '\0' || locale[2] == '.' || locale[2] == '@')
		return (1);

	/* langtag has more than one subtag and the locale has a country code */

	/* ignore second subtag if not two chars */
	if (strlen(langtag) < 5)
		return (1);

	if (!isalpha(langtag[3]) || !isalpha(langtag[4]) ||
	    (langtag[5] != '\0' && langtag[5] != '-'))
		return (1);

	/* ignore rest of locale if there is no two-character country part */
	if (strlen(locale) < 5)
		return (1);

	if (locale[2] != '_' || !isalpha(locale[3]) || !isalpha(locale[4]) ||
	    (locale[5] != '\0' && locale[5] != '.' && locale[5] != '@'))
		return (1);

	/* if the country part matches, return 2 */
	if (strncasecmp(&langtag[3], &locale[3], 2) == 0)
		return (2);

	return (1);
}

char *
g11n_getlocale()
{
	/* we have one text domain - always set it */
	(void) textdomain(TEXT_DOMAIN);

	/* if the locale is not set, set it from the env vars */
	if (!setlocale(LC_MESSAGES, NULL))
		(void) setlocale(LC_MESSAGES, "");

	return (setlocale(LC_MESSAGES, NULL));
}

void
g11n_setlocale(int category, const char *locale)
{
	char *curr;

	/* we have one text domain - always set it */
	(void) textdomain(TEXT_DOMAIN);

	if (!locale)
		return;

	if (*locale && ((curr = setlocale(category, NULL))) &&
	    strcmp(curr, locale) == 0)
		return;

	/* if <category> is bogus, setlocale() will do nothing */
	(void) setlocale(category, locale);
}

char **
g11n_getlocales()
{
	FILE *locale_out;
	uint_t n_elems, list_size, long_line = 0;
	char **list;
	char locale[64];	/* 64 bytes is plenty for locale names */

	if ((locale_out = popen(LOCALE_PATH " -a", "r")) == NULL)
		return (NULL);

	/*
	 * start with enough room for 65 locales - that's a lot fewer than
	 * all the locales available for installation, but a lot more than
	 * what most users will need and install
	 */
	n_elems = 0;
	list_size = 192;
	list = (char **) xmalloc(sizeof (char *) * (list_size + 1));
	memset(list, 0, sizeof (char *) * (list_size + 1));

	while (fgets(locale, sizeof (locale), locale_out)) {
		/* skip long locale names (if any) */
		if (!strchr(locale, '\n')) {
			long_line = 1;
			continue;
		} else if (long_line) {
			long_line = 0;
			continue;
		}

		if (strncmp(locale, "iso_8859", 8) == 0)
			/* ignore locale names like "iso_8859-1" */
			continue;

		if (n_elems == list_size) {
			list_size *= 2;
			list = (char **)xrealloc((void *) list,
			    (list_size + 1) * sizeof (char *));
			memset(&list[n_elems + 1], 0,
			    sizeof (char *) * (list_size - n_elems + 1));
		}

		*(strchr(locale, '\n')) = '\0';	/* remove the trailing \n */
		list[n_elems++] = xstrdup(locale);
	}

	if (n_elems == 0) {
		xfree(list);
		return (NULL);
	}

	list[n_elems] = NULL;
	(void) pclose(locale_out);

	qsort(list, n_elems - 1, sizeof (char *), locale_cmp);
	return (list);
}

char *
g11n_getlangs()
{
	char *locale;

	if (getenv("SSH_LANGS"))
		return (xstrdup(getenv("SSH_LANGS")));

	locale = g11n_getlocale();

	if (!locale || !*locale)
		return (xstrdup("i-default"));

	return (g11n_locale2langtag(locale));
}

char *
g11n_locales2langs(char **locale_set)
{
	char **p, **r, **q;
	char *langtag, *langs;
	int locales, skip;

	for (locales = 0, p = locale_set; p && *p; p++)
		locales++;

	r = (char **)xmalloc((locales + 1) * sizeof (char *));
	memset(r, 0, (locales + 1) * sizeof (char *));

	for (p = locale_set; p && *p && ((p - locale_set) <= locales); p++) {
		skip = 0;
		if ((langtag = g11n_locale2langtag(*p)) == NULL)
			continue;
		for (q = r; (q - r) < locales; q++) {
			if (!*q)
				break;
			if (*q && strcmp(*q, langtag) == 0)
				skip = 1;
		}
		if (!skip)
			*(q++) = langtag;
		else
			xfree(langtag);
		*q = NULL;
	}

	langs = xjoin(r, ',');
	g11n_freelist(r);

	return (langs);
}

static int
sortcmp(const void *d1, const void *d2)
{
	char *s1 = *(char **)d1;
	char *s2 = *(char **)d2;

	return (strcmp(s1, s2));
}

int
g11n_langtag_match(char *langtag1, char *langtag2)
{
	int len1, len2;
	char c1, c2;

	len1 = (strchr(langtag1, '-')) ?
	    (strchr(langtag1, '-') - langtag1)
	    : strlen(langtag1);

	len2 = (strchr(langtag2, '-')) ?
	    (strchr(langtag2, '-') - langtag2)
	    : strlen(langtag2);

	/* no match */
	if (len1 != len2 || strncmp(langtag1, langtag2, len1) != 0)
		return (0);

	c1 = *(langtag1 + len1);
	c2 = *(langtag2 + len2);

	/* no country sub-tags - exact match */
	if (c1 == '\0' && c2 == '\0')
		return (2);

	/* one langtag has a country sub-tag, the other doesn't */
	if (c1 == '\0' || c2 == '\0')
		return (1);

	/* can't happen - both langtags have a country sub-tag */
	if (c1 != '-' || c2 != '-')
		return (1);

	/* compare country subtags */
	langtag1 = langtag1 + len1 + 1;
	langtag2 = langtag2 + len2 + 1;

	len1 = (strchr(langtag1, '-')) ?
	    (strchr(langtag1, '-') - langtag1) : strlen(langtag1);

	len2 = (strchr(langtag2, '-')) ?
	    (strchr(langtag2, '-') - langtag2) : strlen(langtag2);

	if (len1 != len2 || strncmp(langtag1, langtag2, len1) != 0)
		return (1);

	/* country tags matched - exact match */
	return (2);
}

char *
g11n_langtag_set_intersect(char *set1, char *set2)
{
	char **list1, **list2, **list3, **p, **q, **r;
	char *set3, *lang_subtag;
	uint_t n1, n2, n3;
	uint_t do_append;

	list1 = xsplit(set1, ',');
	list2 = xsplit(set2, ',');

	for (n1 = 0, p = list1; p && *p; p++, n1++)
		;
	for (n2 = 0, p = list2; p && *p; p++, n2++)
		;

	list3 = (char **) xmalloc(sizeof (char *) * (n1 + n2 + 1));
	*list3 = NULL;

	/*
	 * we must not sort the user langtags - sorting or not the server's
	 * should not affect the outcome
	 */
	qsort(list2, n2, sizeof (char *), sortcmp);

	for (n3 = 0, p = list1; p && *p; p++) {
		do_append = 0;
		for (q = list2; q && *q; q++) {
			if (g11n_langtag_match(*p, *q) != 2) continue;
			/* append element */
			for (r = list3; (r - list3) <= (n1 + n2); r++) {
				do_append = 1;
				if (!*r)
					break;
				if (strcmp(*p, *r) == 0) {
					do_append = 0;
					break;
				}
			}
			if (do_append && n3 <= (n1 + n2)) {
				list3[n3++] = xstrdup(*p);
				list3[n3] = NULL;
			}
		}
	}

	for (p = list1; p && *p; p++) {
		do_append = 0;
		for (q = list2; q && *q; q++) {
			if (g11n_langtag_match(*p, *q) != 1)
				continue;

			/* append element */
			lang_subtag = xstrdup(*p);
			if (strchr(lang_subtag, '-'))
				*(strchr(lang_subtag, '-')) = '\0';
			for (r = list3; (r - list3) <= (n1 + n2); r++) {
				do_append = 1;
				if (!*r)
					break;
				if (strcmp(lang_subtag, *r) == 0) {
					do_append = 0;
					break;
				}
			}
			if (do_append && n3 <= (n1 + n2)) {
				list3[n3++] = lang_subtag;
				list3[n3] = NULL;
			} else
				xfree(lang_subtag);
		}
	}

	set3 = xjoin(list3, ',');
	xfree_split_list(list1);
	xfree_split_list(list2);
	xfree_split_list(list3);

	return (set3);
}

char *
g11n_clnt_langtag_negotiate(char *clnt_langtags, char *srvr_langtags)
{
	char *list, *result;
	char **xlist;

	/* g11n_langtag_set_intersect uses xmalloc - should not return NULL */
	list = g11n_langtag_set_intersect(clnt_langtags, srvr_langtags);

	if (!list)
		return (NULL);

	xlist = xsplit(list, ',');

	xfree(list);

	if (!xlist || !*xlist)
		return (NULL);

	result = xstrdup(*xlist);
	xfree_split_list(xlist);

	return (result);
}

/*
 * Compare locales, preferring UTF-8 codesets to others, otherwise doing
 * a stright strcmp()
 */
static int
locale_cmp(const void *d1, const void *d2)
{
	char *dot_ptr;
	char *s1 = *(char **)d1;
	char *s2 = *(char **)d2;
	int s1_is_utf8 = 0;
	int s2_is_utf8 = 0;

	/* check if s1 is a UTF-8 locale */
	if (((dot_ptr = strchr((char *)s1, '.')) != NULL) &&
	    (*dot_ptr != '\0') && (strncmp(dot_ptr + 1, "UTF-8", 5) == 0) &&
	    (*(dot_ptr + 6) == '\0' || *(dot_ptr + 6) == '@')) {
		s1_is_utf8++;
	}

	/* check if s2 is a UTF-8 locale */
	if (((dot_ptr = strchr((char *)s2, '.')) != NULL) &&
	    (*dot_ptr != '\0') && (strncmp(dot_ptr + 1, "UTF-8", 5) == 0) &&
	    (*(dot_ptr + 6) == '\0' || *(dot_ptr + 6) == '@')) {
		s2_is_utf8++;
	}

	/* prefer UTF-8 locales */
	if (s1_is_utf8 && !s2_is_utf8)
		return (-1);

	if (s2_is_utf8 && !s1_is_utf8)
		return (1);

	/* prefer any locale over the default locales */
	if (strcmp(s1, "C") == 0 || strcmp(s1, "POSIX") == 0 ||
	    strcmp(s1, "common") == 0) {
		if (strcmp(s2, "C") != 0 && strcmp(s2, "POSIX") != 0 &&
		    strcmp(s2, "common") != 0)
			return (1);
	}

	if (strcmp(s2, "C") == 0 || strcmp(s2, "POSIX") == 0 ||
	    strcmp(s2, "common") == 0) {
		if (strcmp(s1, "C") != 0 &&
		    strcmp(s1, "POSIX") != 0 &&
		    strcmp(s1, "common") != 0)
			return (-1);
	}

	return (strcmp(s1, s2));
}


char **
g11n_langtag_set_locale_set_intersect(char *langtag_set, char **locale_set)
{
	char **langtag_list, **result, **p, **q, **r;
	char *s;
	uint_t do_append, n_langtags, n_locales, n_results, max_results;

	/* count lang tags and locales */
	for (n_locales = 0, p = locale_set; p && *p; p++)
		n_locales++;

	n_langtags = ((s = langtag_set) != NULL && *s && *s != ',') ? 1 : 0;
	/* count the number of langtags */
	for (; s = strchr(s, ','); s++, n_langtags++)
		;

	qsort(locale_set, n_locales, sizeof (char *), locale_cmp);

	langtag_list = xsplit(langtag_set, ',');
	for (n_langtags = 0, p = langtag_list; p && *p; p++, n_langtags++)
		;

	max_results = MIN(n_locales, n_langtags) * 2;
	result = (char **) xmalloc(sizeof (char *) * (max_results + 1));
	*result = NULL;
	n_results = 0;

	/* more specific matches first */
	for (p = langtag_list; p && *p; p++) {
		do_append = 0;
		for (q = locale_set; q && *q; q++) {
			if (g11n_langtag_matches_locale(*p, *q) == 2) {
				do_append = 1;
				for (r = result; (r - result) <=
				    MIN(n_locales, n_langtags); r++) {
					if (!*r)
						break;
					if (strcmp(*q, *r) == 0) {
						do_append = 0;
						break;
					}
				}
				if (do_append && n_results < max_results) {
					result[n_results++] = xstrdup(*q);
					result[n_results] = NULL;
				}
				break;
			}
		}
	}

	for (p = langtag_list; p && *p; p++) {
		do_append = 0;
		for (q = locale_set; q && *q; q++) {
			if (g11n_langtag_matches_locale(*p, *q) == 1) {
				do_append = 1;
				for (r = result; (r - result) <=
				    MIN(n_locales, n_langtags); r++) {
					if (!*r)
						break;
					if (strcmp(*q, *r) == 0) {
						do_append = 0;
						break;
					}
				}
				if (do_append && n_results < max_results) {
					result[n_results++] = xstrdup(*q);
					result[n_results] = NULL;
				}
				break;
			}
		}
	}

	xfree_split_list(langtag_list);

	return (result);
}

char *
g11n_srvr_locale_negotiate(char *clnt_langtags, char **srvr_locales)
{
	char **results, **locales, *result = NULL;

	if (srvr_locales == NULL)
		locales = g11n_getlocales();
	else
		locales = srvr_locales;

	if ((results = g11n_langtag_set_locale_set_intersect(clnt_langtags,
	    locales)) == NULL)
		goto err;

	if (*results != NULL)
		result = xstrdup(*results);

	xfree_split_list(results);

err:
	if (locales != srvr_locales)
		g11n_freelist(locales);
	return (result);
}


/*
 * Functions for validating ASCII and UTF-8 strings
 *
 * The error_str parameter is an optional pointer to a char variable
 * where to store a string suitable for use with error() or fatal() or
 * friends.
 *
 * The return value is 0 if success, EILSEQ or EINVAL.
 *
 */
uint_t
g11n_validate_ascii(const char *str, uint_t len, uchar_t **error_str)
{
	uchar_t *p;

	for (p = (uchar_t *)str; p && *p && (!(*p & 0x80)); p++)
		;

	if (len && ((p - (uchar_t *)str) != len))
		return (EILSEQ);

	return (0);
}

uint_t
g11n_validate_utf8(const uchar_t *str, uint_t len, uchar_t **error_str)
{
	uchar_t *p;
	uint_t c, l;

	if (len == 0)
		len = strlen((const char *)str);

	for (p = (uchar_t *)str; p && (p - str < len) && *p; ) {
		/* 8-bit chars begin a UTF-8 sequence */
		if (*p & 0x80) {
			/* get sequence length and sanity check first byte */
			if (*p < 0xc0)
				return (EILSEQ);
			else if (*p < 0xe0)
				l = 2;
			else if (*p < 0xf0)
				l = 3;
			else if (*p < 0xf8)
				l = 4;
			else if (*p < 0xfc)
				l = 5;
			else if (*p < 0xfe)
				l = 6;
			else
				return (EILSEQ);

			if ((p + l - str) >= len)
				return (EILSEQ);

			/* overlong detection - build codepoint */
			c = *p & 0x3f;
			/* shift c bits from first byte */
			c = c << (6 * (l - 1));

			if (l > 1) {
				if (*(p + 1) && ((*(p + 1) & 0xc0) == 0x80))
					c = c | ((*(p + 1) & 0x3f) <<
					    (6 * (l - 2)));
				else
					return (EILSEQ);

				if (c < 0x80)
					return (EILSEQ);
			}

			if (l > 2) {
				if (*(p + 2) && ((*(p + 2) & 0xc0) == 0x80))
					c = c | ((*(p + 2) & 0x3f) <<
					    (6 * (l - 3)));
				else
					return (EILSEQ);

				if (c < 0x800)
					return (EILSEQ);
			}

			if (l > 3) {
				if (*(p + 3) && ((*(p + 3) & 0xc0) == 0x80))
					c = c | ((*(p + 3) & 0x3f) <<
					    (6 * (l - 4)));
				else
					return (EILSEQ);

				if (c < 0x10000)
					return (EILSEQ);
			}

			if (l > 4) {
				if (*(p + 4) && ((*(p + 4) & 0xc0) == 0x80))
					c = c | ((*(p + 4) & 0x3f) <<
					    (6 * (l - 5)));
				else
					return (EILSEQ);

				if (c < 0x200000)
					return (EILSEQ);
			}

			if (l > 5) {
				if (*(p + 5) && ((*(p + 5) & 0xc0) == 0x80))
					c = c | (*(p + 5) & 0x3f);
				else
					return (EILSEQ);

				if (c < 0x4000000)
					return (EILSEQ);
			}

			/*
			 * check for UTF-16 surrogates ifs other illegal
			 * UTF-8 * points
			 */
			if (((c <= 0xdfff) && (c >= 0xd800)) ||
			    (c == 0xfffe) || (c == 0xffff))
				return (EILSEQ);
			p += l;
		}
		/* 7-bit chars are fine */
		else
			p++;
	}
	return (0);
}

/*
 * Functions for converting to ASCII or UTF-8 from the local codeset
 * Functions for converting from ASCII or UTF-8 to the local codeset
 *
 * The error_str parameter is an optional pointer to a char variable
 * where to store a string suitable for use with error() or fatal() or
 * friends.
 *
 * The err parameter is an optional pointer to an integer where 0
 * (success) or EILSEQ or EINVAL will be stored (failure).
 *
 * These functions return NULL if the conversion fails.
 *
 */
uchar_t *
g11n_convert_from_ascii(const char *str, int *err_ptr, uchar_t **error_str)
{
	static uint_t initialized = 0;
	static uint_t do_convert = 0;
	iconv_t cd;
	int err;

	if (!initialized) {
		/*
		 * iconv_open() fails if the to/from codesets are the
		 * same, and there are aliases of codesets to boot...
		 */
		if (strcmp("646", nl_langinfo(CODESET)) == 0 ||
		    strcmp("ASCII",  nl_langinfo(CODESET)) == 0 ||
		    strcmp("US-ASCII",  nl_langinfo(CODESET)) == 0) {
			initialized = 1;
			do_convert = 0;
		} else {
			cd = iconv_open(nl_langinfo(CODESET), "646");
			if (cd == (iconv_t)-1) {
				if (err_ptr)
					*err_ptr = errno;
				if (error_str)
					*error_str = (uchar_t *)"Cannot "
					    "convert ASCII strings to the local"
					    " codeset";
			}
			initialized = 1;
			do_convert = 1;
		}
	}

	if (!do_convert) {
		if ((err = g11n_validate_ascii(str, 0, error_str))) {
			if (err_ptr)
				*err_ptr = err;
			return (NULL);
		} else
			return ((uchar_t *)xstrdup(str));
	}

	return (do_iconv(cd, NULL, str, 0, NULL, err_ptr, error_str));
}

uchar_t *
g11n_convert_from_utf8(const uchar_t *str, int *err_ptr, uchar_t **error_str)
{
	static uint_t initialized = 0;
	static uint_t do_convert = 0;
	iconv_t cd;
	int err;

	if (!initialized) {
		/*
		 * iconv_open() fails if the to/from codesets are the
		 * same, and there are aliases of codesets to boot...
		 */
		if (strcmp("UTF-8", nl_langinfo(CODESET)) == 0 ||
		    strcmp("UTF8",  nl_langinfo(CODESET)) == 0) {
			initialized = 1;
			do_convert = 0;
		} else {
			cd = iconv_open(nl_langinfo(CODESET), "UTF-8");
			if (cd == (iconv_t)-1) {
				if (err_ptr)
					*err_ptr = errno;
				if (error_str)
					*error_str = (uchar_t *)"Cannot "
					    "convert UTF-8 strings to the "
					    "local codeset";
			}
			initialized = 1;
			do_convert = 1;
		}
	}

	if (!do_convert) {
		if ((err = g11n_validate_utf8(str, 0, error_str))) {
			if (err_ptr)
				*err_ptr = err;
			return (NULL);
		} else
			return ((uchar_t *)xstrdup((char *)str));
	}

	return (do_iconv(cd, NULL, str, 0, NULL, err_ptr, error_str));
}

char *
g11n_convert_to_ascii(const uchar_t *str, int *err_ptr, uchar_t **error_str)
{
	static uint_t initialized = 0;
	static uint_t do_convert = 0;
	iconv_t cd;

	if (!initialized) {
		/*
		 * iconv_open() fails if the to/from codesets are the
		 * same, and there are aliases of codesets to boot...
		 */
		if (strcmp("646", nl_langinfo(CODESET)) == 0 ||
		    strcmp("ASCII",  nl_langinfo(CODESET)) == 0 ||
		    strcmp("US-ASCII",  nl_langinfo(CODESET)) == 0) {
			initialized = 1;
			do_convert = 0;
		} else {
			cd = iconv_open("646", nl_langinfo(CODESET));
			if (cd == (iconv_t)-1) {
				if (err_ptr)
					*err_ptr = errno;
				if (error_str)
					*error_str = (uchar_t *)"Cannot "
					    "convert UTF-8 strings to the "
					    "local codeset";
			}
			initialized = 1;
			do_convert = 1;
		}
	}

	if (!do_convert)
		return (xstrdup((char *)str));

	return ((char *)do_iconv(cd, NULL, str, 0, NULL, err_ptr, error_str));
}

uchar_t *
g11n_convert_to_utf8(const uchar_t *str, int *err_ptr, uchar_t **error_str)
{
	static uint_t initialized = 0;
	static uint_t do_convert = 0;
	iconv_t cd;

	if (!initialized) {
		/*
		 * iconv_open() fails if the to/from codesets are the
		 * same, and there are aliases of codesets to boot...
		 */
		if (strcmp("UTF-8", nl_langinfo(CODESET)) == 0 ||
		    strcmp("UTF8",  nl_langinfo(CODESET)) == 0) {
			initialized = 1;
			do_convert = 0;
		} else {
			cd = iconv_open("UTF-8", nl_langinfo(CODESET));
			if (cd == (iconv_t)-1) {
				if (err_ptr)
					*err_ptr = errno;
				if (error_str)
					*error_str = (uchar_t *)"Cannot "
					    "convert UTF-8 strings to the "
					    "local codeset";
			}
			initialized = 1;
			do_convert = 1;
		}
	}

	if (!do_convert)
		return ((uchar_t *)xstrdup((char *)str));

	return (do_iconv(cd, NULL, str, 0, NULL, err_ptr, error_str));
}


/*
 * Wrapper around iconv()
 *
 * The caller is responsible for freeing the result and for handling
 * (errno && errno != E2BIG) (i.e., EILSEQ, EINVAL, EBADF).
 */
static uchar_t *
do_iconv(iconv_t cd, uint_t *mul_ptr, const void *buf, uint_t len,
    uint_t *outlen, int *err, uchar_t **err_str)
{
	size_t inbytesleft, outbytesleft, converted_size;
	char *outbuf;
	uchar_t *converted;
	const char *inbuf;
	uint_t mul = 0;

	if (!buf || !(*(char *)buf))
		return (NULL);

	if (len == 0)
		len = strlen(buf);

	/* reset conversion descriptor */
	/* XXX Do we need initial shift sequences for UTF-8??? */
	(void) iconv(cd, NULL, &inbytesleft, &outbuf, &outbytesleft);
	inbuf = (const char *) buf;

	if (mul_ptr)
		mul = *mul_ptr;

	converted_size = (len << mul);
	outbuf = (char *)xmalloc(converted_size + 1); /* for null */
	converted = (uchar_t *)outbuf;
	outbytesleft = len;

	do {
		if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) ==
		    (size_t)-1) {
			if (errno == E2BIG) {
				/* UTF-8 codepoints are at most 8 bytes long */
				if (mul > 2) {
					if (err_str)
						*err_str = (uchar_t *)
						    "Conversion to UTF-8 failed"
						    " due to preposterous space"
						    " requirements";
					if (err)
						*err = EILSEQ;
					return (NULL);
				}

				/*
				 * re-alloc output and ensure that the outbuf
				 * and outbytesleft values are adjusted
				 */
				converted = xrealloc(converted,
				    converted_size << 1 + 1);
				outbuf = (char *)converted + converted_size -
				    outbytesleft;
				converted_size = (len << ++(mul));
				outbytesleft = converted_size - outbytesleft;
			} else {
				/*
				 * let the caller deal with iconv() errors,
				 * probably by calling fatal(); xfree() does
				 * not set errno
				 */
				if (err)
					*err = errno;
				xfree(converted);
				return (NULL);
			}
		}
	} while (inbytesleft);

	*outbuf = '\0'; /* ensure null-termination */
	if (outlen)
		*outlen = converted_size - outbytesleft;
	if (mul_ptr)
		*mul_ptr = mul;

	return (converted);
}

/*
 * Free all strings in the list and then free the list itself. We know that the
 * list ends with a NULL pointer.
 */
void
g11n_freelist(char **list)
{
	int i = 0;

	while (list[i] != NULL) {
		xfree(list[i]);
		i++;
	}

	xfree(list);
}
