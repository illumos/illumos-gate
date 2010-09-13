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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <locale.h>
#include <langinfo.h>
#include <iconv.h>
#include <ctype.h>
#include <wctype.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "includes.h"
#include "xmalloc.h"
#include "xlist.h"
#include "compat.h"
#include "log.h"

#ifdef MIN
#undef MIN
#endif /* MIN */

#define	MIN(x, y)	((x) < (y) ? (x) : (y))

#define	LOCALE_PATH	"/usr/bin/locale"

/* two-char country code, '-' and two-char region code */
#define	LANGTAG_MAX	5

static int locale_cmp(const void *d1, const void *d2);
static char *g11n_locale2langtag(char *locale);

static char *do_iconv(iconv_t cd, const char *s, uint_t *lenp, char **err_str);

/*
 * native_codeset records the codeset of the default system locale.
 * It is used to convert the contents of file (eg /etc/issue) which is
 * supposed to be in the codeset of default system locale.
 */
static char *native_codeset;

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

	if (native_codeset == NULL) {
		/* set default locale, and record current codeset */
		(void) setlocale(LC_ALL, "");
		curr = nl_langinfo(CODESET);
		native_codeset = xstrdup(curr);
	}

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

	(void) pclose(locale_out);

	if (n_elems == 0) {
		xfree(list);
		return (NULL);
	}

	list[n_elems] = NULL;

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

	if (locale_set == NULL)
		return (NULL);

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
	if (locales != NULL && locales != srvr_locales)
		g11n_freelist(locales);
	return (result);
}

/*
 * Functions for converting to UTF-8 from the local codeset and
 * converting from UTF-8 to the local codeset.
 *
 * The error_str parameter is an pointer to a char variable where to
 * store a string suitable for use with error() or fatal() or friends.
 * It is also used for an error indicator when NULL is returned.
 *
 * If conversion isn't necessary, *error_str is set to NULL, and
 * NULL is returned.
 * If conversion error occured, *error_str points to an error message,
 * and NULL is returned.
 */
char *
g11n_convert_from_utf8(const char *str, uint_t *lenp, char **error_str)
{
	static char *last_codeset;
	static iconv_t cd = (iconv_t)-1;
	char	*codeset;

	*error_str = NULL;

	codeset = nl_langinfo(CODESET);

	if (strcmp(codeset, "UTF-8") == 0)
		return (NULL);

	if (last_codeset == NULL || strcmp(codeset, last_codeset) != 0) {
		if (last_codeset != NULL) {
			xfree(last_codeset);
			last_codeset = NULL;
		}
		if (cd != (iconv_t)-1)
			(void) iconv_close(cd);

		if ((cd = iconv_open(codeset, "UTF-8")) == (iconv_t)-1) {
			*error_str = gettext("Cannot convert UTF-8 "
			    "strings to the local codeset");
			return (NULL);
		}
		last_codeset = xstrdup(codeset);
	}
	return (do_iconv(cd, str, lenp, error_str));
}

char *
g11n_convert_to_utf8(const char *str, uint_t *lenp,
    int native, char **error_str)
{
	static char *last_codeset;
	static iconv_t cd = (iconv_t)-1;
	char	*codeset;

	*error_str = NULL;

	if (native)
		codeset = native_codeset;
	else
		codeset = nl_langinfo(CODESET);

	if (strcmp(codeset, "UTF-8") == 0)
		return (NULL);

	if (last_codeset == NULL || strcmp(codeset, last_codeset) != 0) {
		if (last_codeset != NULL) {
			xfree(last_codeset);
			last_codeset = NULL;
		}
		if (cd != (iconv_t)-1)
			(void) iconv_close(cd);

		if ((cd = iconv_open("UTF-8", codeset)) == (iconv_t)-1) {
			*error_str = gettext("Cannot convert the "
			    "local codeset strings to UTF-8");
			return (NULL);
		}
		last_codeset = xstrdup(codeset);
	}
	return (do_iconv(cd, str, lenp, error_str));
}

/*
 * Wrapper around iconv()
 *
 * The caller is responsible for freeing the result. NULL is returned when
 * (errno && errno != E2BIG) (i.e., EILSEQ, EINVAL, EBADF).
 * The caller must ensure that the input string isn't NULL pointer.
 */
static char *
do_iconv(iconv_t cd, const char *str, uint_t *lenp, char **err_str)
{
	int	ilen, olen;
	size_t	ileft, oleft;
	char	*ostr, *optr;
	const char *istr;

	ilen = *lenp;
	olen = ilen + 1;

	ostr = NULL;
	for (;;) {
		olen *= 2;
		oleft = olen;
		ostr = optr = xrealloc(ostr, olen);
		istr = (const char *)str;
		if ((ileft = ilen) == 0)
			break;

		if (iconv(cd, &istr, &ileft, &optr, &oleft) != (size_t)-1) {
			/* success: generate reset sequence */
			if (iconv(cd, NULL, NULL,
			    &optr, &oleft) == (size_t)-1 && errno == E2BIG) {
				continue;
			}
			break;
		}
		/* failed */
		if (errno != E2BIG) {
			oleft = olen;
			(void) iconv(cd, NULL, NULL, &ostr, &oleft);
			xfree(ostr);
			*err_str = gettext("Codeset conversion failed");
			return (NULL);
		}
	}
	olen = optr - ostr;
	optr = xmalloc(olen + 1);
	(void) memcpy(optr, ostr, olen);
	xfree(ostr);

	optr[olen] = '\0';
	*lenp = olen;

	return (optr);
}

/*
 * A filter for output string. Control and unprintable characters
 * are converted into visible form (eg "\ooo").
 */
char *
g11n_filter_string(char *s)
{
	int	mb_cur_max = MB_CUR_MAX;
	int	mblen, len;
	char	*os = s;
	wchar_t	wc;
	char	*obuf, *op;

	/* all character may be converted into the form of \ooo */
	obuf = op = xmalloc(strlen(s) * 4 + 1);

	while (*s != '\0') {
		mblen = mbtowc(&wc, s, mb_cur_max);
		if (mblen <= 0) {
			mblen = 1;
			wc = (unsigned char)*s;
		}
		if (!iswprint(wc) &&
		    wc != L'\n' && wc != L'\r' && wc != L'\t') {
			/*
			 * control chars which need to be replaced
			 * with safe character sequence.
			 */
			while (mblen != 0) {
				op += sprintf(op, "\\%03o",
				    (unsigned char)*s++);
				mblen--;
			}
		} else {
			while (mblen != 0) {
				*op++ = *s++;
				mblen--;
			}
		}
	}
	*op = '\0';
	len = op - obuf + 1;
	op = xrealloc(os, len);
	(void) memcpy(op, obuf, len);
	xfree(obuf);
	return (op);
}

/*
 * Once we negotiated with a langtag, server need to map it to a system
 * locale. That is done based on the locale supported on the server side.
 * We know (with the locale supported on Solaris) how the langtag is
 * mapped to. However, from the client point of view, there is no way to
 * know exactly what locale(encoding) will be used.
 *
 * With the bug fix of SSH_BUG_STRING_ENCODING, it is guaranteed that the
 * UTF-8 characters always come over the wire, so it is no longer the problem
 * as long as both side has the bug fix. However if the server side doesn't
 * have the fix, client can't safely perform the code conversion since the
 * incoming character encoding is unknown.
 *
 * To alleviate this situation, we take an empirical approach to find
 * encoding from langtag.
 *
 * If langtag has a subtag, we can directly map the langtag to UTF-8 locale
 * (eg en-US can be mapped to en_US.UTF-8) with a few exceptions.
 * Certain xx_YY locales don't support UTF-8 encoding (probably due to lack
 * of L10N support ..). Those are:
 *
 * 	no_NO, no_NY, sr_SP, sr_YU
 *
 * They all use ISO8859-X encoding.
 *
 * For those "xx" langtags, some of them can be mapped to "xx.UTF-8",
 * but others cannot. So we need to use the "xx" as the locale name.
 * Those locales are:
 *
 * ar, ca, cs, da, et, fi, he, hu, ja, lt, lv, nl, no, pt, sh, th, tr
 *
 * Their encoding vary. They could be ISO8859-X or EUC or something else.
 * So we don't perform code conversion for these langtags.
 */
static const char *non_utf8_langtag[] = {
	"no-NO", "no-NY", "sr-SP", "sr-YU",
	"ar", "ca", "cs", "da", "et", "fi", "he", "hu", "ja",
	"lt", "lv", "nl", "no", "pt", "sh", "th", "tr", NULL};

void
g11n_test_langtag(const char *lang, int server)
{
	const char	**lp;

	if (datafellows & SSH_BUG_LOCALES_NOT_LANGTAGS) {
		/*
		 * We negotiated with real locale name (not lang tag).
		 * We shouldn't expect UTF-8, thus shouldn't do code
		 * conversion.
		 */
		datafellows |= SSH_BUG_STRING_ENCODING;
		return;
	}

	if (datafellows & SSH_BUG_STRING_ENCODING) {
		if (server) {
			/*
			 * Whatever bug exists in the client side, server
			 * side has nothing to do, since server has no way
			 * to know what actual encoding is used on the client
			 * side. For example, even if we negotiated with
			 * en_US, client locale could be en_US.ISO8859-X or
			 * en_US.UTF-8.
			 */
			return;
		}
		/*
		 * We are on the client side. We'll check with known
		 * locales to see if non-UTF8 characters could come in.
		 */
		for (lp = non_utf8_langtag; *lp != NULL; lp++) {
			if (strcmp(lang, *lp) == 0)
				break;
		}
		if (*lp == NULL) {
			debug2("Server is expected to use UTF-8 locale");
			datafellows &= ~SSH_BUG_STRING_ENCODING;
		} else {
			/*
			 * Server is expected to use non-UTF8 encoding.
			 */
			debug2("Enforcing no code conversion: %s", lang);
		}
	}
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
