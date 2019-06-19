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
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * catopen.c
 *
 */

#pragma weak _catopen = catopen
#pragma weak _catclose = catclose

#include "lint.h"
#include "libc.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <nl_types.h>
#include <locale.h>
#include <limits.h>
#include <errno.h>
#include "../i18n/_loc_path.h"
#include "nlspath_checks.h"

#define	SAFE_F		1
#define	UNSAFE_F	0

static char *
replace_nls_option(char *, char *, char *, char *, char *, char *, char *);
static nl_catd file_open(const char *, int);
static nl_catd process_nls_path(char *, int);

nl_catd
catopen(const char *name, int oflag)
{
	nl_catd p;

	if (!name) {				/* Null pointer */
		errno = EFAULT;
		return ((nl_catd)-1);
	} else if (!*name) {		/* Empty string */
		errno = ENOENT;
		return ((nl_catd)-1);
	} else if (strchr(name, '/') != NULL) {
		/* If name contains '/', then it is complete file name */
		p = file_open(name, SAFE_F);
	} else {				/* Normal case */
		p = process_nls_path((char *)name, oflag);
	}

	if (p == NULL) {  /* Opening catalog file failed */
		return ((nl_catd)-1);
	} else {
		return (p);
	}
}


/*
 * This routine will process NLSPATH environment variable.
 * It will return catd id whenever it finds valid catalog.
 */
static nl_catd
process_nls_path(char *name, int oflag)
{
	char	*s, *s1, *s2, *t;
	char	*nlspath, *lang, *territory, *codeset, *locale;
	char	pathname[PATH_MAX + 1];
	nl_catd	p;

	/*
	 * locale=language_territory.codeset
	 * XPG4 uses LC_MESSAGES.
	 * XPG3 uses LANG.
	 * From the following two lines, choose one depending on XPG3 or 4.
	 *
	 * Chose XPG4. If oflag == NL_CAT_LOCALE, use LC_MESSAGES.
	 */
	if (oflag == NL_CAT_LOCALE) {
		locale_t loc = uselocale(NULL);
		locale = current_locale(loc, LC_MESSAGES);
	} else {
		locale = getenv("LANG");
	}

	nlspath = getenv("NLSPATH");
	lang = NULL;
	if (nlspath) {
		territory = NULL;
		codeset = NULL;
		/*
		 * extract lang, territory and codeset from locale name
		 */
		if (locale) {
			lang = s = libc_strdup(locale);
			if (!lang) {
				/* strdup failed */
				return (NULL);
			}
			s1 = s2 = NULL;
			while (s && *s) {
				if (*s == '_') {
					s1 = s;
					*s1++ = '\0';
				} else if (*s == '.') {
					s2 = s;
					*s2++ = '\0';
				}
				s++;
			}
			territory = s1;
			codeset   = s2;
		} /* if (locale) */

		/*
		 * March through NLSPATH until finds valid cat file
		 */
		s = nlspath;
		while (*s) {
			if (*s == ':') {
				/* unqualified pathname is unsafe */
				p = file_open(name, UNSAFE_F);
				if (p != NULL) {
					if (lang)
						libc_free(lang);
					return (p);
				}
				++s;
				continue;
			}

			/* replace Substitution field */
			s = replace_nls_option(s, name, pathname, locale,
			    lang, territory, codeset);

			p = file_open(pathname, UNSAFE_F);
			if (p != NULL) {
				if (lang)
					libc_free(lang);
				return (p);
			}
			if (*s)
				++s;
		} /* while */
	} /* if (nlspath) */

	/* lang is not used any more, free it */
	if (lang)
		libc_free(lang);

	/*
	 * Implementation dependent default location of XPG3.
	 * We use /usr/lib/locale/<locale>/LC_MESSAGES/%N.
	 * If C locale, do not translate message.
	 */
	if (locale == NULL) {
		return (NULL);
	} else if (locale[0] == 'C' && locale[1] == '\0') {
		p = libc_malloc(sizeof (struct _nl_catd_struct));
		if (p == NULL) {
			/* malloc failed */
			return (NULL);
		}
		p->__content = NULL;
		p->__size = 0;
		p->__trust = 1;
		return (p);
	}

	s = _DFLT_LOC_PATH;
	t = pathname;
	while (*t++ = *s++)
		continue;
	t--;
	s = locale;
	while (*s && t < pathname + PATH_MAX)
		*t++ = *s++;
	s = "/LC_MESSAGES/";
	while (*s && t < pathname + PATH_MAX)
		*t++ = *s++;
	s = name;
	while (*s && t < pathname + PATH_MAX)
		*t++ = *s++;
	*t = '\0';
	return (file_open(pathname, SAFE_F));
}


/*
 * This routine will replace substitution parameters in NLSPATH
 * with appropiate values. Returns expanded pathname.
 */
static char *
replace_nls_option(char *s, char *name, char *pathname, char *locale,
	char *lang, char *territory, char *codeset)
{
	char	*t, *u;

	t = pathname;
	while (*s && *s != ':') {
		if (t < pathname + PATH_MAX) {
			/*
			 * %% is considered a single % character (XPG).
			 * %L : LC_MESSAGES (XPG4) LANG(XPG3)
			 * %l : The language element from the current locale.
			 *	(XPG3, XPG4)
			 */
			if (*s != '%')
				*t++ = *s;
			else if (*++s == 'N') {
				u = name;
				while (*u && t < pathname + PATH_MAX)
					*t++ = *u++;
			} else if (*s == 'L') {
				if (locale) {
					u = locale;
					while (*u && t < pathname + PATH_MAX)
						*t++ = *u++;
				}
			} else if (*s == 'l') {
				if (lang) {
					u = lang;
					while (*u && *u != '_' &&
					    t < pathname + PATH_MAX)
						*t++ = *u++;
				}
			} else if (*s == 't') {
				if (territory) {
					u = territory;
					while (*u && *u != '.' &&
					    t < pathname + PATH_MAX)
						*t++ = *u++;
				}
			} else if (*s == 'c') {
				if (codeset) {
					u = codeset;
					while (*u && t < pathname + PATH_MAX)
						*t++ = *u++;
				}
			} else {
				if (t < pathname + PATH_MAX)
					*t++ = *s;
			}
		}
		++s;
	}
	*t = '\0';
	return (s);
}

/*
 * This routine will open file, mmap it, and return catd id.
 */
static nl_catd
file_open(const char *name, int safe)
{
	int		fd;
	struct stat64	statbuf;
	void		*addr;
	struct _cat_hdr	*tmp;
	nl_catd		tmp_catd;
	int		trust;

	fd = nls_safe_open(name, &statbuf, &trust, safe);

	if (fd == -1) {
		return (NULL);
	}

	addr = mmap(0, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	(void) close(fd);

	if (addr == MAP_FAILED) {
		return (NULL);
	}

	/* check MAGIC number of catalogue file */
	tmp = (struct _cat_hdr *)addr;
	if (tmp->__hdr_magic != _CAT_MAGIC) {
		(void) munmap(addr, (size_t)statbuf.st_size);
		return (NULL);
	}

	tmp_catd = libc_malloc(sizeof (struct _nl_catd_struct));
	if (tmp_catd == NULL) {
		/* malloc failed */
		(void) munmap(addr, statbuf.st_size);
		return (NULL);
	}
	tmp_catd->__content = addr;
	tmp_catd->__size = (int)statbuf.st_size;
	tmp_catd->__trust = trust;

	return (tmp_catd);
}

int
catclose(nl_catd catd)
{
	if (catd &&
	    catd != (nl_catd)-1) {
		if (catd->__content) {
			(void) munmap(catd->__content, catd->__size);
			catd->__content = NULL;
		}
		catd->__size = 0;
		catd->__trust = 0;
		libc_free(catd);
	}
	return (0);
}
