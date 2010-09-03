/*
 * Copyright (c) 1996 - 2002 FreeBSD Project
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <stdio.h>
#include "collate.h"
#include "lmonetary.h"	/* for __monetary_load_locale() */
#include "lnumeric.h"	/* for __numeric_load_locale() */
#include "lmessages.h"	/* for __messages_load_locale() */
#include "setlocale.h"
#include "ldpart.h"
#include "timelocal.h" /* for __time_load_locale() */
#include "../i18n/_loc_path.h"

/*
 * Category names for getenv()  Note that this was modified
 * for Solaris.  See <iso/locale_iso.h>.
 */
#define NUM_CATS	7
static char *categories[7] = {
	"LC_CTYPE",
	"LC_NUMERIC",
	"LC_TIME",
	"LC_COLLATE",
	"LC_MONETARY",
	"LC_MESSAGES",
	"LC_ALL",
};

/*
 * Current locales for each category
 */
static char current_categories[NUM_CATS][ENCODING_LEN + 1] = {
	"C",
	"C",
	"C",
	"C",
	"C",
	"C",
	"C",
};

/*
 * Path to locale storage directory.  See ../i18n/_loc_path.h
 */
char	*_PathLocale = _DFLT_LOC_PATH;

/*
 * The locales we are going to try and load
 */
static char new_categories[NUM_CATS][ENCODING_LEN + 1];
static char saved_categories[NUM_CATS][ENCODING_LEN + 1];
static char current_locale_string[NUM_CATS * (ENCODING_LEN + 1 + 1)];

static char	*currentlocale(void);
static char	*loadlocale(int);
static const char *__get_locale_env(int);

char *
setlocale(int category, const char *locale)
{
	int i, j, saverr;
	const char *env, *r;

	if (category < 0 || category >= NUM_CATS) {
		errno = EINVAL;
		return (NULL);
	}

	if (locale == NULL)
		return (category != LC_ALL ?
		    current_categories[category] : currentlocale());

	/*
	 * Default to the current locale for everything.
	 */
	for (i = 0; i < NUM_CATS; ++i)
		(void) strcpy(new_categories[i], current_categories[i]);

	/*
	 * Now go fill up new_categories from the locale argument
	 */
	if (!*locale) {
		if (category == LC_ALL) {
			for (i = 0; i < NUM_CATS; ++i) {
				if (i == LC_ALL)
					continue;
				env = __get_locale_env(i);
				if (strlen(env) > ENCODING_LEN) {
					errno = EINVAL;
					return (NULL);
				}
				(void) strcpy(new_categories[i], env);
			}
		} else {
			env = __get_locale_env(category);
			if (strlen(env) > ENCODING_LEN) {
				errno = EINVAL;
				return (NULL);
			}
			(void) strcpy(new_categories[category], env);
		}
	} else if (category != LC_ALL) {
		if (strlen(locale) > ENCODING_LEN) {
			errno = EINVAL;
			return (NULL);
		}
		(void) strcpy(new_categories[category], locale);
	} else {
		if ((r = strchr(locale, '/')) == NULL) {
			if (strlen(locale) > ENCODING_LEN) {
				errno = EINVAL;
				return (NULL);
			}
			for (i = 0; i < NUM_CATS; ++i)
				(void) strcpy(new_categories[i], locale);
		} else {
			char	*buf;
			char	*save;

			buf = alloca(strlen(locale) + 1);
			(void) strcpy(buf, locale);

			save = NULL;
			r = strtok_r(buf, "/", &save);
			for (i = 0;  i < NUM_CATS; i++) {
				if (i == LC_ALL)
					continue;
				if (r == NULL) {
					/*
					 * Composite Locale is inadequately
					 * specified!   (Or with empty fields.)
					 * The old code would fill fields
					 * out from the last one, but I think
					 * this is suboptimal.
					 */
					errno = EINVAL;
					return (NULL);
				}
				(void) strlcpy(new_categories[i], r,
				    ENCODING_LEN);
				r = strtok_r(NULL, "/", &save);
			}
			if (r != NULL) {
				/*
				 * Too many components - we had left over
				 * data in the LC_ALL.  It is malformed.
				 */
				errno = EINVAL;
				return (NULL);
			}
		}
	}

	if (category != LC_ALL)
		return (loadlocale(category));

	for (i = 0; i < NUM_CATS; ++i) {
		(void) strcpy(saved_categories[i], current_categories[i]);
		if (i == LC_ALL)
			continue;
		if (loadlocale(i) == NULL) {
			saverr = errno;
			for (j = 0; j < i; j++) {
				(void) strcpy(new_categories[j],
				    saved_categories[j]);
				if (i == LC_ALL)
					continue;
				if (loadlocale(j) == NULL) {
					(void) strcpy(new_categories[j], "C");
					(void) loadlocale(j);
				}
			}
			errno = saverr;
			return (NULL);
		}
	}
	return (currentlocale());
}

static char *
currentlocale(void)
{
	int i;
	int composite = 0;

	/* Look to see if any category is different */
	for (i = 1; i < NUM_CATS; ++i) {
		if (i == LC_ALL)
			continue;
		if (strcmp(current_categories[0], current_categories[i])) {
			composite = 1;
			break;
		}
	}

	if (composite) {
		/*
		 * Note ordering of these follows the numeric order,
		 * if the order is changed, then setlocale() will need
		 * to be changed as well.
		 */
		(void) snprintf(current_locale_string,
		    sizeof (current_locale_string),
		    "%s/%s/%s/%s/%s/%s",
		    current_categories[LC_CTYPE],
		    current_categories[LC_NUMERIC],
		    current_categories[LC_TIME],
		    current_categories[LC_COLLATE],
		    current_categories[LC_MONETARY],
		    current_categories[LC_MESSAGES]);
	} else {
		(void) strlcpy(current_locale_string, current_categories[0],
		    sizeof (current_locale_string));
	}
	return (current_locale_string);
}

static char *
loadlocale(int category)
{
	char *new = new_categories[category];
	char *old = current_categories[category];
	int (*func)(const char *);

	if ((new[0] == '.' &&
	    (new[1] == '\0' || (new[1] == '.' && new[2] == '\0'))) ||
	    strchr(new, '/') != NULL) {
		errno = EINVAL;
		return (NULL);
	}

	switch (category) {
	case LC_CTYPE:
		func = __wrap_setrunelocale;
		break;
	case LC_COLLATE:
		func = __collate_load_tables;
		break;
	case LC_TIME:
		func = __time_load_locale;
		break;
	case LC_NUMERIC:
		func = __numeric_load_locale;
		break;
	case LC_MONETARY:
		func = __monetary_load_locale;
		break;
	case LC_MESSAGES:
		func = __messages_load_locale;
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}

	if (strcmp(new, old) == 0)
		return (old);

	if (func(new) != _LDP_ERROR) {
		(void) strcpy(old, new);
		return (old);
	}

	return (NULL);
}

static const char *
__get_locale_env(int category)
{
	const char *env;

	/* 1. check LC_ALL. */
	env = getenv(categories[LC_ALL]);

	/* 2. check LC_* */
	if (env == NULL || !*env)
		env = getenv(categories[category]);

	/* 3. check LANG */
	if (env == NULL || !*env)
		env = getenv("LANG");

	/* 4. if none is set, fall to "C" */
	if (env == NULL || !*env)
		env = "C";

	return (env);
}
