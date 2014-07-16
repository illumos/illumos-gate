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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * This file implements the 2008 newlocale and friends handling.
 */

#ifndef	_LCONV_C99
#define	_LCONV_C99
#endif

#include "lint.h"
#include <atomic.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "mtlib.h"
#include "tsd.h"
#include "localeimpl.h"
#include "lctype.h"

/*
 * Big Theory of Locales:
 *
 * (It is recommended that readers familiarize themselves with the POSIX
 * 2008 (XPG Issue 7) specifications for locales, first.)
 *
 * Historically, we had a bunch of global variables that stored locale
 * data.  While this worked well, it limited applications to a single locale
 * at a time.  This doesn't work well in certain server applications.
 *
 * Issue 7, X/Open introduced the concept of a locale_t object, along with
 * versions of functions that can take this object as a parameter, along
 * with functions to clone and manipulate these locale objects.  The new
 * functions are named with a _l() suffix.
 *
 * Additionally uselocale() is introduced which can change the locale of
 * of a single thread.  However, setlocale() can still be used to change
 * the global locale.
 *
 * In our implementation, we use libc's TSD to store the locale data that
 * was previously global.  We still have global data because some applications
 * have had those global objects compiled into them.  (Such applications will
 * be unable to benefit from uselocale(), btw.)  The legacy routines are
 * reimplemented as wrappers that use the appropriate locale object by
 * calling uselocale().  uselocale() when passed a NULL pointer returns the
 * thread-specific locale object if one is present, or the global locale
 * object otherwise.  Note that once the TSD data is set, the only way
 * to revert to the global locale is to pass the global locale LC_GLOBAL_LOCALE
 * to uselocale().
 *
 * We are careful to minimize performance impact of multiple calls to
 * uselocale() or setlocale() by using a cache of locale data whenever possible.
 * As a consequence of this, applications that iterate over all possible
 * locales will burn through a lot of virtual memory, but we find such
 * applications rare.  (locale -a might be an exception, but it is short lived.)
 *
 * Category data is never released (although enclosing locale objects might be),
 * in order to guarantee thread-safety.  Calling freelocale() on an object
 * while it is in use by another thread is a programmer error (use-after-free)
 * and we don't bother to note it further.
 *
 * Locale objects (global locales) established by setlocale() are also
 * never freed (for MT safety), but we will save previous locale objects
 * and reuse them when we can.
 */

typedef struct locdata *(*loadfn_t)(const char *);

static const loadfn_t loaders[LC_ALL] = {
	__lc_ctype_load,
	__lc_numeric_load,
	__lc_time_load,
	__lc_collate_load,
	__lc_monetary_load,
	__lc_messages_load,
};

extern struct lc_monetary lc_monetary_posix;
extern struct lc_numeric lc_numeric_posix;
extern struct lc_messages lc_messages_posix;
extern struct lc_time lc_time_posix;
extern struct lc_ctype lc_ctype_posix;
extern struct lc_collate lc_collate_posix;

static struct _locale posix_locale = {
	/* locdata */
	.locdata = {
		&__posix_ctype_locdata,
		&__posix_numeric_locdata,
		&__posix_time_locdata,
		&__posix_collate_locdata,
		&__posix_monetary_locdata,
		&__posix_messages_locdata,
	},
	.locname = "C",
	.ctype = &lc_ctype_posix,
	.numeric = &lc_numeric_posix,
	.collate = &lc_collate_posix,
	.monetary = &lc_monetary_posix,
	.messages = &lc_messages_posix,
	.time = &lc_time_posix,
	.runelocale = &_DefaultRuneLocale,
};

locale_t ___global_locale = &posix_locale;

locale_t
__global_locale(void)
{
	return (___global_locale);
}

/*
 * Category names for getenv()  Note that this was modified
 * for Solaris.  See <iso/locale_iso.h>.
 */
#define	NUM_CATS	7
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
 * Prototypes.
 */
static const char *get_locale_env(int);
static struct locdata *locdata_get(int, const const char *);
static struct locdata *locdata_get_cache(int, const char *);
static locale_t mklocname(locale_t);

/*
 * Some utility routines.
 */

struct locdata *
__locdata_alloc(const char *name, size_t memsz)
{
	struct locdata *ldata;

	if ((ldata = lmalloc(sizeof (*ldata))) == NULL) {
		return (NULL);
	}
	if ((ldata->l_data[0] = libc_malloc(memsz)) == NULL) {
		lfree(ldata, sizeof (*ldata));
		errno = ENOMEM;
		return (NULL);
	}
	(void) strlcpy(ldata->l_lname, name, sizeof (ldata->l_lname));

	return (ldata);
}

/*
 * Normally we never free locale data truly, but if we failed to load it
 * for some reason, this routine is used to cleanup the partial mess.
 */
void
__locdata_free(struct locdata *ldata)
{
	for (int i = 0; i < NLOCDATA; i++)
		libc_free(ldata->l_data[i]);
	if (ldata->l_map != NULL && ldata->l_map_len)
		(void) munmap(ldata->l_map, ldata->l_map_len);
	lfree(ldata, sizeof (*ldata));
}

/*
 * It turns out that for performance reasons we would really like to
 * cache the most recently referenced locale data to avoid wasteful
 * loading from files.
 */

static struct locdata *cache_data[LC_ALL];
static struct locdata *cat_data[LC_ALL];
static mutex_t cache_lock = DEFAULTMUTEX;

/*
 * Returns the cached data if the locale name is the same.  If not,
 * returns NULL (cache miss).  The locdata is returned with a hold on
 * it, taken on behalf of the caller.  The caller should drop the hold
 * when it is finished.
 */
static struct locdata *
locdata_get_cache(int category, const char *locname)
{
	struct locdata *loc;

	if (category < 0 || category >= LC_ALL)
		return (NULL);

	/* Try cache first. */
	lmutex_lock(&cache_lock);
	loc = cache_data[category];

	if ((loc != NULL) && (strcmp(loc->l_lname, locname) == 0)) {
		lmutex_unlock(&cache_lock);
		return (loc);
	}

	/*
	 * Failing that try previously loaded locales (linear search) --
	 * this could be optimized to a hash, but its unlikely that a single
	 * application will ever need to work with more than a few locales.
	 */
	for (loc = cat_data[category]; loc != NULL; loc = loc->l_next) {
		if (strcmp(locname, loc->l_lname) == 0) {
			break;
		}
	}

	/*
	 * Finally, if we still don't have one, try loading the locale
	 * data from the actual on-disk data.
	 *
	 * We drop the lock (libc wants to ensure no internal locks
	 * are held when we call other routines required to read from
	 * files, allocate memory, etc.)  There is a small race here,
	 * but the consequences of the race are benign -- if multiple
	 * threads hit this at precisely the same point, we could
	 * wind up with duplicates of the locale data in the cache.
	 *
	 * This wastes the memory for an extra copy of the locale
	 * data, but there is no further harm beyond that.  Its not
	 * worth the effort to recode this to something "safe"
	 * (which would require rescanning the list, etc.), given
	 * that this race will probably never actually occur.
	 */
	if (loc == NULL) {
		lmutex_unlock(&cache_lock);
		loc = (*loaders[category])(locname);
		lmutex_lock(&cache_lock);
		if (loc != NULL)
			(void) strlcpy(loc->l_lname, locname,
			    sizeof (loc->l_lname));
	}

	/*
	 * Assuming we got one, update the cache, and stick us on the list
	 * of loaded locale data.  We insert into the head (more recent
	 * use is likely to win.)
	 */
	if (loc != NULL) {
		cache_data[category] = loc;
		if (!loc->l_cached) {
			loc->l_cached = 1;
			loc->l_next = cat_data[category];
			cat_data[category] = loc;
		}
	}

	lmutex_unlock(&cache_lock);
	return (loc);
}

/*
 * Routine to get the locdata for a given category and locale.
 * This includes retrieving it from cache, retrieving it from
 * a file, etc.
 */
static struct locdata *
locdata_get(int category, const char *locname)
{
	char scratch[ENCODING_LEN + 1];
	char *slash;
	int cnt;
	int len;

	if (locname == NULL || *locname == 0) {
		locname = get_locale_env(category);
	}

	/*
	 * Extract the locale name for the category if it is a composite
	 * locale.
	 */
	if ((slash = strchr(locname, '/')) != NULL) {
		for (cnt = category; cnt && slash != NULL; cnt--) {
			locname = slash + 1;
			slash = strchr(locname, '/');
		}
		if (slash) {
			len = slash - locname + 1;
			if (len >= sizeof (scratch)) {
				len = sizeof (scratch);
			}
		} else {
			len = sizeof (scratch);
		}
		(void) strlcpy(scratch, locname, len);
		locname = scratch;
	}

	if ((strcmp(locname, "C") == 0) || (strcmp(locname, "POSIX") == 0))
		return (posix_locale.locdata[category]);

	return (locdata_get_cache(category, locname));
}

/* tsd destructor */
static void
freelocptr(void *arg)
{
	locale_t *locptr = arg;
	if (*locptr != NULL)
		freelocale(*locptr);
}

static const char *
get_locale_env(int category)
{
	const char *env;

	/* 1. check LC_ALL. */
	env = getenv(categories[LC_ALL]);

	/* 2. check LC_* */
	if (env == NULL || *env == '\0')
		env = getenv(categories[category]);

	/* 3. check LANG */
	if (env == NULL || *env == '\0')
		env = getenv("LANG");

	/* 4. if none is set, fall to "C" */
	if (env == NULL || *env == '\0')
		env = "C";

	return (env);
}


/*
 * This routine is exposed via the MB_CUR_MAX macro.  Note that legacy
 * code will continue to use _ctype[520], but we prefer this function as
 * it is the only way to get thread-specific information.
 */
unsigned char
__mb_cur_max_l(locale_t loc)
{
	return (loc->ctype->lc_max_mblen);
}

unsigned char
__mb_cur_max(void)
{
	return (__mb_cur_max_l(uselocale(NULL)));
}

/*
 * Public interfaces.
 */

locale_t
duplocale(locale_t src)
{
	locale_t	loc;
	int		i;

	loc = lmalloc(sizeof (*loc));
	if (loc == NULL) {
		return (NULL);
	}
	if (src == NULL) {
		/* illumos extension: POSIX says LC_GLOBAL_LOCALE here */
		src = ___global_locale;
	}
	for (i = 0; i < LC_ALL; i++) {
		loc->locdata[i] = src->locdata[i];
		loc->loaded[i] = 0;
	}
	loc->collate = loc->locdata[LC_COLLATE]->l_data[0];
	loc->ctype = loc->locdata[LC_CTYPE]->l_data[0];
	loc->runelocale = loc->locdata[LC_CTYPE]->l_data[1];
	loc->messages = loc->locdata[LC_MESSAGES]->l_data[0];
	loc->monetary = loc->locdata[LC_MONETARY]->l_data[0];
	loc->numeric = loc->locdata[LC_NUMERIC]->l_data[0];
	loc->time = loc->locdata[LC_TIME]->l_data[0];
	return (loc);
}

void
freelocale(locale_t loc)
{
	/*
	 * We take extra care never to free a saved locale created by
	 * setlocale().  This shouldn't be strictly necessary, but a little
	 * extra safety doesn't hurt here.
	 */
	if ((loc != NULL) && (loc != &posix_locale) && (!loc->on_list))
		lfree(loc, sizeof (*loc));
}

locale_t
newlocale(int catmask, const char *locname, locale_t base)
{
	locale_t loc;
	int i, e;

	if (catmask & ~(LC_ALL_MASK)) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Technically passing LC_GLOBAL_LOCALE here is illegal,
	 * but we allow it.
	 */
	if (base == NULL || base == ___global_locale) {
		loc = duplocale(___global_locale);
	} else {
		loc = duplocale(base);
	}
	if (loc == NULL) {
		return (NULL);
	}

	for (i = 0; i < LC_ALL; i++) {
		struct locdata *ldata;
		loc->loaded[i] = 0;
		if (((1 << i) & catmask) == 0) {
			/* Default to base locale if not overriding */
			continue;
		}
		ldata = locdata_get(i, locname);
		if (ldata == NULL) {
			e = errno;
			freelocale(loc);
			errno = e;
			return (NULL);
		}
		loc->locdata[i] = ldata;
	}
	loc->collate = loc->locdata[LC_COLLATE]->l_data[0];
	loc->ctype = loc->locdata[LC_CTYPE]->l_data[0];
	loc->runelocale = loc->locdata[LC_CTYPE]->l_data[1];
	loc->messages = loc->locdata[LC_MESSAGES]->l_data[0];
	loc->monetary = loc->locdata[LC_MONETARY]->l_data[0];
	loc->numeric = loc->locdata[LC_NUMERIC]->l_data[0];
	loc->time = loc->locdata[LC_TIME]->l_data[0];
	freelocale(base);

	return (mklocname(loc));
}

locale_t
uselocale(locale_t loc)
{
	locale_t lastloc = ___global_locale;
	locale_t *locptr;

	locptr = tsdalloc(_T_SETLOCALE, sizeof (locale_t), freelocptr);
	/* Should never occur */
	if (locptr == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (*locptr != NULL)
		lastloc = *locptr;

	/* Argument loc is NULL if we are just querying. */
	if (loc != NULL) {
		/*
		 * Set it to LC_GLOBAL_LOCAL to return to using
		 * the global locale (setlocale).
		 */
		if (loc == ___global_locale) {
			*locptr = NULL;
		} else {
			/* No validation of the provided locale at present */
			*locptr = loc;
		}
	}

	/*
	 * The caller is responsible for freeing, of course it would be
	 * gross error to call freelocale() on a locale object that is still
	 * in use.
	 */
	return (lastloc);
}

static locale_t
mklocname(locale_t loc)
{
	int composite = 0;

	/* Look to see if any category is different */
	for (int i = 1; i < LC_ALL; ++i) {
		if (strcmp(loc->locdata[0]->l_lname,
		    loc->locdata[i]->l_lname) != 0) {
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
		(void) snprintf(loc->locname, sizeof (loc->locname),
		    "%s/%s/%s/%s/%s/%s",
		    loc->locdata[LC_CTYPE]->l_lname,
		    loc->locdata[LC_NUMERIC]->l_lname,
		    loc->locdata[LC_TIME]->l_lname,
		    loc->locdata[LC_COLLATE]->l_lname,
		    loc->locdata[LC_MONETARY]->l_lname,
		    loc->locdata[LC_MESSAGES]->l_lname);
	} else {
		(void) strlcpy(loc->locname, loc->locdata[LC_CTYPE]->l_lname,
		    sizeof (loc->locname));
	}
	return (loc);
}
