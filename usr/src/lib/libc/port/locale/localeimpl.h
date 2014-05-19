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
 * This file implements the 2008 newlocale and friends handling. It is
 * private to libc.
 */
#ifndef	_LOCALEIMPL_H_
#define	_LOCALEIMPL_H_

#ifndef _LCONV_C99
#define	_LCONV_C99	/* so we get all the extensions */
#endif

#include <sys/types.h>
#include <locale.h>
#include <xlocale.h>
#include "setlocale.h"
#include "runetype.h"

/* private locale structures */

/*
 * Because some locale data is rather ahem.. large, we would like to keep
 * reference counts on it.  We create an abstract header (locdata) structure
 * which keeps a point to the opaque per-category data, along with a reference
 * count to it.  To be threadsafe, we will use atomics when holding it or
 * freeing it.  (This only occurs when locale objects are created or destroyed,
 * so there should be no performance impact on hot code paths.  If your code
 * uses locale_t creation/destruction on a hot code path, its broken.  But
 * even so, the atomic and reference counting will probably *greatly* improve
 * your life as bootstrapping locale data from files is quite expensive.
 */

#define	NLOCDATA	4
struct locdata {
	char		l_lname[ENCODING_LEN+1];	/* locale name */
	void		*l_data[NLOCDATA];		/* storage area */
	void		*l_map;				/* mapped file */
	size_t		l_map_len;
	struct locdata	*l_next;			/* link cached list */
	int		l_cached;			/* nonzero if cached */
};


struct locale {
	struct locdata	*locdata[LC_ALL];
	struct locale	*next;
	int		on_list;	/* on linked list */
	char		locname[(ENCODING_LEN+1)*NLOCDATA + 1];

	/*
	 * Convenience pointers.
	 */
	const struct lc_ctype		*ctype;
	const struct lc_collate		*collate;
	const struct lc_messages	*messages;
	const struct lc_monetary	*monetary;
	const struct lc_numeric		*numeric;
	const struct lc_time		*time;
	const _RuneLocale		*runelocale;

	/*
	 * The loaded value is used for localeconv.  In paticular, when
	 * when we change the value of one of the above categories, we will
	 * also need to update the lconv structure.  The loaded bit indicates
	 * that the lconv structure is "current" for that category.  It's
	 * sort of an "inverse dirty" bit.
	 */
	int		loaded[LC_ALL];
	struct lconv	lconv;
};


struct locdata *__locdata_alloc(const char *, size_t);
void __locdata_free(struct locdata *);
struct locdata *__locdata_get_cache(int, const char *);
void __locdata_set_cache(int, struct locdata *);

struct locdata *__lc_numeric_load(const char *name);
struct locdata *__lc_monetary_load(const char *name);
struct locdata *__lc_messages_load(const char *name);
struct locdata *__lc_time_load(const char *name);
struct locdata *__lc_ctype_load(const char *name);
struct locdata *__lc_collate_load(const char *name);

extern struct locdata	__posix_numeric_locdata;
extern struct locdata	__posix_monetary_locdata;
extern struct locdata	__posix_messages_locdata;
extern struct locdata	__posix_time_locdata;
extern struct locdata	__posix_ctype_locdata;
extern struct locdata	__posix_collate_locdata;
extern locale_t ___global_locale;

#endif	/* _LOCALEIMPL_H_ */
