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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _TZINT_H
#define	_TZINT_H

/*
 * Time Zone Internal functions for libc. This contains a few extras that we
 * have to deal with the fact that we don't have tm_zone and other extras that
 * we want for ourselves, but are not part of public interfaces.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The maximum length, including the terminating NUL, of a single time zone
 * abbreviation. We carry our own definition here so that consumers of
 * tzinfo_ctx_t need not pull in <tzfile.h>; localtime.c asserts that the two
 * agree.
 */
#define	TZC_ABBR_MAX	50

/*
 * This represents the global state that is normally associated with calling
 * tzset().
 */
typedef struct tzinfo_ctx {
	const char *tzc_tzname[2];
	char tzc_namebuf[2][TZC_ABBR_MAX];
	long tzc_timezone;
	long tzc_altzone;
	int tzc_daylight;
	int tzc_is_in_dst;
} tzinfo_ctx_t;

/*
 * Using the currently set timezone calculate the timezone and offset rules for
 * the specified time. This is not going to be the same as what is set by
 * calling tzset() as tzset() is generally based on the current time. This will
 * hold _time_lock during it, but no effort is made to guarantee that this is
 * consistent with a corresponding call to tzset(). That should be dealt with in
 * the future by internally (and possibly externally) adding the tzalloc() and
 * related APIs.
 */
extern void tzinfo_tm_to_ctx(const struct tm *, tzinfo_ctx_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TZINT_H */
