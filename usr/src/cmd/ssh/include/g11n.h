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

#ifndef	_G11N_H
#define	_G11N_H

#ifdef __cplusplus
extern "C" {
#endif


#include "includes.h"
#include <sys/types.h>

/*
 * Functions for language tag negotiation
 */

/* boolean */
uint_t g11n_langtag_is_default(char *langtag);

/* return 0 if not, 1 if yes, 2 if the country is matched too */
uint_t g11n_langtag_matches_locale(char *langtag, char *locale);

/* get current locale */
char *g11n_getlocale();

/* get current locale */
void g11n_setlocale(int category, const char *locale);

/* get list of locales - returns pointer to array of pointers to char */
char **g11n_getlocales();

/* get list of langs spoken by the user, from SSH_LANGS env var */
char *g11n_getlangs();

/* make a comma-separated list of language tags from list of locales */
char *g11n_locales2langs(char **locale_set);

int g11n_langtag_match(char *langtag1, char *langtag2);

/* intersect comma-separated lists of IETF language tags */
char *g11n_langtag_set_intersect(char *set1, char *set2);

char *g11n_clnt_langtag_negotiate(char *clnt_langtags, char *srvr_langtags);

char **g11n_langtag_set_locale_set_intersect(char *langtag_set,
    char **locale_set);

char *g11n_srvr_locale_negotiate(char *clnt_langtags, char **srvr_locales);

/* auxiliary functions */
void g11n_freelist(char **list);

/*
 * Functions for converting to ASCII or UTF-8 from the local codeset
 * Functions for converting from ASCII or UTF-8 to the local codeset
 *
 * The error_str parameter is an optional pointer to a char variable
 * where to store a string suitable for use with error() or fatal() or
 * friends.
 *
 */
extern char *g11n_convert_from_utf8(const char *str, uint_t *lenp,
				char **error_str);

extern char *g11n_convert_to_utf8(const char *str, uint_t *lenp, int native,
				char **error_str);

extern char *g11n_filter_string(char *);
extern void g11n_test_langtag(const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _G11N_H */
