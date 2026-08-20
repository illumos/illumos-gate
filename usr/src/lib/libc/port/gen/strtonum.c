/*
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#define	INVALID		1
#define	TOOSMALL	2
#define	TOOLARGE	3
#define	BADBASE		4

#define	MBASE		('z' - 'a' + 1 + 10)

static const struct errval {
	const char *errstr;
	int err;
} strtonum_ev[5] = {
	{ NULL,		0 },
	{ "invalid",	EINVAL },
	{ "too small",	ERANGE },
	{ "too large",	ERANGE },
	{ "unparsable; invalid base specified", EINVAL },
};

static int
strtonum_done(int error, int serrno, const char **errstrp)
{
	if (errstrp != NULL)
		*errstrp = strtonum_ev[error].errstr;
	errno = (error == 0) ? serrno : strtonum_ev[error].err;
	return (error);
}

long long
strtonumx(const char *numstr, long long minval, long long maxval,
    const char **errstrp, int base)
{
	long long ll = 0;
	int error = 0;
	int serrno = errno;
	char *ep;

	errno = 0;
	if (minval > maxval) {
		error = INVALID;
	} else if (base < 0 || base > MBASE || base == 1) {
		error = BADBASE;
	} else {
		ll = strtoll(numstr, &ep, base);
		if (numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}

	if (strtonum_done(error, serrno, errstrp) != 0)
		ll = 0;

	return (ll);
}

long long
strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	return (strtonumx(numstr, minval, maxval, errstrp, 10));
}

unsigned long long
strtounumx(const char *numstr, unsigned long long minval,
    unsigned long long maxval, const char **errstrp, int base)
{
	unsigned long long ull = 0;
	int error = 0;
	int serrno = errno;
	char *ep;
	const char *np;

	errno = 0;

	np = numstr;
	while (isspace((unsigned char)*np))
		np++;

	if (minval > maxval) {
		error = INVALID;
	} else if (base < 0 || base > MBASE || base == 1) {
		error = BADBASE;
	} else {
		ull = strtoull(numstr, &ep, base);
		if (numstr == ep || *ep != '\0') {
			error = INVALID;
		} else if (*np == '-') {
			/*
			 * strtoull() silently accepts a leading minus sign
			 * and returns the unsigned complement of the value.
			 * Explicitly reject strings which parsed successfully
			 * but represent a negative number.
			 */
			error = TOOSMALL;
		} else if (ull == ULLONG_MAX && errno == ERANGE) {
			error = TOOLARGE;
		} else if (ull < minval) {
			error = TOOSMALL;
		} else if (ull > maxval) {
			error = TOOLARGE;
		}
	}

	if (strtonum_done(error, serrno, errstrp) != 0)
		ull = 0;

	return (ull);
}

unsigned long long
strtounum(const char *numstr, unsigned long long minval,
    unsigned long long maxval, const char **errstrp)
{
	return (strtounumx(numstr, minval, maxval, errstrp, 10));
}
