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
 * Copyright 2019, Joyent, Inc.
 */

#include <string.h>
#include <sys/debug.h>
#include "strview.h"

void
sv_init_sv(strview_t *sv, const strview_t *src)
{
	*sv = *src;
}

void
sv_init_sv_range(strview_t *sv, const strview_t *src, size_t len)
{
	VERIFY3U(sv_remaining(src), >=, len);

	sv->sv_first = src->sv_first;
	sv->sv_last = src->sv_first + len;
	sv->sv_rem = len;
}

void
sv_init_str(strview_t *sv, const char *first, const char *last)
{
	if (last == NULL)
		last = first + strlen(first);

	VERIFY3P(first, <=, last);
	sv->sv_first = first;
	sv->sv_last = last;
	sv->sv_rem = (size_t)(uintptr_t)(sv->sv_last - sv->sv_first);
}

size_t
sv_remaining(const strview_t *sv)
{
	return (sv->sv_rem);
}

boolean_t
sv_consume_if_c(strview_t *sv, char c)
{
	if (sv->sv_rem < 1 || *sv->sv_first != c)
		return (B_FALSE);

	sv->sv_first++;
	sv->sv_rem--;
	return (B_TRUE);
}

boolean_t
sv_consume_if(strview_t *sv, const char *str)
{
	size_t slen = strlen(str);

	if (sv->sv_rem < slen)
		return (B_FALSE);
	if (strncmp(sv->sv_first, str, slen) != 0)
		return (B_FALSE);

	sv->sv_first += slen;
	sv->sv_rem -= slen;
	return (B_TRUE);
}

char
sv_peek(const strview_t *sv, ssize_t n)
{
	const char *p;

	p = (n >= 0) ? sv->sv_first + n : sv->sv_last + n;
	return ((p >= sv->sv_first && p < sv->sv_last) ? *p : '\0');
}

char
sv_consume_c(strview_t *sv)
{
	char c = '\0';

	if (sv->sv_first < sv->sv_last) {
		c = *sv->sv_first++;
		sv->sv_rem--;
	}
	return (c);
}

void
sv_consume_n(strview_t *sv, size_t n)
{
	VERIFY3U(sv->sv_rem, >=, n);
	sv->sv_first += n;
	sv->sv_rem -= n;
}
