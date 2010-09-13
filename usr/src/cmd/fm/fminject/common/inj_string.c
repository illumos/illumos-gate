/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>

#include <inj.h>
#include <inj_err.h>
#include <inj_string.h>

char *
inj_strdup(const char *s)
{
	char *s1 = inj_alloc(strlen(s) + 1);

	(void) strcpy(s1, s);
	return (s1);
}

char *
inj_strndup(const char *s, size_t n)
{
	char *s2 = inj_alloc(n + 1);

	(void) strncpy(s2, s, n + 1);
	s2[n] = '\0';
	return (s2);
}

void
inj_strfree(const char *s)
{
	inj_free((void *)s, strlen(s) + 1);
}

typedef struct type_desc {
	int64_t td_min;
	uint64_t td_max;
} type_desc_t;

static const type_desc_t signed_types[] = {
	{ 0, 0 },
	{ INT8_MIN, INT8_MAX },
	{ INT16_MIN, INT16_MAX },
	{ 0, 0 },
	{ INT32_MIN, INT32_MAX },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ INT64_MIN, INT64_MAX }
};

static const type_desc_t unsigned_types[] = {
	{ 0, 0 },
	{ 0, UINT8_MAX },
	{ 0, UINT16_MAX },
	{ 0, 0 },
	{ 0, UINT32_MAX },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, UINT64_MAX }
};

int
inj_strtoll(const char *str, int width, longlong_t *valp)
{
	const type_desc_t *desc;
	longlong_t val;
	char *c;

	if (width != 0) {
		assert(width / 8 < (sizeof (signed_types) /
		    sizeof (signed_types[0])));
		desc = &signed_types[width / 8];
		assert(desc->td_max != 0);
	}

	errno = 0;
	val = strtoll(str, &c, 0);
	if (*c != '\0' || errno == EINVAL)
		return (inj_set_errno(EINVAL));

	if (errno == ERANGE || (width != 0 && (val < desc->td_min ||
	    val > (longlong_t)desc->td_max)))
		return (inj_set_errno(ERANGE));

	if (valp != NULL)
		*valp = val;

	return (0);
}

int
inj_strtoull(const char *str, int width, u_longlong_t *valp)
{
	const type_desc_t *desc;
	u_longlong_t val;
	char *c;

	if (width != 0) {
		assert(width / 8 < (sizeof (unsigned_types) /
		    sizeof (unsigned_types[0])));
		desc = &unsigned_types[width / 8];
		assert(desc->td_max != 0);
	}

	errno = 0;
	val = strtoull(str, &c, 0);
	if (*c != '\0' || errno == EINVAL)
		return (inj_set_errno(EINVAL));

	if (errno == ERANGE || (width != 0 && val > desc->td_max))
		return (inj_set_errno(ERANGE));

	if (valp != NULL)
		*valp = val;

	return (0);
}

int
inj_strtime(hrtime_t *nsp, const char *units)
{
	static const struct {
		const char *name;
		hrtime_t mul;
	} suffix[] = {
		{ "ns", 	NANOSEC / NANOSEC },
		{ "nsec",	NANOSEC / NANOSEC },
		{ "us",		NANOSEC / MICROSEC },
		{ "usec",	NANOSEC / MICROSEC },
		{ "ms",		NANOSEC / MILLISEC },
		{ "msec",	NANOSEC / MILLISEC },
		{ "s",		NANOSEC / SEC },
		{ "sec",	NANOSEC / SEC },
		{ "m",		NANOSEC * (hrtime_t)60 },
		{ "min",	NANOSEC * (hrtime_t)60 },
		{ "h",		NANOSEC * (hrtime_t)(60 * 60) },
		{ "hour",	NANOSEC * (hrtime_t)(60 * 60) },
		{ "d",		NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "day",	NANOSEC * (hrtime_t)(24 * 60 * 60) },
		{ "hz",		0 },
		{ NULL }
	};

	hrtime_t val = *nsp, mul = 1;
	int i;

	for (i = 0; suffix[i].name != NULL; i++) {
		if (strcasecmp(suffix[i].name, units) == 0) {
			mul = suffix[i].mul;
			break;
		}
	}

	if (suffix[i].name == NULL && *units != '\0')
		return (inj_set_errno(EINVAL));

	if (mul == 0) {
		if (val != 0)
			val = NANOSEC / val; /* compute val as value per sec */
	} else
		val *= mul;

	*nsp = val;
	return (0);
}

static ulong_t
inj_hashfn_string(void *key)
{
	size_t g, h = 0;
	char *p;

	assert(key != NULL);

	for (p = key; *p != '\0'; p++) {
		h = (h << 4) + *p;

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static int
inj_hashcmp_string(void *k1, void *k2)
{
	return (strcmp(k1, k2));
}

/*ARGSUSED*/
static void
inj_hashfree_string(inj_var_t *v, void *arg)
{
	inj_strfree(inj_hash_get_key(v));
}

void
inj_strhash_create(inj_hash_t *h)
{
	inj_hash_create(h, inj_hashfn_string, inj_hashcmp_string);
}

int
inj_strhash_insert(inj_hash_t *h, const char *str, uintmax_t value)
{
	return (inj_hash_insert(h, (void *)inj_strdup(str), value));
}

inj_var_t *
inj_strhash_lookup(inj_hash_t *h, const char *str)
{
	return (inj_hash_lookup(h, (void *)str));
}

void
inj_strhash_destroy(inj_hash_t *h)
{
	inj_hash_destroy(h, inj_hashfree_string, NULL);
}
