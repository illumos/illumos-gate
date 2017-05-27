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
 * Copyright 2017 Jason King
 */
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <string.h>
#include "str.h"
#include "demangle_int.h"

#define	STR_CHUNK_SZ	(64U)

/* are we storing a reference vs. a dynamically allocated copy? */
#define	IS_REF(s) ((s)->str_s != NULL && (s)->str_size == 0)

/*
 * Dynamically resizeable strings, with lazy allocation when initialized
 * with a constant string value
 *
 * NOTE: these are not necessairly 0-terminated
 *
 * Additionally, these can store references instead of copies of strings
 * (as indicated by the IS_REF() macro.  However mutation may cause a
 * string to convert from a refence to a dynamically allocated copy.
 */

void
str_init(str_t *restrict s, sysdem_ops_t *restrict ops)
{
	(void) memset(s, 0, sizeof (*s));
	s->str_ops = (ops != NULL) ? ops : sysdem_ops_default;
}

void
str_fini(str_t *s)
{
	if (s == NULL)
		return;
	if (!IS_REF(s))
		xfree(s->str_ops, s->str_s, s->str_size);
	(void) memset(s, 0, sizeof (*s));
}

size_t
str_length(const str_t *s)
{
	return (s->str_len);
}

/*
 * store as a reference instead of a copy
 * if len == 0, means store entire copy of 0 terminated string
 */
void
str_set(str_t *s, const char *cstr, size_t len)
{
	sysdem_ops_t *ops = s->str_ops;

	str_fini(s);
	s->str_ops = ops;
	s->str_s = (char *)cstr;
	s->str_len = (len == 0 && cstr != NULL) ? strlen(cstr) : len;
}

boolean_t
str_copy(const str_t *src, str_t *dest)
{
	str_fini(dest);
	str_init(dest, src->str_ops);

	if (src->str_len == 0)
		return (B_TRUE);

	size_t len = roundup(src->str_len, STR_CHUNK_SZ);
	dest->str_s = zalloc(src->str_ops, len);
	if (dest->str_s == NULL)
		return (B_FALSE);

	(void) memcpy(dest->str_s, src->str_s, src->str_len);
	dest->str_len = src->str_len;
	dest->str_size = len;

	return (B_TRUE);
}

/*
 * ensure s has at least amt bytes free, resizing if necessary
 */
static boolean_t
str_reserve(str_t *s, size_t amt)
{
	size_t newlen = s->str_len + amt;

	/* overflow check */
	if (newlen < s->str_len || newlen < amt)
		return (B_FALSE);

	if ((amt > 0) && (s->str_len + amt <= s->str_size))
		return (B_TRUE);

	size_t newsize = roundup(newlen, STR_CHUNK_SZ);
	void *temp;

	if (IS_REF(s)) {
		temp = zalloc(s->str_ops, newsize);
		if (temp == NULL)
			return (B_FALSE);

		(void) memcpy(temp, s->str_s, s->str_len);
	} else {
		temp = xrealloc(s->str_ops, s->str_s, s->str_size, newsize);
		if (temp == NULL)
			return (B_FALSE);
	}

	s->str_s = temp;
	s->str_size = newsize;

	return (B_TRUE);
}

/* append to s, cstrlen == 0 means entire length of string */
boolean_t
str_append(str_t *s, const char *cstr, size_t cstrlen)
{
	if (cstr != NULL && cstrlen == 0)
		cstrlen = strlen(cstr);

	const str_t src = {
		.str_s = (char *)cstr,
		.str_len = cstrlen,
		.str_ops = s->str_ops
	};

	return (str_append_str(s, &src));
}

boolean_t
str_append_str(str_t *dest, const str_t *src)
{
	/* empty string is a noop */
	if (src->str_s == NULL || src->str_len == 0)
		return (B_TRUE);

	/* if src is a reference, we can just copy that */
	if (dest->str_s == NULL && IS_REF(src)) {
		*dest = *src;
		return (B_TRUE);
	}

	if (!str_reserve(dest, src->str_len))
		return (B_FALSE);

	(void) memcpy(dest->str_s + dest->str_len, src->str_s, src->str_len);
	dest->str_len += src->str_len;
	return (B_TRUE);
}

boolean_t
str_append_c(str_t *s, char c)
{
	if (!str_reserve(s, 1))
		return (B_FALSE);

	s->str_s[s->str_len++] = c;
	return (B_TRUE);
}

boolean_t
str_insert(str_t *s, size_t idx, const char *cstr, size_t cstrlen)
{
	if (cstr == NULL)
		return (B_TRUE);

	if (cstrlen == 0)
		cstrlen = strlen(cstr);

	str_t src = {
		.str_s = (char *)cstr,
		.str_len = cstrlen,
		.str_ops = s->str_ops,
		.str_size = 0
	};

	return (str_insert_str(s, idx, &src));
}

boolean_t
str_insert_str(str_t *dest, size_t idx, const str_t *src)
{
	ASSERT3U(idx, <=, dest->str_len);

	if (idx == dest->str_len)
		return (str_append_str(dest, src));

	if (idx == 0 && dest->str_s == NULL && IS_REF(src)) {
		sysdem_ops_t *ops = dest->str_ops;
		*dest = *src;
		dest->str_ops = ops;
		return (B_TRUE);
	}

	if (!str_reserve(dest, src->str_len))
		return (B_FALSE);

	/*
	 * Shift the contents of dest over at the insertion point.  Since
	 * src and dest ranges will overlap, and unlike some programmers,
	 * *I* can read man pages - memmove() is the appropriate function
	 * to this.
	 */
	(void) memmove(dest->str_s + idx + src->str_len, dest->str_s + idx,
	    dest->str_len - idx);

	/*
	 * However the content to insert does not overlap with the destination
	 * so memcpy() is fine here.
	 */
	(void) memcpy(dest->str_s + idx, src->str_s, src->str_len);
	dest->str_len += src->str_len;

	return (B_TRUE);
}

boolean_t
str_erase(str_t *s, size_t pos, size_t len)
{
	ASSERT3U(pos, <, s->str_len);
	ASSERT3U(pos + len, <=, s->str_len);

	if (IS_REF(s)) {
		if (!str_reserve(s, 0))
			return (B_FALSE);
	}

	(void) memmove(s->str_s + pos, s->str_s + pos + len, s->str_len - len);
	s->str_len -= len;
	return (B_TRUE);
}

str_pair_t *
str_pair_init(str_pair_t *sp, sysdem_ops_t *ops)
{
	(void) memset(sp, 0, sizeof (*sp));
	str_init(&sp->strp_l, ops);
	str_init(&sp->strp_r, ops);
	return (sp);
}

void
str_pair_fini(str_pair_t *sp)
{
	str_fini(&sp->strp_l);
	str_fini(&sp->strp_r);
}

/* combine left and right parts and put result into left part */
boolean_t
str_pair_merge(str_pair_t *sp)
{
	/* if right side is empty, don't need to do anything */
	if (str_length(&sp->strp_r) == 0)
		return (B_TRUE);

	/* if left side is empty, just move right to left */
	if (str_length(&sp->strp_l) == 0) {
		str_fini(&sp->strp_l);
		sp->strp_l = sp->strp_r;
		sp->strp_r.str_s = NULL;
		sp->strp_r.str_len = sp->strp_r.str_size = 0;
		return (B_TRUE);
	}

	if (!str_append_str(&sp->strp_l, &sp->strp_r))
		return (B_FALSE);

	str_fini(&sp->strp_r);
	str_init(&sp->strp_r, sp->strp_l.str_ops);
	return (B_TRUE);
}

boolean_t
str_pair_copy(const str_pair_t *src, str_pair_t *dest)
{
	boolean_t ok = B_TRUE;

	ok &= str_copy(&src->strp_l, &dest->strp_l);
	ok &= str_copy(&src->strp_r, &dest->strp_r);

	if (!ok) {
		str_fini(&dest->strp_l);
		str_fini(&dest->strp_r);
		return (B_FALSE);
	}

	return (B_TRUE);
}

size_t
str_pair_len(const str_pair_t *sp)
{
	return (str_length(&sp->strp_l) + str_length(&sp->strp_r));
}
