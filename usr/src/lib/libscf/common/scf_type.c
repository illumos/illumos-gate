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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <repcache_protocol.h>
#include "scf_type.h"
#include <errno.h>
#include <libgen.h>
#include <libscf_priv.h>
#include <stdlib.h>
#include <string.h>

#define	UTF8_TOP_N(n) \
	(0xff ^ (0xff >> (n)))		/* top N bits set */

#define	UTF8_BOTTOM_N(n) \
	((1 << (n)) - 1)		/* bottom N bits set */

/*
 * The first byte of an n-byte UTF8 encoded character looks like:
 *
 *	n	bits
 *
 *	1	0xxxxxxx
 *	2	110xxxxx
 *	3	1110xxxx
 *	4	11110xxx
 *	5	111110xx
 *	6	1111110x
 *
 * Continuation bytes are 01xxxxxx.
 */

#define	UTF8_MAX_BYTES	6

/*
 * number of bits in an n-byte UTF-8 encoding.  for multi-byte encodings,
 * You get (7 - n) bits in the first byte, and 6 bits for each additional byte.
 */
#define	UTF8_BITS(n)	/* 1 <= n <= 6 */			\
	((n) == 1)? 7 :						\
	(7 - (n) + 6 * ((n) - 1))

#define	UTF8_SINGLE_BYTE(c) \
	(((c) & UTF8_TOP_N(1)) == 0)	/* 0xxxxxxx */

#define	UTF8_HEAD_CHECK(c, n)		/* 2 <= n <= 6 */		\
	(((c) & UTF8_TOP_N((n) + 1)) == UTF8_TOP_N(n))

#define	UTF8_HEAD_VALUE(c, n)		/* 2 <= n <= 6 */		\
	((c) & UTF8_BOTTOM_N(7 - (n)))	/* 'x' mask */

#define	UTF8_CONT_CHECK(c) \
	(((c) & UTF8_TOP_N(2)) == UTF8_TOP_N(1))	/* 10xxxxxx */

/*
 * adds in the 6 new bits from a continuation byte
 */
#define	UTF8_VALUE_UPDATE(v, c) \
	(((v) << 6) | ((c) & UTF8_BOTTOM_N(6)))

/*
 * URI components
 */

#define	URI_COMPONENT_COUNT	5

enum {
	URI_SCHEME = 0x0,		/* URI scheme */
	URI_AUTHORITY,			/* URI authority */
	URI_PATH,			/* URI path */
	URI_QUERY,			/* URI query */
	URI_FRAGMENT			/* URI fragment  */
};

static int
valid_utf8(const char *str_arg)
{
	const char *str = str_arg;
	uint_t c;
	uint32_t v;
	int i, n;

	while ((c = *str++) != 0) {
		if (UTF8_SINGLE_BYTE(c))
			continue;	/* ascii */

		for (n = 2; n <= UTF8_MAX_BYTES; n++)
			if (UTF8_HEAD_CHECK(c, n))
				break;

		if (n > UTF8_MAX_BYTES)
			return (0);		/* invalid head byte */

		v = UTF8_HEAD_VALUE(c, n);

		for (i = 1; i < n; i++) {
			c = *str++;
			if (!UTF8_CONT_CHECK(c))
				return (0);	/* invalid byte */

			v = UTF8_VALUE_UPDATE(v, c);
		}

		/*
		 * if v could have been encoded in the next smallest
		 * encoding, the string is not well-formed UTF-8.
		 */
		if ((v >> (UTF8_BITS(n - 1))) == 0)
			return (0);
	}

	/*
	 * we've reached the end of the string -- make sure it is short enough
	 */
	return ((str - str_arg) < REP_PROTOCOL_VALUE_LEN);
}

static int
valid_string(const char *str)
{
	return (strlen(str) < REP_PROTOCOL_VALUE_LEN);
}

static int
valid_opaque(const char *str_arg)
{
	const char *str = str_arg;
	uint_t c;
	ptrdiff_t len;

	while ((c = *str++) != 0)
		if ((c < '0' || c > '9') && (c < 'a' || c > 'f') &&
		    (c < 'A' || c > 'F'))
			return (0);		/* not hex digit */

	len = (str - str_arg) - 1;		/* not counting NIL byte */
	return ((len % 2) == 0 && len / 2 < REP_PROTOCOL_VALUE_LEN);
}

/*
 * Return 1 if the supplied parameter is a conformant URI (as defined
 * by RFC 2396), 0 otherwise.
 */
static int
valid_uri(const char *str)
{
	/*
	 * URI Regular Expression. Compiled with regcmp(1).
	 *
	 * ^(([^:/?#]+:){0,1})$0(//([^/?#]*)$1){0,1}([^?#]*)$2
	 * (?([^#]*)$3){0,1}(#(.*)$4){0,1}
	 */
	char exp[] = {
		040, 074, 00, 060, 012, 0126, 05, 072, 057, 077, 043, 024,
		072, 057, 00, 00, 01, 014, 00, 00, 060, 020, 024, 057,
		024, 057, 074, 01, 0125, 04, 057, 077, 043, 014, 01, 01,
		057, 01, 00, 01, 074, 02, 0125, 03, 077, 043, 014, 02,
		02, 060, 014, 024, 077, 074, 03, 0125, 02, 043, 014, 03,
		03, 057, 02, 00, 01, 060, 012, 024, 043, 074, 04, 021,
		014, 04, 04, 057, 03, 00, 01, 064, 00,
		0};
	char uri[URI_COMPONENT_COUNT][REP_PROTOCOL_VALUE_LEN];

	/*
	 * If the string is too long, then the URI cannot be valid. Also,
	 * this protects against buffer overflow attacks on the uri array.
	 */
	if (strlen(str) >= REP_PROTOCOL_VALUE_LEN)
		return (0);

	if (regex(exp, str, uri[URI_SCHEME], uri[URI_AUTHORITY], uri[URI_PATH],
	    uri[URI_QUERY], uri[URI_FRAGMENT]) == NULL) {
		return (0);
	}
	/*
	 * To be a valid URI, the length of the URI_PATH must not be zero
	 */
	if (strlen(uri[URI_PATH]) == 0) {
		return (0);
	}
	return (1);
}

/*
 * Return 1 if the supplied parameter is a conformant fmri, 0
 * otherwise.
 */
static int
valid_fmri(const char *str)
{
	int ret;
	char fmri[REP_PROTOCOL_VALUE_LEN] = { 0 };

	/*
	 * Try to parse the fmri, if we can parse it then it
	 * must be syntactically correct. Work on a copy of
	 * the fmri since the parsing process can modify the
	 * supplied string.
	 */
	if (strlcpy(fmri, str, sizeof (fmri)) >= sizeof (fmri))
		return (0);

	ret = ! scf_parse_fmri(fmri, NULL, NULL, NULL, NULL, NULL, NULL);

	return (ret);
}

rep_protocol_value_type_t
scf_proto_underlying_type(rep_protocol_value_type_t t)
{
	switch (t) {
	case REP_PROTOCOL_TYPE_BOOLEAN:
	case REP_PROTOCOL_TYPE_COUNT:
	case REP_PROTOCOL_TYPE_INTEGER:
	case REP_PROTOCOL_TYPE_TIME:
	case REP_PROTOCOL_TYPE_STRING:
	case REP_PROTOCOL_TYPE_OPAQUE:
		return (t);

	case REP_PROTOCOL_SUBTYPE_USTRING:
		return (REP_PROTOCOL_TYPE_STRING);

	case REP_PROTOCOL_SUBTYPE_URI:
		return (REP_PROTOCOL_SUBTYPE_USTRING);
	case REP_PROTOCOL_SUBTYPE_FMRI:
		return (REP_PROTOCOL_SUBTYPE_URI);

	case REP_PROTOCOL_SUBTYPE_HOST:
		return (REP_PROTOCOL_SUBTYPE_USTRING);
	case REP_PROTOCOL_SUBTYPE_HOSTNAME:
		return (REP_PROTOCOL_SUBTYPE_HOST);
	case REP_PROTOCOL_SUBTYPE_NETADDR_V4:
		return (REP_PROTOCOL_SUBTYPE_HOST);
	case REP_PROTOCOL_SUBTYPE_NETADDR_V6:
		return (REP_PROTOCOL_SUBTYPE_HOST);

	case REP_PROTOCOL_TYPE_INVALID:
	default:
		return (REP_PROTOCOL_TYPE_INVALID);
	}
}

int
scf_is_compatible_type(rep_protocol_value_type_t base,
    rep_protocol_value_type_t new)
{
	rep_protocol_value_type_t t, cur;

	if (base == REP_PROTOCOL_TYPE_INVALID)
		return (0);

	if (base == new)
		return (1);

	for (t = new; t != (cur = scf_proto_underlying_type(t)); t = cur) {
		if (cur == REP_PROTOCOL_TYPE_INVALID)
			return (0);
		if (cur == base)
			return (1);		/* base is parent of new */
	}
	return (0);
}

static int
valid_encoded_value(rep_protocol_value_type_t t, const char *v)
{
	char *p;
	ulong_t ns;

	switch (t) {
	case REP_PROTOCOL_TYPE_BOOLEAN:
		return ((*v == '0' || *v == '1') && v[1] == 0);

	case REP_PROTOCOL_TYPE_COUNT:
		errno = 0;
		if (strtoull(v, &p, 10) != 0 && *v == '0')
			return (0);
		return (errno == 0 && p != v && *p == 0);

	case REP_PROTOCOL_TYPE_INTEGER:
		errno = 0;
		if (strtoll(v, &p, 10) != 0 && *v == '0')
			return (0);
		return (errno == 0 && p != v && *p == 0);

	case REP_PROTOCOL_TYPE_TIME:
		errno = 0;
		(void) strtoll(v, &p, 10);
		if (errno != 0 || p == v || (*p != 0 && *p != '.'))
			return (0);
		if (*p == '.') {
			v = p + 1;
			errno = 0;
			ns = strtoul(v, &p, 10);

			/* must be exactly 9 digits */
			if ((p - v) != 9 || errno != 0 || *p != 0)
				return (0);
			if (ns >= NANOSEC)
				return (0);
		}
		return (1);

	case REP_PROTOCOL_TYPE_STRING:
		return (valid_string(v));

	case REP_PROTOCOL_TYPE_OPAQUE:
		return (valid_opaque(v));

	/*
	 * The remaining types are subtypes -- because of the way
	 * scf_validate_encoded_value() works, we can rely on the fact
	 * that v is a valid example of our base type.  We only have to
	 * check our own additional restrictions.
	 */
	case REP_PROTOCOL_SUBTYPE_USTRING:
		return (valid_utf8(v));

	case REP_PROTOCOL_SUBTYPE_URI:
		return (valid_uri(v));

	case REP_PROTOCOL_SUBTYPE_FMRI:
		return (valid_fmri(v));

	case REP_PROTOCOL_SUBTYPE_HOST:
		return (valid_encoded_value(REP_PROTOCOL_SUBTYPE_HOSTNAME, v) ||
		    valid_encoded_value(REP_PROTOCOL_SUBTYPE_NETADDR_V4, v) ||
		    valid_encoded_value(REP_PROTOCOL_SUBTYPE_NETADDR_V6, v));

	case REP_PROTOCOL_SUBTYPE_HOSTNAME:
		/* XXX check for valid hostname */
		return (valid_utf8(v));

	case REP_PROTOCOL_SUBTYPE_NETADDR_V4:
	case REP_PROTOCOL_SUBTYPE_NETADDR_V6:
		/* XXX check for valid netaddr */
		return (valid_utf8(v));

	case REP_PROTOCOL_TYPE_INVALID:
	default:
		return (0);
	}
}

int
scf_validate_encoded_value(rep_protocol_value_type_t t, const char *v)
{
	rep_protocol_value_type_t base, cur;

	base = scf_proto_underlying_type(t);
	while ((cur = scf_proto_underlying_type(base)) != base)
		base = cur;

	if (base != t && !valid_encoded_value(base, v))
		return (0);

	return (valid_encoded_value(t, v));
}
