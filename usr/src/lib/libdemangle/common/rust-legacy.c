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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Jason King
 */

#include <errno.h>
#include <libcustr.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "rust.h"

/*
 * Unfortunately, there is currently no official specification for the legacy
 * rust name mangling.  This is an attempt to document the understanding of the
 * mangling used here.  It is based off examination of
 *     https://docs.rs/rustc-demangle/0.1.13/rustc_demangle/
 *
 * A mangled rust name is:
 *     <prefix> <name>
 *
 * <prefix>	::=	_Z
 *			__Z
 *
 * <name>	::= N <name-segment>+ [<hash>] E
 *
 * <name-segment> ::= <len> <name-chars>{len}
 *
 * <len>	::= [1-9][0-9]+
 *
 * <name-chars>	::=	<[A-Za-z]> <[A-Za-z0-9]>*
 *			<separator>
 *			<special>
 *
 * <separator>	::=	'..'	# '::'
 *
 * <special>	::=	$SP$	# '@'
 *			$BP$	# '*'
 *			$RF$	# '&'
 *			$LT$	# '<'
 *			$GT$	# '>'
 *			$LP$	# '('
 *			$RP$	# ')'
 *			$C$	# ','
 *
 * <hash>	:= <len> h <hex-digits>+
 *
 * <hex-digits>	:= <[0-9a-f]>
 */

static const struct rust_charmap {
	const char	*ruc_seq;
	char		ruc_ch;
} rust_charmap[] = {
	{ "$SP$", '@' },
	{ "$BP$", '*' },
	{ "$RF$", '&' },
	{ "$LT$", '<' },
	{ "$GT$", '>' },
	{ "$LP$", '(' },
	{ "$RP$", ')' },
	{ "$C$", ',' },
};
static const size_t rust_charmap_sz = ARRAY_SIZE(rust_charmap);

static boolean_t rustleg_valid_sym(const strview_t *);
static boolean_t rustleg_parse_name(rust_state_t *, strview_t *);
static boolean_t rustleg_parse_hash(rust_state_t *, strview_t *);
static boolean_t rustleg_parse_special(rust_state_t *, strview_t *);
static boolean_t rustleg_add_sep(rust_state_t *);

boolean_t
rust_demangle_legacy(rust_state_t *restrict st, strview_t *restrict sv)
{

	/* Make sure the whole thing contains valid characters */
	if (!rustleg_valid_sym(sv)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	if (sv_peek(sv, -1) != 'E') {
		DEMDEBUG("ERROR: string does not end with 'E'");
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	if (!rustleg_parse_name(st, sv))
		return (B_FALSE);

	if (sv_remaining(sv) != 0) {
		DEMDEBUG("ERROR: trailing characters in name");
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
rustleg_parse_name_segment(rust_state_t *st, strview_t *svp, boolean_t first)
{
	strview_t orig;
	strview_t name;
	uint64_t len;
	size_t rem;
	boolean_t last = B_FALSE;

	if (HAS_ERROR(st) || sv_remaining(svp) == 0)
		return (B_FALSE);

	sv_init_sv(&orig, svp);

	if (!rust_parse_base10(st, svp, &len)) {
		DEMDEBUG("ERROR: no leading length");
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	rem = sv_remaining(svp);

	if (rem < len) {
		DEMDEBUG("ERROR: segment length (%" PRIu64 ") > remaining "
		    "bytes in string (%zu)", len, rem);
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	/* Is this the last segment before the terminating E? */
	if (rem == len + 1) {
		VERIFY3U(sv_peek(svp, -1), ==, 'E');
		last = B_TRUE;
	}

	if (!first && !rustleg_add_sep(st))
		return (B_FALSE);

	/* Reduce length of seg to the length we parsed */
	(void) sv_init_sv_range(&name, svp, len);

	DEMDEBUG("%s: segment='%.*s'", __func__, SV_PRINT(&name));

	/*
	 * A rust hash starts with 'h', and is the last component of a name
	 * before the terminating 'E'. It is however not always present
	 * in every mangled symbol, and a last segment that starts with 'h'
	 * could be confused for it, so failing to part it just means
	 * we don't have a trailing hash.
	 */
	if (sv_peek(&name, 0) == 'h' && last) {
		if (rustleg_parse_hash(st, &name))
			goto done;

		/*
		 * However any error other than 'not a hash' (e.g. ENOMEM)
		 * means we should fail.
		 */
		if (st->rs_error != 0)
			goto done;
	}

	/* A '_' followed by $ is ignored at the start of a name segment */
	if (sv_peek(&name, 0) == '_' && sv_peek(&name, 1) == '$')
		(void) sv_consume_n(&name, 1);

	while (sv_remaining(&name) > 0) {
		switch (sv_peek(&name, 0)) {
		case '$':
			if (rustleg_parse_special(st, &name))
				continue;
			break;
		case '.':
			/* Convert '..' to '::' */
			if (sv_peek(&name, 1) != '.')
				break;

			if (!rustleg_add_sep(st))
				return (B_FALSE);

			sv_consume_n(&name, 2);
			continue;
		default:
			break;
		}

		if (!rust_appendc(st, sv_consume_c(&name))) {
			SET_ERROR(st);
			return (B_FALSE);
		}
	}

done:
	sv_consume_n(svp, len);

	VERIFY3P(orig.sv_first, <=, svp->sv_first);
	DEMDEBUG("%s: consumed '%.*s'", __func__,
	    (int)(uintptr_t)(svp->sv_first - orig.sv_first), orig.sv_first);
	return (B_TRUE);
}

/*
 * Parse N (<num><name>{num})+ [<num>h<hex digits]E
 */
static boolean_t
rustleg_parse_name(rust_state_t *st, strview_t *svp)
{
	strview_t name;
	boolean_t first = B_TRUE;

	sv_init_sv(&name, svp);

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: name = '%.*s'", __func__, SV_PRINT(&name));

	if (sv_remaining(svp) == 0) {
		DEMDEBUG("%s: empty name", __func__);
		return (B_FALSE);
	}

	if (!sv_consume_if_c(svp, 'N')) {
		DEMDEBUG("%s: does not start with 'N'", __func__);
		return (B_FALSE);
	}

	while (sv_remaining(svp) > 0 && sv_peek(svp, 0) != 'E') {
		if (!rustleg_parse_name_segment(st, svp, first))
			return (B_FALSE);
		first = B_FALSE;
	}

	if (!sv_consume_if_c(svp, 'E')) {
		DEMDEBUG("%s: ERROR no terminating 'E'", __func__);
		return (B_FALSE);
	}

	VERIFY3P(name.sv_first, <=, svp->sv_first);
	DEMDEBUG("%s: consumed '%.*s'", __func__,
	    (int)(uintptr_t)(svp->sv_first - name.sv_first), name.sv_first);

	return (B_TRUE);
}

static boolean_t
rustleg_parse_hash(rust_state_t *st, strview_t *svp)
{
	if (HAS_ERROR(st))
		return (B_FALSE);

	VERIFY(sv_consume_if_c(svp, 'h'));
	if (!rust_appendc(st, 'h'))
		return (B_FALSE);

	while (sv_remaining(svp) > 0) {
		char c = sv_consume_c(svp);

		switch (c) {
		/*
		 * The upper-case hex digits (A-F) are excluded as valid
		 * hash values for several reasons:
		 *
		 * 1. It would result in two different possible names for
		 * the same function, leading to ambiguity in linking (among
		 * other things).
		 *
		 * 2. It would cause potential ambiguity in parsing -- is a
		 * trailing 'E' part of the hash, or the terminating character
		 * in the mangled name?
		 *
		 * 3. No examples were able to be found in the wild where
		 * uppercase digits are used, and other rust demanglers all
		 * seem to assume the hash must contain lower-case hex digits.
		 */
		case '0': case '1': case '2': case '3':
		case '4': case '5': case '6': case '7':
		case '8': case '9': case 'a': case 'b':
		case 'c': case 'd': case 'e': case 'f':
			if (!rust_appendc(st, c))
				return (B_FALSE);
			break;
		default:
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
rustleg_parse_special(rust_state_t *restrict st, strview_t *restrict svp)
{
	if (HAS_ERROR(st))
		return (B_FALSE);

	if (sv_peek(svp, 0) != '$')
		return (B_FALSE);

	for (size_t i = 0; i < rust_charmap_sz; i++) {
		if (sv_consume_if(svp, rust_charmap[i].ruc_seq)) {
			if (!rust_appendc(st, rust_charmap[i].ruc_ch))
				return (B_FALSE);
			return (B_TRUE);
		}
	}

	/* Handle $uXXXX$ */

	strview_t sv;
	uint32_t val = 0;
	uint_t ndigits = 0;

	sv_init_sv(&sv, svp);

	/* We peeked at this earlier, so it should still be there */
	VERIFY(sv_consume_if_c(&sv, '$'));

	if (!sv_consume_if_c(&sv, 'u'))
		return (B_FALSE);

	while (sv_remaining(&sv) > 0) {
		uint32_t cval = 0;
		char c;

		if (ndigits == 4)
			return (B_FALSE);

		c = sv_consume_c(&sv);
		if (c >= '0' && c <= '9')
			cval = c - '0';
		else if (c >= 'a' && c <= 'f')
			cval = c - 'a' + 10;
		else if (c == '$')
			break;
		else
			return (B_FALSE);

		val <<= 4;
		val |= cval;
		ndigits++;
	}

	if (!rust_append_utf8_c(st, val))
		return (B_FALSE);

	sv_consume_n(svp, ndigits + 3);
	return (B_TRUE);
}

static boolean_t
rustleg_add_sep(rust_state_t *st)
{
	if (HAS_ERROR(st))
		return (B_FALSE);

	return (rust_append(st, "::"));
}

static boolean_t
rustleg_valid_sym(const strview_t *sv)
{
	size_t i;

	for (i = 0; i < sv->sv_rem; i++) {
		char c = sv->sv_first[i];

		if ((c & 0x80) == 0)
			continue;
		DEMDEBUG("%s: ERROR found 8-bit character '%c' in '%.*s' "
		    "at index %zu", __func__, c, SV_PRINT(sv), i);
		return (B_FALSE);
	}
	return (B_TRUE);
}
