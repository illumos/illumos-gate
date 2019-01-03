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

#include <errno.h>
#include <libcustr.h>
#include <limits.h>
#include <string.h>
#include <sys/ctype.h>	/* We want the C locale ISXXX() versions */
#include <sys/debug.h>
#include <stdio.h>
#include <sys/sysmacros.h>

#include "strview.h"
#include "demangle_int.h"

/*
 * Unfortunately, there is currently no official specification for the rust
 * name mangling.  This is an attempt to document the understanding of the
 * mangling used here.  It is based off examination of
 *     https://docs.rs/rustc-demangle/0.1.13/rustc_demangle/
 *
 * A mangled rust name is:
 *     <prefix> <name> <hash> E
 *
 * <prefix>	::=	_Z
 *			__Z
 *
 * <name>	::= <name-segment>+
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
 * <special>	::=	$SP$	# ' '
 *			$BP$	# '*'
 *			$RF$	# '&'
 *			$LT$	# '<'
 *			$GT$	# '>'
 *			$LP$	# '('
 *			$RP$	# ')'
 *			$C$	# ','
 *			$u7e$	# '~'
 *			$u20$	# ' '
 *			$u27$	# '\''
 *			$u3d$	# '='
 *			$u5b$	# '['
 *			$u5d$	# ']'
 *			$u7b$	# '{'
 *			$u7d$	# '}'
 *			$u3b$	# ';'
 *			$u2b$	# '+'
 *			$u22$	# '"'
 *
 * <hash>	:= <len> h <hex-digits>+
 *
 * <hex-digits>	:= <[0-9a-f]>
 */

typedef struct rustdem_state {
	const char	*rds_str;
	custr_t		*rds_demangled;
	sysdem_ops_t	*rds_ops;
	int		rds_error;
} rustdem_state_t;

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
	{ "$u7e$", '~' },
	{ "$u20$", ' ' },
	{ "$u27$", '\'' },
	{ "$u3d$", '=' },
	{ "$u5b$", '[' },
	{ "$u5d$", ']' },
	{ "$u7b$", '{' },
	{ "$u7d$", '}' },
	{ "$u3b$", ';' },
	{ "$u2b$", '+' },
	{ "$u22$", '"' }
};
static const size_t rust_charmap_sz = ARRAY_SIZE(rust_charmap);

static void *rustdem_alloc(custr_alloc_t *, size_t);
static void rustdem_free(custr_alloc_t *, void *, size_t);

static boolean_t rustdem_append_c(rustdem_state_t *, char);
static boolean_t rustdem_all_ascii(const strview_t *);

static boolean_t rustdem_parse_prefix(rustdem_state_t *, strview_t *);
static boolean_t rustdem_parse_name(rustdem_state_t *, strview_t *);
static boolean_t rustdem_parse_hash(rustdem_state_t *, strview_t *);
static boolean_t rustdem_parse_num(rustdem_state_t *, strview_t *, uint64_t *);
static boolean_t rustdem_parse_special(rustdem_state_t *, strview_t *);
static boolean_t rustdem_add_sep(rustdem_state_t *);

char *
rust_demangle(const char *s, size_t slen, sysdem_ops_t *ops)
{
	rustdem_state_t st = {
		.rds_str = s,
		.rds_ops = ops,
	};
	custr_alloc_ops_t custr_ops = {
		.custr_ao_alloc = rustdem_alloc,
		.custr_ao_free = rustdem_free
	};
	custr_alloc_t custr_alloc = {
		.cua_version = CUSTR_VERSION
	};
	strview_t sv;
	int ret;

	if (custr_alloc_init(&custr_alloc, &custr_ops) != 0)
		return (NULL);
	custr_alloc.cua_arg = &st;

	sv_init_str(&sv, s, s + slen);

	if (sv_remaining(&sv) < 1 || sv_peek(&sv, -1) != 'E') {
		DEMDEBUG("ERROR: string is either too small or does not end "
		    "with 'E'");
		errno = EINVAL;
		return (NULL);
	}

	if (!rustdem_parse_prefix(&st, &sv)) {
		DEMDEBUG("ERROR: could not parse prefix");
		errno = EINVAL;
		return (NULL);
	}
	DEMDEBUG("parsed prefix; remaining='%.*s'", SV_PRINT(&sv));

	if (!rustdem_all_ascii(&sv)) {
		/* rustdem_all_ascii() provides debug output */
		errno = EINVAL;
		return (NULL);
	}

	if ((ret = custr_xalloc(&st.rds_demangled, &custr_alloc)) != 0)
		return (NULL);

	while (sv_remaining(&sv) > 1) {
		if (rustdem_parse_name(&st, &sv))
			continue;
		if (st.rds_error != 0)
			goto fail;
	}

	if (st.rds_error != 0 || !sv_consume_if_c(&sv, 'E'))
		goto fail;

	char *res = xstrdup(ops, custr_cstr(st.rds_demangled));
	if (res == NULL) {
		st.rds_error = errno;
		goto fail;
	}

	custr_free(st.rds_demangled);
	DEMDEBUG("result = '%s'", res);
	return (res);

fail:
	custr_free(st.rds_demangled);
	errno = st.rds_error;
	return (NULL);
}

static boolean_t
rustdem_parse_prefix(rustdem_state_t *st, strview_t *svp)
{
	strview_t pfx;

	sv_init_sv(&pfx, svp);

	DEMDEBUG("checking for '_ZN' or '__ZN' in '%.*s'", SV_PRINT(&pfx));

	if (st->rds_error != 0)
		return (B_FALSE);

	if (!sv_consume_if_c(&pfx, '_'))
		return (B_FALSE);

	(void) sv_consume_if_c(&pfx, '_');

	if (!sv_consume_if_c(&pfx, 'Z') || !sv_consume_if_c(&pfx, 'N'))
		return (B_FALSE);

	/* Update svp with new position */
	sv_init_sv(svp, &pfx);
	return (B_TRUE);
}

static boolean_t
rustdem_parse_name_segment(rustdem_state_t *st, strview_t *svp, boolean_t first)
{
	strview_t sv;
	strview_t name;
	uint64_t len;
	size_t rem;
	boolean_t last = B_FALSE;

	if (st->rds_error != 0 || sv_remaining(svp) == 0)
		return (B_FALSE);

	sv_init_sv(&sv, svp);

	if (!rustdem_parse_num(st, &sv, &len)) {
		DEMDEBUG("ERROR: no leading length");
		st->rds_error = EINVAL;
		return (B_FALSE);
	}

	rem = sv_remaining(&sv);

	if (rem < len || len > SIZE_MAX) {
		st->rds_error = EINVAL;
		return (B_FALSE);
	}

	/* Is this the last segment before the terminating E? */
	if (rem == len + 1) {
		VERIFY3U(sv_peek(&sv, -1), ==, 'E');
		last = B_TRUE;
	}

	if (!first && !rustdem_add_sep(st))
		return (B_FALSE);

	/* Reduce length of seg to the length we parsed */
	(void) sv_init_sv_range(&name, &sv, len);

	DEMDEBUG("%s: segment='%.*s'", __func__, SV_PRINT(&name));

	/*
	 * A rust hash starts with 'h', and is the last component of a name
	 * before the terminating 'E'
	 */
	if (sv_peek(&name, 0) == 'h' && last) {
		if (!rustdem_parse_hash(st, &name))
			return (B_FALSE);
		goto done;
	}

	while (sv_remaining(&name) > 0) {
		switch (sv_peek(&name, 0)) {
		case '$':
			if (rustdem_parse_special(st, &name))
				continue;
			break;
		case '_':
			if (sv_peek(&name, 1) == '$') {
				/*
				 * Only consume/ignore '_'.  Leave
				 * $ for next round.
				 */
				sv_consume_n(&name, 1);
				continue;
			}
			break;
		case '.':
			/* Convert '..' to '::' */
			if (sv_peek(&name, 1) != '.')
				break;

			if (!rustdem_add_sep(st))
				return (B_FALSE);

			sv_consume_n(&name, 2);
			continue;
		default:
			break;
		}

		if (custr_appendc(st->rds_demangled,
		    sv_consume_c(&name)) != 0) {
			st->rds_error = ENOMEM;
			return (B_FALSE);
		}
	}

done:
	DEMDEBUG("%s: consumed '%.*s'", __func__, (int)len, svp->sv_first);
	sv_consume_n(&sv, len);
	sv_init_sv(svp, &sv);
	return (B_TRUE);
}

static boolean_t
rustdem_parse_name(rustdem_state_t *st, strview_t *svp)
{
	strview_t name;
	boolean_t first = B_TRUE;

	if (st->rds_error != 0)
		return (B_FALSE);

	sv_init_sv(&name, svp);

	if (sv_remaining(&name) == 0)
		return (B_FALSE);

	while (sv_remaining(&name) > 0 && sv_peek(&name, 0) != 'E') {
		if (!rustdem_parse_name_segment(st, &name, first))
			return (B_FALSE);
		first = B_FALSE;
	}

	sv_init_sv(svp, &name);
	return (B_TRUE);
}

static boolean_t
rustdem_parse_hash(rustdem_state_t *st, strview_t *svp)
{
	strview_t sv;

	sv_init_sv(&sv, svp);

	VERIFY(sv_consume_if_c(&sv, 'h'));
	if (!rustdem_append_c(st, 'h'))
		return (B_FALSE);

	while (sv_remaining(&sv) > 0) {
		char c = sv_consume_c(&sv);

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
			if (!rustdem_append_c(st, c))
				return (B_FALSE);
			break;
		default:
			return (B_FALSE);
		}
	}

	sv_init_sv(svp, &sv);
	return (B_TRUE);
}

/*
 * A 10 digit value would imply a name 1Gb or larger in size.  It seems
 * unlikely to the point of absurdity any such value could every possibly
 * be valid (or even have compiled properly).  This also prevents the
 * uint64_t conversion from possibly overflowing since the value must always
 * be below 10 * UINT32_MAX.
 */
#define	MAX_DIGITS 10

static boolean_t
rustdem_parse_num(rustdem_state_t *restrict st, strview_t *restrict svp,
    uint64_t *restrict valp)
{
	strview_t snum;
	uint64_t v = 0;
	size_t ndigits = 0;
	char c;

	if (st->rds_error != 0)
		return (B_FALSE);

	sv_init_sv(&snum, svp);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(&snum));

	c = sv_peek(&snum, 0);
	if (!ISDIGIT(c)) {
		DEMDEBUG("%s: ERROR no digits in str\n", __func__);
		st->rds_error = EINVAL;
		return (B_FALSE);
	}

	/*
	 * Since there is currently no official specification on rust name
	 * mangling, only that it has been stated that rust follows what
	 * C++ mangling does.  In the Itanium C++ ABI (what practically
	 * every non-Windows C++ implementation uses these days), it
	 * explicitly disallows leading 0s in numeric values (except for
	 * substition and template indexes, which aren't relevant here).
	 * We enforce the same restriction -- if a rust implementation allowed
	 * leading zeros in numbers (basically segment lengths) it'd
	 * cause all sorts of ambiguity problems with names that likely lead
	 * to much bigger problems with linking and such, so this seems
	 * reasonable.
	 */
	if (c == '0') {
		DEMDEBUG("%s: ERROR number starts with leading 0\n", __func__);
		st->rds_error = EINVAL;
		return (B_FALSE);
	}

	while (sv_remaining(&snum) > 0 && ndigits <= MAX_DIGITS) {
		c = sv_consume_c(&snum);

		if (!ISDIGIT(c))
			break;

		v *= 10;
		v += c - '0';
		ndigits++;
	}

	if (ndigits > MAX_DIGITS) {
		DEMDEBUG("%s: value %llu is too large\n", __func__, v);
		st->rds_error = ERANGE;
		return (B_FALSE);
	}

	DEMDEBUG("%s: num=%llu", __func__, v);

	*valp = v;
	sv_consume_n(svp, ndigits);
	return (B_TRUE);
}

static boolean_t
rustdem_parse_special(rustdem_state_t *restrict st, strview_t *restrict svp)
{
	if (st->rds_error != 0)
		return (B_FALSE);

	if (sv_peek(svp, 0) != '$')
		return (B_FALSE);

	for (size_t i = 0; i < rust_charmap_sz; i++) {
		if (sv_consume_if(svp, rust_charmap[i].ruc_seq)) {
			if (!rustdem_append_c(st, rust_charmap[i].ruc_ch))
				return (B_FALSE);
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
rustdem_add_sep(rustdem_state_t *st)
{
	if (st->rds_error != 0)
		return (B_FALSE);

	if (!rustdem_append_c(st, ':') ||
	    !rustdem_append_c(st, ':'))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
rustdem_append_c(rustdem_state_t *st, char c)
{
	if (st->rds_error != 0)
		return (B_FALSE);

	if (custr_appendc(st->rds_demangled, c) == 0)
		return (B_TRUE);

	st->rds_error = errno;
	return (B_FALSE);
}

static boolean_t
rustdem_all_ascii(const strview_t *svp)
{
	strview_t p;

	sv_init_sv(&p, svp);

	while (sv_remaining(&p) > 0) {
		char c = sv_consume_c(&p);

		/*
		 * #including <sys/ctype.h> conflicts with <ctype.h>.  Since
		 * we want the C locale macros (ISDIGIT, etc), it also means
		 * we can't use isascii(3C).
		 */
		if ((c & 0x80) != 0) {
			DEMDEBUG("%s: found non-ascii character 0x%02hhx at "
			    "offset %tu", __func__, c,
			    (ptrdiff_t)(p.sv_first - svp->sv_first));
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static void *
rustdem_alloc(custr_alloc_t *cao, size_t len)
{
	rustdem_state_t *st = cao->cua_arg;
	return (zalloc(st->rds_ops, len));
}

static void
rustdem_free(custr_alloc_t *cao, void *p, size_t len)
{
	rustdem_state_t *st = cao->cua_arg;
	xfree(st->rds_ops, p, len);
}
