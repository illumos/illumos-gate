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
 * Copyright 2021 Jason King
 * Copyright 2019 Joyent, Inc.
 */

#include <errno.h>
#include <langinfo.h>
#include <libcustr.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>

#include "demangle_int.h"
#include "rust.h"

static void *
rust_cualloc(custr_alloc_t *cua, size_t len)
{
	rust_state_t *st = cua->cua_arg;
	return (zalloc(st->rs_ops, len));
}

static void
rust_cufree(custr_alloc_t *cua, void *p, size_t len)
{
	rust_state_t *st = cua->cua_arg;
	xfree(st->rs_ops, p, len);
}

static const custr_alloc_ops_t rust_custr_ops = {
	.custr_ao_alloc = rust_cualloc,
	.custr_ao_free = rust_cufree
};

boolean_t
rust_appendc(rust_state_t *st, char c)
{
	custr_t *cus = st->rs_demangled;

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (st->rs_skip)
		return (B_TRUE);

	switch (c) {
	case '\a':
		return (rust_append(st, "\\a"));
	case '\b':
		return (rust_append(st, "\\b"));
	case '\f':
		return (rust_append(st, "\\f"));
	case '\n':
		return (rust_append(st, "\\n"));
	case '\r':
		return (rust_append(st, "\\r"));
	case '\t':
		return (rust_append(st, "\\t"));
	case '\v':
		return (rust_append(st, "\\v"));
	case '\\':
		return (rust_append(st, "\\\\"));
	}

	if (c < ' ')
		return (rust_append_printf(st, "\\x%02" PRIx8, (uint8_t)c));

	if (custr_appendc(cus, c) != 0) {
		SET_ERROR(st);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Append a UTF-8 code point. If we're not in a UTF-8 locale, this gets
 * appended as '\u<hex codepoint>' otherwise the character itself is
 * added.
 */
boolean_t
rust_append_utf8_c(rust_state_t *st, uint32_t val)
{
	custr_t *cus = st->rs_demangled;
	uint_t n = 0;
	uint8_t c[4] = { 0 };

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (!st->rs_isutf8) {
		if (val < 0x80)
			return (rust_appendc(st, (char)val));
		if (val < 0x10000)
			return (rust_append_printf(st, "\\u%04" PRIx32, val));
		return (rust_append_printf(st, "\\U%08" PRIx32, val));
	}

	if (val < 0x80) {
		return (rust_appendc(st, (char)val));
	} else if (val < 0x800) {
		c[0] = 0xc0 | ((val >> 6) & 0x1f);
		c[1] = 0x80 | (val & 0x3f);
		n = 2;
	} else if (val < 0x10000) {
		c[0] = 0xe0 | ((val >> 12) & 0x0f);
		c[1] = 0x80 | ((val >> 6) & 0x3f);
		c[2] = 0x80 | (val & 0x3f);
		n = 3;
	} else if (val < 0x110000) {
		c[0] = 0xf0 | ((val >> 18) & 0x7);
		c[1] = 0x80 | ((val >> 12) & 0x3f);
		c[2] = 0x80 | ((val >> 6) & 0x3f);
		c[3] = 0x80 | (val & 0x3f);
		n = 4;
	} else {
		DEMDEBUG("%s: invalid unicode character \\u%" PRIx32, __func__,
		    val);
		return (B_FALSE);
	}

	for (uint_t i = 0; i < n; i++) {
		if (custr_appendc(cus, c[i]) != 0) {
			SET_ERROR(st);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

boolean_t
rust_append(rust_state_t *st, const char *s)
{
	custr_t *cus = st->rs_demangled;

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (st->rs_skip)
		return (B_TRUE);

	if (custr_append(cus, s) != 0) {
		SET_ERROR(st);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
rust_append_sv(rust_state_t *restrict st, uint64_t n, strview_t *restrict sv)
{
	if (HAS_ERROR(st))
		return (B_FALSE);

	if (st->rs_skip) {
		sv_consume_n(sv, (size_t)n);
		return (B_TRUE);
	}

	if (n > sv_remaining(sv)) {
		DEMDEBUG("%s: ERROR amount to append (%" PRIu64 ") > "
		    "remaining bytes (%zu)", __func__, n, sv_remaining(sv));
		st->rs_error = ERANGE;
		return (B_FALSE);
	}

	if (n > INT_MAX) {
		DEMDEBUG("%s: amount (%" PRIu64 ") > INT_MAX", __func__, n);
		st->rs_error = ERANGE;
		return (B_FALSE);
	}

	if (custr_append_printf(st->rs_demangled, "%.*s",
	    (int)n, sv->sv_first) != 0) {
		SET_ERROR(st);
		return (B_FALSE);
	}
	sv_consume_n(sv, (size_t)n);

	return (B_TRUE);
}

boolean_t
rust_append_printf(rust_state_t *st, const char *fmt, ...)
{
	va_list ap;
	int ret;

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (st->rs_skip)
		return (B_TRUE);

	va_start(ap, fmt);
	ret = custr_append_vprintf(st->rs_demangled, fmt, ap);
	va_end(ap);

	if (ret == 0)
		return (B_TRUE);
	SET_ERROR(st);
	return (B_FALSE);
}

boolean_t
rust_parse_base10(rust_state_t *restrict st, strview_t *restrict sv,
    uint64_t *restrict valp)
{
	uint64_t v = 0;
	char c;

	if (HAS_ERROR(st) || sv_remaining(sv) == 0)
		return (B_FALSE);

	c = sv_peek(sv, 0);

	/*
	 * Since the legacy rust encoding states that it follows the
	 * Itanium C++ mangling format, we match the behavior of the
	 * Itanium C++ ABI in disallowing leading 0s in decimal numbers.
	 *
	 * For Rust encoding v0, RFC2603 currently has omitted the
	 * actual definition of <decimal-number>. However examination of
	 * other implementations written in tandem with the mangling
	 * implementation suggest that <decimal-number> can be expressed
	 * by the eregex: 0|[1-9][0-9]* -- that is a '0' is allowed and
	 * terminates the token, while any other leading digit allows
	 * parsing to continue until a non-digit is encountered, the
	 * end of the string is encountered, or overflow is encountered.
	 */
	if (c == '0') {
		if (st->rs_encver == RUSTENC_V0) {
			sv_consume_n(sv, 1);
			*valp = 0;
			return (B_TRUE);
		}

		DEMDEBUG("%s: ERROR number starts with leading 0\n",
		    __func__);
		st->rs_error = EINVAL;
		return (B_FALSE);
	} else if (!ISDIGIT(c)) {
		return (B_FALSE);
	}

	while (sv_remaining(sv) > 0) {
		uint64_t cval;

		c = sv_peek(sv, 0);
		if (!ISDIGIT(c))
			break;
		sv_consume_n(sv, 1);

		cval = c - '0';

		if (mul_overflow(v, 10, &v)) {
			DEMDEBUG("%s: multiplication overflowed\n", __func__);
			st->rs_error = EOVERFLOW;
			return (B_FALSE);
		}

		if (add_overflow(v, cval, &v)) {
			DEMDEBUG("%s: addition overflowed\n", __func__);
			st->rs_error = EOVERFLOW;
			return (B_FALSE);
		}
	}

	*valp = v;
	return (B_TRUE);
}

static boolean_t
rust_parse_prefix(rust_state_t *restrict st, strview_t *restrict sv)
{
	DEMDEBUG("checking prefix in '%.*s'", SV_PRINT(sv));

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (!sv_consume_if_c(sv, '_'))
		return (B_FALSE);

	/*
	 * MacOS prepends an additional '_' -- allow that in case
	 * we're given symbols from a MacOS object.
	 */
	(void) sv_consume_if_c(sv, '_');

	if (sv_consume_if_c(sv, 'Z')) {
		/*
		 * Legacy names must start with '[_]_Z'
		 */
		st->rs_encver = RUSTENC_LEGACY;
		DEMDEBUG("name is encoded using the rust legacy mangling "
		    "scheme");
	} else if (sv_consume_if_c(sv, 'R')) {
		uint64_t ver = 0;

		/*
		 * The non-legacy encoding is versioned. After the initial
		 * 'R' is the version. This isn't spelled out clearly in the
		 * RFC, but many numeric values encoded take an approach of
		 * a value of 0 is omitted, and any digits represent the
		 * value - 1. In other words, in this case, no digits means
		 * version 0, '_R0...' would be version 1, 'R1...' would
		 * be version 2, etc. Currently only version 0 is defined,
		 * but we try to provide a (hopefully) useful message
		 * when debugging, even if we can't use the version value
		 * beyond that.
		 */
		if (rust_parse_base10(st, sv, &ver)) {
			DEMDEBUG("%s: ERROR: an unsupported encoding version "
			    "(%" PRIu64 ") was encountered", ver + 1);
			st->rs_error = ENOTSUP;
			return (B_FALSE);
		}

		st->rs_encver = RUSTENC_V0;
		DEMDEBUG("name is encoded using the v0 mangling scheme");
	} else {
		DEMDEBUG("did not find a valid rust prefix");
		return (B_FALSE);
	}

	sv_init_sv(&st->rs_orig, sv);
	return (B_TRUE);
}

static void
rust_fini_state(rust_state_t *st)
{
	custr_free(st->rs_demangled);
	custr_alloc_fini(&st->rs_cualloc);
}

static boolean_t
rust_init_state(rust_state_t *restrict st, const char *s, sysdem_ops_t *ops)
{
	const char *codeset;

	(void) memset(st, 0, sizeof (*st));

	st->rs_str = s;
	st->rs_ops = ops;

	st->rs_cualloc.cua_version = CUSTR_VERSION;
	if (custr_alloc_init(&st->rs_cualloc, &rust_custr_ops) != 0)
		return (B_FALSE);
	st->rs_cualloc.cua_arg = st;

	if (custr_xalloc(&st->rs_demangled, &st->rs_cualloc) != 0) {
		custr_alloc_fini(&st->rs_cualloc);
		return (B_FALSE);
	}

	codeset = nl_langinfo(CODESET);
	if (codeset != NULL && strcmp(codeset, "UTF-8") == 0)
		st->rs_isutf8 = B_TRUE;

	return (B_TRUE);
}

char *
rust_demangle(const char *s, size_t len, sysdem_ops_t *ops)
{
	rust_state_t st;
	strview_t sv = { 0 };
	boolean_t success = B_FALSE;
	int e = 0;
	char *out = NULL;

	if (!rust_init_state(&st, s, ops))
		return (NULL);

	sv_init_str(&sv, s, s + len);

	if (!rust_parse_prefix(&st, &sv)) {
		if (st.rs_error == 0)
			st.rs_error = EINVAL;
		goto done;
	}

	DEMDEBUG("parsed prefix; remaining string='%.*s'", SV_PRINT(&sv));

	switch (st.rs_encver) {
	case RUSTENC_LEGACY:
		success = rust_demangle_legacy(&st, &sv);
		break;
	case RUSTENC_V0:
		success = rust_demangle_v0(&st, &sv);
		break;
	}

done:
	if (success) {
		out = xstrdup(ops, custr_cstr(st.rs_demangled));
		if (out == NULL)
			SET_ERROR(&st);
	} else {
		DEMDEBUG("%s: failed, str='%s'", __func__,
		    custr_cstr(st.rs_demangled));

		st.rs_error = EINVAL;
	}

	e = st.rs_error;
	rust_fini_state(&st);
	if (e > 0)
		errno = e;

	return (out);
}
