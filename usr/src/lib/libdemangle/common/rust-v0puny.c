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

#include <inttypes.h>
#include <libcustr.h>
#include <limits.h>
#include <string.h>
#include <sys/byteorder.h>
#include "rust.h"
#include "strview.h"

/*
 * The rust v0 encoding (rust RFC 2603) uses a slightly modified
 * version of punycode to encode characters that are not ASCII.
 * The big difference is that '_' is used to separate the ASCII codepoints
 * from the non-ASCII code points instead of '-'.
 *
 * The decoding is taken almost directly from (IETF) RFC 3492
 */

#define	BASE		36
#define	TMIN		1
#define	TMAX		26
#define	SKEW		38
#define	DAMP		700
#define	INITIAL_BIAS	72
#define	INITIAL_N	0x80
#define	DELIMITER	'_'

static inline uint32_t char_val(char);

static size_t
rustv0_puny_adapt(size_t delta, size_t npoints, boolean_t first)
{
	size_t k = 0;

	delta = first ? delta / DAMP : delta / 2;
	delta += delta / npoints;
	while (delta > ((BASE - TMIN) * TMAX) / 2) {
		delta /= (BASE - TMIN);
		k += BASE;
	}

	return (k + (((BASE - TMIN + 1) * delta) / (delta + SKEW)));
}

boolean_t
rustv0_puny_decode(rust_state_t *restrict st, strview_t *restrict src,
    boolean_t repl_underscore)
{
	uint32_t *buf;
	size_t bufalloc; /* in units of uint32_t */
	size_t buflen;
	size_t nbasic;
	size_t i, old_i, k, w;
	size_t n = INITIAL_N;
	size_t bias = INITIAL_BIAS;
	size_t delim_idx = 0;
	boolean_t ret = B_FALSE;
	char c;

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(src));

	/*
	 * The decoded string should never contain more codepoints than
	 * the original string, so creating a temporary buffer large
	 * enought to hold sv_remaining(src) uint32_t's should be
	 * large enough.
	 *
	 * This also serves as a size check -- xcalloc will fail if the
	 * resulting size of the buf (sizeof (uint32_t) * bufalloc) >=
	 * SIZE_MAX. If xcalloc succeeds, we therefore know that that
	 * buflen cannot overflow.
	 */
	buflen = 0;
	bufalloc = sv_remaining(src) + 1;
	buf = xcalloc(st->rs_ops, bufalloc, sizeof (uint32_t));
	if (buf == NULL) {
		SET_ERROR(st);
		return (B_FALSE);
	}

	/*
	 * Find the position of the last delimiter (if any).
	 * IETF RFC 3492 3.1 states that the delimiter is present if and only
	 * if there are a non-zero number of basic (ASCII) code points. Since
	 * the delimiter itself is a basic code point, the last one present
	 * in the original string is the actual delimiter between the basic
	 * and non-basic code points. Earlier occurences of the delimiter
	 * are treated as normal basic code points. For plain punycode, an
	 * all ASCII string encoded with punycode would terminate with a
	 * final delimiter, and a name with all non-basic code points would
	 * not have a delimiter at all. With the rust v0 encoding, punycode
	 * encoded identifiers have a 'u' prefix prior to the identifier
	 * length (['u'] <decimal-number> <bytes>), so we should never
	 * encounter an all ASCII name that's encoded with punycode (we error
	 * on this).  For an all non-basic codepoint identifier, no delimiter
	 * will be present, and we treat that the same as the delimiter being
	 * in the first position of the string, and consume it (if present)
	 * when we transition from copying the basic code points (which there
	 * will be none in this situation) to non-basic code points.
	 */
	for (i = 0; i < src->sv_rem; i++) {
		if (src->sv_first[i] == DELIMITER) {
			delim_idx = i;
		}
	}
	VERIFY3U(delim_idx, <, bufalloc);

	if (delim_idx + 1 == sv_remaining(src)) {
		DEMDEBUG("%s: encountered an all-ASCII name encoded with "
		    "punycode", __func__);
		goto done;
	}

	/* Copy all the basic characters up to the delimiter into buf */
	for (nbasic = 0; nbasic < delim_idx; nbasic++) {
		c = sv_consume_c(src);

		/* The rust prefix check should guarantee this */
		VERIFY3U(c, <, 0x80);

		/*
		 * Normal rust identifiers do not contain '-' in them.
		 * However ABI identifiers could contain a dash. Those
		 * are translated to _, and we need to replace accordingly
		 * when asked.
		 */
		if (repl_underscore && c == '_')
			c = '-';

		buf[nbasic] = c;
		buflen++;
	}
	DEMDEBUG("%s: %" PRIu32 " ASCII codepoints copied", __func__, nbasic);

	/*
	 * Consume delimiter between basic and non-basic code points if present.
	 * See above for explanation why it may not be present.
	 */
	(void) sv_consume_if_c(src, DELIMITER);

	DEMDEBUG("%s: non-ASCII codepoints to decode: %.*s", __func__,
	    SV_PRINT(src));

	for (i = 0; sv_remaining(src) > 0; i++) {
		VERIFY3U(i, <=, buflen);

		/*
		 * Guarantee we have enough space to insert another codepoint.
		 * Our buffer sizing above should prevent this from ever
		 * tripping, but check this out of paranoia.
		 */
		VERIFY3U(buflen, <, bufalloc - 1);

		/* decode the next codepoint */
		for (old_i = i, k = BASE, w = 1; ; k += BASE) {
			size_t t;
			uint32_t digit;

			if (sv_remaining(src) == 0)
				goto done;

			digit = char_val(sv_consume_c(src));
			if (digit >= BASE)
				goto done;

			i = i + digit * w;

			if (k <= bias)
				t = TMIN;
			else if (k >= bias + TMAX)
				t = TMAX;
			else
				t = k - bias;

			if (digit < t)
				break;

			w = w * (BASE - t);
		}
		buflen++;

		bias = rustv0_puny_adapt(i - old_i, buflen,
		    (old_i == 0) ? B_TRUE : B_FALSE);
		n = n + i / buflen;
		i = i % buflen;

		DEMDEBUG("%s: insert \\u%04" PRIx32 " at index %zu (len = %zu)",
		    __func__, n, i, buflen);

		/*
		 * At the start of this while loop, we guaranteed
		 * buflen < bufalloc - 1. Therefore we know there is room
		 * to move over the contents of buf at i to make room
		 * for the codepoint. We also just guaranteed that i
		 * is in the range [0, buflen), so this should always be
		 * safe.
		 */
		(void) memmove(buf + i + 1, buf + i,
		    (buflen - i) * sizeof (uint32_t));

#if _LP64
		/*
		 * This is always false for ILP32 and smatch will also complain,
		 * so we just omit it for ILP32.
		 */
		if (n > UINT32_MAX) {
			DEMDEBUG("%s: ERROR: utf8 value is out of range",
			    __func__);
			goto done;
		}
#endif

		buf[i] = (uint32_t)n;
	}

	DEMDEBUG("%s: inserted %zu non-basic code points", __func__,
	    buflen - nbasic);

	for (i = 0; i < buflen; i++) {
		if (!rust_append_utf8_c(st, buf[i]))
			goto done;
	}
	ret = B_TRUE;

done:
	xfree(st->rs_ops, buf, bufalloc * sizeof (uint32_t));
	return (ret);
}

/*
 * Convert [0-9][a-z] to a value [0..35]. Rust's punycode encoding always
 * uses lowercase, so we treat uppercase (and any other characters) as
 * invalid, and return BASE (36) to indicate a bad value.
 */
static inline uint32_t
char_val(char c)
{
	uint32_t v = c;

	if (ISLOWER(c)) {
		return (c - 'a');
	} else if (ISDIGIT(c)) {
		return (c - '0' + 26);
	} else {
		DEMDEBUG("%s: ERROR: invalid character 0x%02x encountered",
		    __func__, v);
		return (BASE);
	}
}
