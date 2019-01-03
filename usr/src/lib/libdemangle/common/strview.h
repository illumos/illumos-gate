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

#ifndef _STRVIEW_H
#define	_STRVIEW_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * strview_t's represent a read-only subset of a string.  It is somewhat
 * similar to the concept of ranges found in other languages in that one can
 * create a strview_t, and then create a smaller range for iteration.
 *
 * sv_first is the address of the first location (and is advanced as values
 * are consumed) in the string.
 *
 * sv_last is the address one byte after the last valid value of the subset.
 * Basically, the length of the range is equal to 'sv_last - sv_first'.  For
 * example, in the string 'abcdef' to create a view 'bcd', *sv_first would
 * equal 'b' and *sv_last would equal 'e'.
 *
 * sv_rem is the number of bytes remaining in the range.
 *
 * A strview_t maintains references to the underlying string, so the lifetime
 * of a strview_t should be equal to or less than the underlying string (i.e.
 * it doesn't copy the data from the underlying string, but maintains pointers
 * to the original data).
 *
 * While the underlying string does not need to be NUL-terminated, NUL is still
 * used as a sentinel value in some instances (e.g. sv_peek()), and should not
 * be contained within the defined range.
 *
 * As hinted above, the functions currently do not deal with multi-byte
 * characters, i.e. each character is assumed to be a single byte.  The
 * current consumers do not need to handle multi-byte characters (UTF-8
 * or otherwise), so this is sufficient at the current time.
 */
typedef struct strview {
	const char *sv_first;
	const char *sv_last;
	size_t sv_rem;
} strview_t;

/*
 * SV_PRINT() is used for printing strview_t values during debugging, e.g.
 * `DEMDEBUG("%*.s", SV_PRINT(sv));`
 */
#define	SV_PRINT(_sv)	(int)(_sv)->sv_rem, (_sv)->sv_first

/*
 * Initialize a strview_t from an already initialized strview_t -- the state of
 * the source strview_t is duplicated in the newly initialized strview_t.
 */
void sv_init_sv(strview_t *, const strview_t *);

/*
 * Initialize a strview_t as a subset of an already initialized strview_t.
 * The size of the subset (size_t) must be <= sv_remaining(src).
 */
void sv_init_sv_range(strview_t *, const strview_t *, size_t);

/*
 * Initialize a strview_t from a string.  The two const char * pointers are the
 * sv_first and sv_last values to use (see above).  If the source string is
 * NUL-terminated, one can optionally pass NULL for the second parameter in
 * which case, the entire NUL-terminated string (starting at sv_first) is
 * treated as a strview_t.
 */
void sv_init_str(strview_t *, const char *, const char *);

/*
 * Return the number of bytes remaining to consume in the strview_t
 */
size_t sv_remaining(const strview_t *);

/*
 * Return the char at the given position in the strview_t (without advancing
 * the position).  Position values >=0 are relative to the current position
 * of the strview_t (e.g. '0' will return the next character, '1' will return
 * the character after that), while negative position values are relative to
 * the end of the strview_t (e.g. '-1' will return the last character, '-2'
 * will return the second to last character).
 *
 * If the position value is out of range, '\0' is returned.
 */
char sv_peek(const strview_t *, ssize_t);

/*
 * Return the next character and advance the strview_t position.  If no more
 * characters are available, '\0' is returned.
 */
char sv_consume_c(strview_t *);

/*
 * Advance the position of the strview_t by the given number of bytes.  The
 * amount must be <= the number of bytes remaining in the strview_t.
 */
void sv_consume_n(strview_t *, size_t);

/*
 * Advance the strview_t position if the bytes of the strview starting at the
 * current position match the given NUL-terminated string.  The length of the
 * NUL-terminated string must be <= the number of bytes remaining in the
 * strview_t.
 *
 * If there is a match, the position of the strview_t is advanced by the
 * length of the NUL-terminated comparison string, and B_TRUE is returned. If
 * there is no match, the position is not advanced and B_FALSE is returned.
 */
boolean_t sv_consume_if(strview_t *, const char *);

/*
 * Advance the position of the strview_t if the next char in the strview_t
 * is equal to the given char.  If there is a match, the strview_t position
 * is advanced one byte and B_TRUE is returned.  If they do not match, B_FALSE
 * is returned and the position is not advanced.
 */
boolean_t sv_consume_if_c(strview_t *, char);

#ifdef __cplusplus
}
#endif

#endif /* _STRVIEW_H */
