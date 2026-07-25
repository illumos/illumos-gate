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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * C23 c8rtomb(3C) support.
 */

#include "thr_uberdata.h"
#include <locale.h>
#include <uchar.h>
#include <sys/debug.h>
#include <sys/bitext.h>
#include "mblocal.h"

/*
 * Ensure that we never cause our save state to ever exceed that of the
 * mbstate_t. See the block comment in mblocal.h.
 */
CTASSERT(sizeof (_CHAR8State) <= sizeof (mbstate_t));
static mbstate_t c8rtomb_state;


/*
 * Since the UTF-8 Corrigendum to Unicode 3.1 only a subset of encodings of are
 * allowed. We must validate this. While u8_validate() works for entire strings,
 * we need to determine what's expected ahead of this point. The following table
 * summarizes the spec's requirements.
 *
 * POINTS		Byte[0]		Byte[1]		Byte[2]		Byte[3]
 * 00..7f		00..7f
 * 80..7ff		c2..df		80..bf
 * 800..fff		e0		a0..bf		80..bf
 * 1000..cfff		e1..ec		80..bf		80..bf
 * d000..d7ff		ed		80..9f		80..bf
 * e000..ffff		ee..ef		80..bf		80..bf
 * 10000..3ffff		f0		90..bf		80..bf		80..bf
 * 40000..fffff		f1..f3		80..bf		80..bf		80..bf
 * 100000..10ffff	f4		80..8f		80..bf		80..bf
 *
 * The way that we deal with this is through the existing tables that exist in
 * u8_textprep.c. u8_number_of_bytes[] tells us which starting points are valid
 * and their length. u8_valid_min_2nd_byte[] and u8_valid_max_2nd_byte[] can be
 * consulted to see what characters are valid given the value of what our table
 * above calls Byte[0]. Byte[2] and Byte[3] when present are always in the range
 * [80 .. bf]. We manually use these tables versus adding a prefix check for
 * u8_validate() so we avoid checking things that we already have.
 */
extern const int8_t u8_number_of_bytes[0x100];
extern const uint8_t u8_valid_min_2nd_byte[0x100];
extern const uint8_t u8_valid_max_2nd_byte[0x100];

size_t
c8rtomb_l(char *restrict str, char8_t c8, mbstate_t *restrict ps,
    locale_t restrict loc)
{
	_CHAR8State *c8s;
	char32_t c32;
	int err;

	if (ps == NULL) {
		ps = &c8rtomb_state;
	}

	if (str == NULL) {
		c8 = '\0';
	}

	c8s = (_CHAR8State *)ps;

	/*
	 * When the input character is a null character, the standard says it
	 * should be stored and any shift sequence included, and then we should
	 * be reset to the initial state sequence.
	 */
	if (c8 == 0) {
		c8s->c8_count = 0;
		c8s->c8_exp = 0;
		(void) memset(c8s->c8_bytes, 0, sizeof (c8s->c8_bytes));
		return (c32rtomb_l(str, 0, ps, loc));
	}

	/*
	 * We have received a UTF-8 character. We must see if there is any
	 * existing state that this should be appended to. While it would be
	 * nice to u8_validate() directly here, that wants a complete string and
	 * we would prefer to error immediately. We pack how many bytes we've
	 * seen and how many we expect.
	 */
	if (c8s->c8_count == 0) {
		if (u8_number_of_bytes[c8] < 0) {
			errno = EILSEQ;
			return ((size_t)-1);
		}

		c8s->c8_exp = u8_number_of_bytes[c8];
		c8s->c8_bytes[c8s->c8_count] = c8;
		c8s->c8_count++;
	} else {
		uint8_t min, max;

		if (c8s->c8_count == 1) {
			min = u8_valid_min_2nd_byte[c8s->c8_bytes[0]];
			max = u8_valid_max_2nd_byte[c8s->c8_bytes[0]];
		} else {
			min = 0x80;
			max = 0xbf;
		}

		if (c8 < min || c8 > max) {
			errno = EILSEQ;
			return ((size_t)-1);
		}

		c8s->c8_bytes[c8s->c8_count] = c8;
		c8s->c8_count++;
	}

	/*
	 * If we don't have all the characters that we expect to need, return
	 * that this character has been consumed, but nothing has been written.
	 */
	if (c8s->c8_exp != c8s->c8_count) {
		return (0);
	}

	/*
	 * Reassemble the various bytes into the right positions. The exact
	 * number of bits varies depending on the target character count.
	 */
	switch (c8s->c8_count) {
	case 1:
		c32 = bitset32(0, 6, 0, bitx8(c8s->c8_bytes[0], 6, 0));
		break;
	case 2:
		c32 = bitset32(0, 10, 6, bitx8(c8s->c8_bytes[0], 4, 0));
		c32 = bitset32(c32, 5, 0, bitx8(c8s->c8_bytes[1], 5, 0));
		break;
	case 3:
		c32 = bitset32(0, 15, 12, bitx8(c8s->c8_bytes[0], 3, 0));
		c32 = bitset32(c32, 11, 6, bitx8(c8s->c8_bytes[1], 5, 0));
		c32 = bitset32(c32, 5, 0, bitx8(c8s->c8_bytes[2], 5, 0));
		break;
	case 4:
		c32 = bitset32(0, 19, 17, bitx8(c8s->c8_bytes[0], 2, 0));
		c32 = bitset32(c32, 16, 12, bitx8(c8s->c8_bytes[1], 5, 0));
		c32 = bitset32(c32, 11, 6, bitx8(c8s->c8_bytes[2], 5, 0));
		c32 = bitset32(c32, 5, 0, bitx8(c8s->c8_bytes[3], 5, 0));
		break;
	default:
		abort();
	}

	c8s->c8_count = 0;
	c8s->c8_exp = 0;
	(void) memset(c8s->c8_bytes, 0, sizeof (c8s->c8_bytes));
	return (c32rtomb_l(str, c32, ps, loc));
}

size_t
c8rtomb(char *restrict str, char8_t c8, mbstate_t *restrict ps)
{
	return (c8rtomb_l(str, c8, ps, __curlocale()));
}
