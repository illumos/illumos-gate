/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This program covers conversion from UTF-8, UCS-2, and, UCS-4 to UTF-7.
 * UTF-7 is described in RFC 2152.
 * We only support conversions between UCS-2/UCS-4/UTF-8 and UTF-7. No
 * other UCS formats are going to be supported unless there is a significant
 * reason.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "ucs_to_utf7.h"


void *
_icv_open()
{
	utf7_state_t *cd = (utf7_state_t *)calloc(1, sizeof(utf7_state_t));

	if (cd == (utf7_state_t *)NULL) {
		errno = ENOMEM;
		return((void *)-1);
	}
#if defined(_LITTLE_ENDIAN)
	cd->little_endian = true;
#endif

	return((void *)cd);
}


void
_icv_close(utf7_state_t *cd)
{
	if (! cd)
		errno = EBADF;
	else
		free((void *)cd);
}


size_t
_icv_iconv(utf7_state_t *cd, char **inbuf, size_t *inbufleft, char **outbuf,
                size_t *outbufleft)
{
	size_t ret_val = 0;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	uchar_t *ib_org;
	uint_t u4;
	uint_t u7;
	signed char sz;
	signed char new_bits_count;
	signed char new_remnant_count;
#if defined(UCS_2) || defined(UCS_4)
	register int i;
#endif

	if (! cd) {
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf)) {
		if (cd->in_the_middle_of_utf7_sequence) {
			sz = (cd->remnant_count > 0) ? 2 : 1;

			if ((! outbufleft) || *outbufleft < sz) {
				errno = E2BIG;
				return((size_t)-1);
			}

			if (cd->remnant_count > 0) {
				/* Masking is needed. */
				**outbuf = mb64[((cd->remnant <<
					(6 - cd->remnant_count)) & 0x003f)];
				(*outbuf)++;
			}

			**outbuf = '-';
			(*outbuf)++;
			*outbufleft -= sz;
		}

		cd->remnant = 0;
		cd->remnant_count = 0;
		cd->in_the_middle_of_utf7_sequence = false;
#if defined(UCS_2) || defined(UCS_4)
		cd->bom_written = false;
#endif

		return((size_t)0);
	}

	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

#if defined(UCS_2) || defined(UCS_4)
	if (! cd->bom_written) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			return((size_t)-1);
		}

		for (u4 = 0, i = 0; i < ICV_FETCH_UCS_SIZE; i++)
			u4 = (u4 << 8) | ((uint_t)(*(ib + i)));

		if (u4 == ICV_BOM_IN_BIG_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->little_endian = false;
		} else if (u4 == ICV_BOM_IN_LITTLE_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->little_endian = true;
		}
	}
	cd->bom_written = true;
#endif

	while (ib < ibtail) {
#if defined(UTF_8)
		sz = number_of_bytes_in_utf8_char[*ib];
		if (sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
#elif defined(UCS_2) || defined(UCS_4)
		sz = ICV_FETCH_UCS_SIZE;
#else
#error	"Fatal: One of UTF_8, UCS_2, or, UCS_4 is needed."
#endif

		if ((ibtail - ib) < sz) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		ib_org = ib;
#if defined(UTF_8)
		u4 = *ib++ & masks_tbl[sz];
		for (; sz > 1; sz--) {
			if (((uint_t)*ib) < 0x80) {
				ib = ib_org;
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto illegal_char_err;
			}
			u4 = (u4 << ICV_UTF8_BIT_SHIFT) |
				(((uint_t)*ib) & ICV_UTF8_BIT_MASK);
			ib++;
		}
#elif defined(UCS_2) || defined(UCS_4)
		u4 = 0;
		if (cd->little_endian) {
			for (i = ICV_FETCH_UCS_SIZE - 1; i >= 0; i--)
				u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
		} else {
			for (i = 0; i < ICV_FETCH_UCS_SIZE; i++)
				u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
		}
		ib += ICV_FETCH_UCS_SIZE;
#endif

		/* Check against known non-characters. */
#if defined(UTF_8)
		if ((u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_fffe ||
		    (u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_ffff ||
		    u4 > ICV_UTF32_LAST_VALID_CHAR ||
		    (u4 >= ICV_UTF32_SURROGATE_START_d800 &&
		    u4 <= ICV_UTF32_SURROGATE_END_dfff) ||
		    (u4 >= ICV_UTF32_ARABIC_NONCHAR_START_fdd0 &&
		    u4 <= ICV_UTF32_ARABIC_NONCHAR_END_fdef)) {
#elif defined(UCS_2)
		if (u4 >= ICV_UTF32_NONCHAR_fffe ||
		    (u4 >= ICV_UTF32_SURROGATE_START_d800 &&
		    u4 <= ICV_UTF32_SURROGATE_END_dfff) ||
		    (u4 >= ICV_UTF32_ARABIC_NONCHAR_START_fdd0 &&
		    u4 <= ICV_UTF32_ARABIC_NONCHAR_END_fdef)) {
#else
		if ((u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_fffe ||
		    (u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_ffff ||
		    u4 > ICV_UCS4_LAST_VALID_CHAR ||
		    (u4 >= ICV_UTF32_SURROGATE_START_d800 &&
		    u4 <= ICV_UTF32_SURROGATE_END_dfff) ||
		    (u4 >= ICV_UTF32_ARABIC_NONCHAR_START_fdd0 &&
		    u4 <= ICV_UTF32_ARABIC_NONCHAR_END_fdef)) {
#endif
			ib = ib_org;
			errno = EILSEQ;
			ret_val = (size_t)-1;
			goto illegal_char_err;
		}

#if defined(UCS_4) || defined(UTF_8)
		if (u4 > 0x00ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#endif

		/* Set D or Rule 3? */
		if ((u4 >= (uint_t)'A' && u4 <= (uint_t)'Z') ||
		    (u4 >= (uint_t)'a' && u4 <= (uint_t)'z') ||
		    (u4 >= (uint_t)'0' && u4 <= (uint_t)'9') ||
		    u4 == (uint_t)'\'' || u4 == (uint_t)'(' ||
		    u4 == (uint_t)')' ||
		    (u4 >= (uint_t)',' && u4 <= (uint_t)'/') || /* , - . / */
		    u4 == (uint_t)':' || u4 == (uint_t)'?' ||
		    u4 == (uint_t)' ' || u4 == (uint_t)'\t' ||
		    u4 == (uint_t)'\r' || u4 == (uint_t)'\n') {

			u7 = 0;
			sz = 1;
			if (cd->in_the_middle_of_utf7_sequence) {
				if (cd->remnant_count > 0) {
					sz++;
					u7 = cd->remnant <<
						(6 - cd->remnant_count);
				}
				if (u4 == (uint_t)'-' ||
				    ICV_INRANGE_OF_MBASE64_ALPHABET(u4))
					sz++;
			}

			if ((obtail - ob) < sz) {
				ib = ib_org;
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}

			if (cd->in_the_middle_of_utf7_sequence) {
				/* Masking is needed. */
				if (cd->remnant_count > 0)
					*ob++ = mb64[u7 & 0x003f];
				if (u4 == (uint_t)'-' ||
				    ICV_INRANGE_OF_MBASE64_ALPHABET(u4))
					*ob++ = '-';

				cd->in_the_middle_of_utf7_sequence = false;
				cd->remnant_count = 0;
			}

			*ob++ = (uchar_t)(u4 & 0x007f);

		} else {
/*
 * Any UCS-2 character sequences will yield:
 *
 * +-16 bits (UCS-2)-+  +-16 bits (UCS-2)-+  +-16 bits (UCS-2)-+
 * |                 |  |                 |  |                 |
 * xxxx xxxx xxxx xxxx  xxxx xxxx xxxx xxxx  xxxx xxxx xxxx xxxx
 * |     ||     | |      ||     | |     ||      | |     ||     |
 * +-----++-----+ +------++-----+ +-----++------+ +-----++-----+ MBase64 chars
 *                ^                      ^
 * initially,     |                      |
 *                four remnant bits,     |
 *                                       two remnant bits,
 *
 * and, then no remnant bit for three sequential UCS-2 characters,
 * respectively, and repeat these three UCS-2 character sequences. For the
 * first UCS-2 character in this sequence, there will be two MBase64
 * characters, and for the second and the third UCS-2 characters, there will be
 * three MBase64 characters.
 */
			sz = (cd->remnant_count) ? 3 : 2;
			if (! cd->in_the_middle_of_utf7_sequence)
				sz++;

			if ((obtail - ob) < sz) {
				ib = ib_org;
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}

			if (! cd->in_the_middle_of_utf7_sequence) {
				*ob++ = '+';
				cd->in_the_middle_of_utf7_sequence = true;
			}

			if (cd->remnant_count) {
				new_bits_count = 18 - cd->remnant_count;
				new_remnant_count = 16 - new_bits_count;
				u7 = (cd->remnant << new_bits_count) |
					(u4 >> new_remnant_count);
				cd->remnant = u4 & 0x0003;
				cd->remnant_count = new_remnant_count;

				/* Masking is needed. */
				*ob++ = mb64[(u7 >> 12) & 0x003f];
				*ob++ = mb64[(u7 >> 6) & 0x003f];
				*ob++ = mb64[u7 & 0x003f];
			} else {
				cd->remnant = u4 & 0x000f;
				cd->remnant_count = 4;

				/* Masking is needed. */
				*ob++ = mb64[(u4 >> 10) & 0x003f];
				*ob++ = mb64[(u4 >> 4) & 0x003f];
			}
		}
	}

illegal_char_err:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
