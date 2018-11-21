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
 * This is for conversions from UTF-8 to various UCS forms, esp.,
 * UCS-2, UCS-2BE, UCS-2LE, UTF-16, UTF-16BE, UTF-16LE, UCS-4, UCS-4BE,
 * UCS-4LE, UTF-32, UTF-32BE, and UTF-32LE.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "utf8_to_ucs.h"


void *
_icv_open()
{
	ucs_state_t *cd = (ucs_state_t *)calloc(1, sizeof(ucs_state_t));

	if (cd == (ucs_state_t *)NULL) {
		errno = ENOMEM;
		return((void *)-1);
	}

#if defined(UTF_16BE) || defined(UCS_2BE) || defined(UCS_4BE) || \
	defined(UTF_32BE)
	cd->little_endian = false;
	cd->bom_written = true;
#elif defined(UTF_16LE) || defined(UCS_2LE) || defined(UCS_4LE) || \
	defined(UTF_32LE)
	cd->little_endian = true;
	cd->bom_written = true;
#elif defined(_LITTLE_ENDIAN)
	cd->little_endian = true;
#endif

	return((void *)cd);
}


void
_icv_close(ucs_state_t *cd)
{
	if (! cd)
		errno = EBADF;
	else
		free((void *)cd);
}


size_t
_icv_iconv(ucs_state_t *cd, char **inbuf, size_t *inbufleft, char **outbuf,
                size_t *outbufleft)
{
	size_t ret_val = 0;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;

	if (! cd) {
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf)) {
#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
		cd->bom_written = false;
#endif
		return((size_t)0);
	}

	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		uchar_t *ib_org;
		uint_t u4;
#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		uint_t u4_2;
#endif
		uint_t first_byte;
		signed char sz;
		signed char obsz;

		sz = number_of_bytes_in_utf8_char[*ib];
		if (sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((ibtail - ib) < sz) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		ib_org = ib;
		first_byte = *ib;
		u4 = (uint_t)(*ib++ & masks_tbl[sz]);
		for (; sz > 1; sz--) {
			if (first_byte) {
				if (((uchar_t)*ib) <
					valid_min_2nd_byte[first_byte] ||
				    ((uchar_t)*ib) >
					valid_max_2nd_byte[first_byte]) {
					ib = ib_org;
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto ILLEGAL_CHAR_ERR;
				}
				first_byte = 0;
			} else if (((uint_t)*ib) < 0x80 ||
				   ((uint_t)*ib) > 0xbf) {
				ib = ib_org;
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto ILLEGAL_CHAR_ERR;
			}
			u4 = (u4 << ICV_UTF8_BIT_SHIFT) |
				(((uint_t)*ib) & ICV_UTF8_BIT_MASK);
			ib++;
		}

		/* Check against known non-characters. */
		if ((u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_fffe ||
		    (u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_ffff ||
		    u4 > ICV_UTF32_LAST_VALID_CHAR ||
		    (u4 >= ICV_UTF32_SURROGATE_START_d800 &&
		    u4 <= ICV_UTF32_SURROGATE_END_dfff) ||
		    (u4 >= ICV_UTF32_ARABIC_NONCHAR_START_fdd0 &&
		    u4 <= ICV_UTF32_ARABIC_NONCHAR_END_fdef)) {
			ib = ib_org;
			errno = EILSEQ;
			ret_val = (size_t)-1;
			goto ILLEGAL_CHAR_ERR;
		}

#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		u4_2 = 0;
#endif

		if (u4 == ICV_BOM_IN_BIG_ENDIAN) {
			cd->bom_written = true;
		}

#if defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE)
		obsz = (cd->bom_written) ? 4 : 8;
#elif defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
		obsz = (cd->bom_written) ? 4 : 8;
		if (u4 > 0x10ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#elif defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE)
		obsz = (cd->bom_written) ? 2 : 4;
		if (u4 > 0x00ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#elif defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		obsz = (cd->bom_written) ? 2 : 4;
		if (u4 > 0x10ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		} else if (u4 > 0x00ffff) {
			u4_2 = ((u4 - 0x010000) % 0x400) + 0x00dc00;
			u4   = ((u4 - 0x010000) / 0x400) + 0x00d800;
			obsz += 2;
		}
#else
#error	"Fatal: one of the UCS macros need to be defined."
#endif
		if ((obtail - ob) < obsz) {
			ib = ib_org;
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		if (cd->little_endian) {
			if (! cd->bom_written) {
				*ob++ = (uchar_t)0xff;
				*ob++ = (uchar_t)0xfe;
#if defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
	defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
				*(ushort_t *)ob = (ushort_t)0;
				ob += 2;
#endif
				cd->bom_written = true;
			}
			*ob++ = (uchar_t)(u4 & 0xff);
			*ob++ = (uchar_t)((u4 >> 8) & 0xff);
#if defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
	defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
			*ob++ = (uchar_t)((u4 >> 16) & 0xff);
			*ob++ = (uchar_t)((u4 >> 24) & 0xff);
#elif defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
			if (u4_2) {
				*ob++ = (uchar_t)(u4_2 & 0xff);
				*ob++ = (uchar_t)((u4_2 >> 8) & 0xff);
			}
#endif
		} else {
			if (! cd->bom_written) {
#if defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
	defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
				*(ushort_t *)ob = (ushort_t)0;
				ob += 2;
#endif
				*ob++ = (uchar_t)0xfe;
				*ob++ = (uchar_t)0xff;
				cd->bom_written = true;
			}
#if defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
	defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
			*ob++ = (uchar_t)((u4 >> 24) & 0xff);
			*ob++ = (uchar_t)((u4 >> 16) & 0xff);
#endif
			*ob++ = (uchar_t)((u4 >> 8) & 0xff);
			*ob++ = (uchar_t)(u4 & 0xff);
#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
			if (u4_2) {
				*ob++ = (uchar_t)((u4_2 >> 8) & 0xff);
				*ob++ = (uchar_t)(u4_2 & 0xff);
			}
#endif
		}
	}

ILLEGAL_CHAR_ERR:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
