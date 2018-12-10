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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * In this program, we assume that each table entry provided will contain
 * a valid UCS character, an illegal character, or, a replacement character.
 * In other words, it is table provider's responsibility to provide
 * an appropriate mapping for each single byte character in the table since
 * the program in this file will not do any special checking on the table
 * component values.
 *
 * This particular file is to cover conversions from various single byte
 * codesets to UCS-2, UCS-2BE, UCS-2LE, UCS-4, UCS-4BE, UCS-4LE, UTF-16,
 * UTF-16BE, UTF-16LE, UTF-32, UTF-32BE, and UTF-32LE.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "sb_to_ucs.h"


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
	unsigned char *ib;
	unsigned char *ob;
	unsigned char *ibtail;
	unsigned char *obtail;
	unsigned int u4;
#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
	unsigned int u4_2;
#endif
	signed char obsz;


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

	ib = (unsigned char *)*inbuf;
	ob = (unsigned char *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		u4 = sb_u4_tbl[*ib].u8;
#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		u4_2 = 0;
#endif

		if (sb_u4_tbl[*ib].size == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		obsz = (cd->bom_written) ? ICV_FETCH_UCS_SIZE :
			ICV_FETCH_UCS_SIZE_TWO;
#if defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE)
		if (u4 > 0x00ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#elif defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		if (u4 > 0x00ffff && u4 < 0x110000) {
			u4_2 = ((u4 - 0x010000) % 0x400) + 0x00dc00;
			u4   = ((u4 - 0x010000) / 0x400) + 0x00d800;
			obsz += 2;
		} else if (u4 > 0x10ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#elif defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
		if (u4 > 0x10ffff) {
			u4 = ICV_CHAR_UCS2_REPLACEMENT;
			ret_val++;
		}
#elif defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE)
		/* do nothing */
#else
#error	"Fatal: one of the UCS macros need to be defined."
#endif

		/*
		 * The target values in the conversion tables are in UCS-4
		 * without BOM and so the max target value possible would be
		 * U+7FFFFFFF.
		 */
		if (u4 == 0x00fffe || u4 == 0x00ffff || u4 > 0x7fffffff ||
		    (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
			/*
			 * if conversion table is right, this should not
			 * happen.
			 */
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((obtail - ob) < obsz) {
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
		ib++;
	}

	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
