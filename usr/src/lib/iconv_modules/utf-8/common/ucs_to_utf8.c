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
 * Following is how we process BOM and subsequent bytes in this program:
 * - UCS-2BE, UTF-16BE, UCS-4BE, UTF-32BE, UCS-2LE, UTF-16LE, UCS-4LE, and
 *   UTF-32LE don't care about BOM. From the beginning, they are properly
 *   serialized without the BOM character; any BOM is treated as ZWNBSP.
 * - In other encodings, UCS-2, UCS-4, UTF-16, and UTF-32, the initial byte
 *   ordering is of the current processor's byte ordering. During the first
 *   iconv() call, if BOM appears as the first character of the entier
 *   iconv input stream, the byte order will be changed accordingly.
 *   We will use 'bom_written' data field of the conversion descriptor to
 *   save this particular information, in other words, whether we've been
 *   encountered the first character as the BOM.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "ucs_to_utf8.h"


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
	uint_t u4;
	uint_t u4_2;
	register int i;

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

#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
	if (! cd->bom_written) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			goto need_more_input_err;
		}

		for (u4 = 0, i = 0; i < ICV_FETCH_UCS_SIZE; i++)
			u4 = (u4 << 8) | ((uint_t)(*(ib + i)));

		/* Big endian, Little endian, or, not specified?? */
		if (u4 == ICV_BOM_IN_BIG_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->little_endian = false;
		} else if (u4 == ICV_BOM_IN_LITTLE_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->little_endian = true;
		}
	}
	/*
	 * Once BOM checking is done, regardless of whether we had the BOM or
	 * not, we treat the BOM sequence as a ZWNBSP character from now on.
	 */
	cd->bom_written = true;
#endif

	while (ib < ibtail) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		u4 = u4_2 = 0;
		if (cd->little_endian) {
			for (i = ICV_FETCH_UCS_SIZE - 1; i >= 0; i--)
				u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
		} else {
			for (i = 0; i < ICV_FETCH_UCS_SIZE; i++)
				u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
		}

#if defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE)
		if (u4 >= 0x00fffe || (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
#elif defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
		if ((u4 >= 0x00dc00 && u4 <= 0x00dfff) || u4 >= 0x00fffe) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if (u4 >= 0x00d800 && u4 <= 0x00dbff) {
			if ((ibtail - ib) < ICV_FETCH_UCS_SIZE_TWO) {
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (cd->little_endian) {
				for (i = ICV_FETCH_UCS_SIZE_TWO - 1;
					i >= ICV_FETCH_UCS_SIZE;
						i--)
					u4_2 = (u4_2<<8)|((uint_t)(*(ib + i)));
			} else {
				for (i = ICV_FETCH_UCS_SIZE;
					i < ICV_FETCH_UCS_SIZE_TWO;
						i++)
					u4_2 = (u4_2<<8)|((uint_t)(*(ib + i)));
			}

			if (u4_2 < 0x00dc00 || u4_2 > 0x00dfff) {
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}

			u4 = ((((u4 - 0x00d800) * 0x400) +
				(u4_2 - 0x00dc00)) & 0x0fffff) + 0x010000;
		}
#elif defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
		if (u4 == 0x00fffe || u4 == 0x00ffff || u4 > 0x10ffff ||
		    (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
#elif defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE)
		if (u4 == 0x00fffe || u4 == 0x00ffff || u4 > 0x7fffffff ||
		    (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
#else
#error	"Fatal: one of the UCS macros need to be defined."
#endif

		/*
		 * Once we reach here, the "u4" contains a valid character
		 * and thus we don't do any other error checking in
		 * the below.
		 */
		if (u4 <= 0x7f) {
			OUTBUF_SIZE_CHECK(1);
			*ob++ = (uchar_t)u4;
		} else if (u4 <= 0x7ff) {
			OUTBUF_SIZE_CHECK(2);
			*ob++ = (uchar_t)(0xc0 | ((u4 & 0x07c0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x003f));
		} else if (u4 <= 0x00ffff) {
			OUTBUF_SIZE_CHECK(3);
			*ob++ = (uchar_t)(0xe0 | ((u4 & 0x0f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0003f));
		} else if (u4 <= 0x1fffff) {
			OUTBUF_SIZE_CHECK(4);
			*ob++ = (uchar_t)(0xf0 | ((u4 & 0x01c0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x000003f));
		} else if (u4 <= 0x3ffffff) {
			OUTBUF_SIZE_CHECK(5);
			*ob++ = (uchar_t)(0xf8 | ((u4 & 0x03000000) >> 24));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0000003f));
		} else {
			OUTBUF_SIZE_CHECK(6);
			*ob++ = (uchar_t)(0xfc | ((u4 & 0x40000000) >> 30));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x3f000000) >> 24));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0000003f));
		}
		ib += ((u4_2) ? ICV_FETCH_UCS_SIZE_TWO : ICV_FETCH_UCS_SIZE);
	}

#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
need_more_input_err:
#endif
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
