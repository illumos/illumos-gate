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
 * This particular file is to cover conversions from UCS-2, UCS-2BE, UCS-2LE,
 * UCS-4, UCS-4BE, UCS-4LE, UTF-16, UTF-16BE, UTF-16LE, UTF-32, UTF-32BE,
 * and UTF-32LE to various single byte codesets.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "ucs_to_sb.h"


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
	uint_t u4;
	uint_t u4_2;
	register int i;
	register int l, h;

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

#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
	if (! cd->bom_written) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			goto need_more_input_err;
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

#if defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
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
#elif defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE)
		if (u4 >= 0x00fffe || (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
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

		if (ob >= obtail) {
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		if (u4 > 0x7f) {
			i = l = 0;
			h = (sizeof(u4_sb_tbl) /
			     sizeof(to_sb_table_component_t)) - 1;
			while (l <= h) {
				i = (l + h) / 2;
				if (u4_sb_tbl[i].u8 == u4)
					break;
				else if (u4_sb_tbl[i].u8 < u4)
					l = i + 1;
				else
					h = i - 1;
			}

			/*
			 * We just assume that either we found it or it is
			 * a non-identical character that we need to
			 * provide a replacement character.
			 */
			if (u4_sb_tbl[i].u8 == u4) {
				u4 = u4_sb_tbl[i].sb;
			} else {
				u4 = ICV_CHAR_ASCII_REPLACEMENT;
				ret_val++;
			}
		}

		*ob++ = (unsigned char)u4;
		ib += (u4_2) ? ICV_FETCH_UCS_SIZE_TWO : ICV_FETCH_UCS_SIZE;
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
