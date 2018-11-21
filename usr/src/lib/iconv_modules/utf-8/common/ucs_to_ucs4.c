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
 * This particular file is to cover conversions from various UCS formats,
 * especially, UCS-2, UCS-2BE, UCS-2LE, UTF-16, UTF-16BE, and, UTF-16LE to
 * another various UCS formats, UCS-4, UCS-4BE, UCS-4LE, UTF-32, UTF-32BE,
 * and, UTF-32LE.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "ucs_to_ucs4.h"


void *
_icv_open()
{
	ucs_ucs_state_t *cd;

	cd = (ucs_ucs_state_t *)calloc(1, sizeof(ucs_ucs_state_t));
	if (cd == (ucs_ucs_state_t *)NULL) {
		errno = ENOMEM;
		return((void *)-1);
	}

#if defined(UTF_16BE) || defined(UCS_2BE)
	cd->input.little_endian = false;
	cd->input.bom_written = true;
#elif defined(UTF_16LE) || defined(UCS_2LE)
	cd->input.little_endian = true;
	cd->input.bom_written = true;
#elif defined(_LITTLE_ENDIAN)
	cd->input.little_endian = true;
#endif

#if defined(UCS_4BE) || defined(UTF_32BE)
	cd->output.little_endian = false;
	cd->output.bom_written = true;
#elif defined(UCS_4LE) || defined(UTF_32LE)
	cd->output.little_endian = true;
	cd->output.bom_written = true;
#elif defined(_LITTLE_ENDIAN)
	cd->output.little_endian = true;
#endif

	return((void *)cd);
}


void
_icv_close(ucs_ucs_state_t *cd)
{
	if (! cd)
		errno = EBADF;
	else
		free((void *)cd);
}


size_t
_icv_iconv(ucs_ucs_state_t *cd, char **inbuf, size_t *inbufleft, char **outbuf,
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
#if defined(UCS_2) || defined(UTF_16)
		cd->input.bom_written = false;
#endif
#if defined(UCS_4) || defined(UTF_32)
		cd->output.bom_written = false;
#endif
		return((size_t)0);
	}

	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

#if defined(UCS_2) || defined(UTF_16)
	if (! cd->input.bom_written) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			goto need_more_input_err;
		}

		for (u4 = 0, i = 0; i < ICV_FETCH_UCS_SIZE; i++)
			u4 = (u4 << 8) | ((uint_t)(*(ib + i)));

		if (u4 == ICV_BOM_IN_BIG_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->input.little_endian = false;
		} else if (u4 == ICV_BOM_IN_LITTLE_ENDIAN) {
			ib += ICV_FETCH_UCS_SIZE;
			cd->input.little_endian = true;
		}
	}
	cd->input.bom_written = true;
#endif

	while (ib < ibtail) {
		if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		u4 = u4_2 = 0;
		if (cd->input.little_endian) {
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

			if (cd->input.little_endian) {
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
#elif defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
	defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
		/*
		 * We do nothing here since these if expressions are
		 * only for input characters particularly of
		 * UCS-2, UCS-2BE, UCS-2LE, UTF-16, UTF-16BE, and
		 * UTF-16LE.
		 */
#else
#error	"Fatal: one of the UCS macros need to be defined."
#endif

		if ((obtail - ob) < ((cd->output.bom_written) ? 4 : 8)) {
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		if (cd->output.little_endian) {
			if (! cd->output.bom_written) {
				*ob++ = (uchar_t)0xff;
				*ob++ = (uchar_t)0xfe;
				*(ushort_t *)ob = (ushort_t)0;
				ob += 2;
				cd->output.bom_written = true;
			}
			*ob++ = (uchar_t)(u4 & 0xff);
			*ob++ = (uchar_t)((u4 >> 8) & 0xff);
			*ob++ = (uchar_t)((u4 >> 16) & 0xff);
			*ob++ = (uchar_t)((u4 >> 24) & 0xff);
		} else {
			if (! cd->output.bom_written) {
				*(ushort_t *)ob = (ushort_t)0;
				ob += 2;
				*ob++ = (uchar_t)0xfe;
				*ob++ = (uchar_t)0xff;
				cd->output.bom_written = true;
			}
			*ob++ = (uchar_t)((u4 >> 24) & 0xff);
			*ob++ = (uchar_t)((u4 >> 16) & 0xff);
			*ob++ = (uchar_t)((u4 >> 8) & 0xff);
			*ob++ = (uchar_t)(u4 & 0xff);
		}
		ib += ((u4_2) ? ICV_FETCH_UCS_SIZE_TWO : ICV_FETCH_UCS_SIZE);
	}

#if defined(UCS_2) || defined(UTF_16)
need_more_input_err:
#endif
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
