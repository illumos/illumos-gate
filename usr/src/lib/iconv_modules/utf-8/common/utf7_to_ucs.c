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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * This program covers UTF-7 to UTF-8, UCS-2, and, UCS-4 code conversions.
 * UTF-7 described in RFC 2152.
 * We don't support any other UCS formats to and from UTF-7 unless there is
 * a significant requirement.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "utf7_to_ucs.h"


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

	if (! cd) {
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf)) {
		/* We just ignore any remnant bits we so far accumulated. */
		cd->in_the_middle_of_utf7_sequence = false;
		cd->remnant = 0;
		cd->remnant_count = 0;
		cd->prevch = (uchar_t)'\0';

		return((size_t)0);
	}

	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		uint_t temp_remnant;
		uint_t u4;
#if defined(UCS_2) || defined(UCS_4)
		signed char obsz;
#endif

		u4 = ICV_U7_UCS4_OUTOFUTF16;
		if (cd->in_the_middle_of_utf7_sequence) {
			if (rmb64[*ib] >= 0) {
				temp_remnant = (cd->remnant << 6) | rmb64[*ib];

				switch (cd->remnant_count) {
				case ICV_U7_ACTION_HARVEST1:
					u4 = (temp_remnant >> 2) & 0xffff;
					break;
				case ICV_U7_ACTION_HARVEST2:
					u4 = (temp_remnant >> 4) & 0xffff;
					break;
				case ICV_U7_ACTION_HARVEST3:
					u4 = temp_remnant & 0xffff;
					break;
				}

				if (u4 != ICV_U7_UCS4_OUTOFUTF16) {
					if (u4 == 0x00fffe || u4 == 0x00ffff ||
						(u4 >= 0x00d800 &&
						u4 <= 0x00dfff)) {
						errno = EILSEQ;
						ret_val = (size_t)-1;
						break;
					}
#if defined(UCS_2)
					CHECK_OUTBUF_SZ_AND_WRITE_U2;
#elif defined(UCS_4)
					CHECK_OUTBUF_SZ_AND_WRITE_U4;
#elif defined(UTF_8)
					CHECK_OUTBUF_SZ_AND_WRITE_U8_OR_EILSEQ;
#else
#error	"Fatal: One of UCS_2, UCS_4, or, UTF_8 is needed."
#endif
				}

				/* It's now safe to have the bits. */
				cd->remnant = temp_remnant;
				if (cd->remnant_count == ICV_U7_ACTION_HARVEST3)
					cd->remnant_count = ICV_U7_ACTION_START;
				else
					cd->remnant_count++;
			} else {
				if (*ib == (uint_t)'-') {
					if (cd->prevch == '+')
						u4 = (uint_t)'+';
				} else
					u4 = (uint_t)(*ib);

				switch (cd->remnant_count) {
				case ICV_U7_ACTION_START:
					/* (ICV_U7_ACTION_HARVEST3+1): */
					/* These are normal cases. */
					break;
				case (ICV_U7_ACTION_HARVEST1+1):
					if (cd->remnant & 0x03) {
						errno = EILSEQ;
						ret_val = (size_t)-1;
						goto illegal_char_err;
					}
					break;
				case (ICV_U7_ACTION_HARVEST2+1):
					if (cd->remnant & 0x0f) {
						errno = EILSEQ;
						ret_val = (size_t)-1;
						goto illegal_char_err;
					}
					break;
				default:
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto illegal_char_err;
					break;
				}

				if (u4 != ICV_U7_UCS4_OUTOFUTF16) {
#if defined(UCS_2)
					CHECK_OUTBUF_SZ_AND_WRITE_U2;
#elif defined(UCS_4)
					CHECK_OUTBUF_SZ_AND_WRITE_U4;
#elif defined(UTF_8)
					if (ob >= obtail) {
						errno = E2BIG;
						ret_val = (size_t)-1;
						break;
					}
					*ob++ = (uchar_t)(u4 & 0x7f);
#else
#error	"Fatal: One of UCS_2, UCS_4, or, UTF_8 is needed."
#endif
				}

				cd->in_the_middle_of_utf7_sequence = false;
				cd->remnant = 0;
				cd->remnant_count = 0;
			}
		} else {
			if (*ib == '+') {
				cd->in_the_middle_of_utf7_sequence = true;
				cd->remnant = 0;
				cd->remnant_count = 0;
			} else {
#if defined(UCS_2)
				u4 = (uint_t)*ib;
				CHECK_OUTBUF_SZ_AND_WRITE_U2;
#elif defined(UCS_4)
				u4 = (uint_t)*ib;
				CHECK_OUTBUF_SZ_AND_WRITE_U4;
#elif defined(UTF_8)
				if (ob >= obtail) {
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = *ib;
#else
#error	"Fatal: One of UCS_2, UCS_4, or, UTF_8 is needed."
#endif
			}
		}
		cd->prevch = *ib++;
	}

illegal_char_err:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;


	return(ret_val);
}
