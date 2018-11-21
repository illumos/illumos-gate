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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */


#include <errno.h>
#include "ktable.h"
#include "hangulcode.h"

static unsigned short _wansung_to_johap92(unsigned short code);

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	return((void*)MAGIC_NUMBER);
}  /* end of int _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(int* cd)
{
	if (!cd || cd != (int*)MAGIC_NUMBER)
		errno = EBADF;
}  /* end of void _icv_close(int*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(int* cd, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!cd || cd != (int*)MAGIC_NUMBER)
	{
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
	{
		return((size_t)0);
	}

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		if (!(*ib & 0x80))		/* 7 bits */
		{
			if (ob >= obtail)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++;
		}
		else
		{
			unsigned short code;

			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if ((obtail - ob) < 2)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}

			code = _wansung_to_johap92((unsigned short)(*ib)<<8 |
					(unsigned short)(*(ib + 1)));
			if (code != FAILED && code != ILLEGAL_SEQ)
			{
				*ob++ = (unsigned char)(code >> 8);
				*ob++ = (unsigned char)(code & 0xFF);
			}
			else
			{
				*ob++ = NON_IDENTICAL;
				*ob++ = NON_IDENTICAL;
			}
			ib += 2;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*).*/


/**** _ W A N S U N G _ T O _ J O H A P 9 2 ****/

static unsigned short _wansung_to_johap92(unsigned short code)
{
	register unsigned short	jc, jc2;
	register short		h, i, l;
	short			ci, v, cf;
	short			disp;
	long			cfbit;

	if ((unsigned short)(code & 0xFF) < 0xA1)
		return(ILLEGAL_SEQ);

	if (code >= 0xB0A1 && code <= 0xC8FE)  /* Hangul */
	{
		for (h = CI_CNT, l = 0; ; )
		{
			ci = (l + h) / 2;
			if (l >= h)
				break;
			if (code < cmp_srchtbl[ci][0])
				h = ci - 1;
			else if (code < cmp_srchtbl[ci + 1][0])
				break;
			else
				l = ci + 1;
		}

		for (v = 1; ; )
		{
			if (code < cmp_srchtbl[ci][v])
			{
				while (!cmp_srchtbl[ci][--v])
					;
				break;
			}
			else if (v == V_CNT)
				break;
			v++;
		}

		disp = code - cmp_srchtbl[ci][v];
		if (((short)(cmp_srchtbl[ci][v] & BYTE_MASK) + disp) > 0xfe)
			disp -= SKIP;

		for (cfbit = cmp_bitmap[ci][v], i = -1, cf = -1; i < disp; cf++)
		{
			if (cfbit & BIT_MASK)
				i++;
			cfbit >>= 1;
		}

		if (cf == -1)
			return(FAILED);

		code = ci + 2;
		code = (code << 5) | (v + (v + 1) / 6 * 2 + 3);
		return((code << 5) | (cf + cf / 18) | 0x8000);
	}
	else if (code >= 0xA1A1 && code <= 0xACFE)  /* Special symbols */
	{
		jc = (((unsigned short)(code - 0xA100) >> 1) + 0xD900) & 0xFF00;
		jc2 = code & 0xFF;
		if ((unsigned short)(code >> 8) % 2)
			return(jc | (jc2 - ((jc2 > 0xEE) ? 0x5E : 0x70)));
		return(jc | jc2);
	}
	else if (code >= 0xCAA1 && code <= 0xFDFE)  /* Hanja */
	{
		jc = (((unsigned short)(code - 0xCA00) >> 1) + 0xE000) & 0xFF00;
		jc2 = code & 0xFF;
		if ((unsigned short)(code >> 8) % 2)
			return(jc | jc2);
		return(jc | (jc2 - ((jc2 > 0xEE) ? 0x5E : 0x70)));
	}
	else if ((code >= 0xC9A1 && code <= 0xC9FE) ||
		 (code >= 0xFEA1 && code <= 0xFEFE))  /* User-definable area */
	{
		if ((code & 0xFF00) == 0xFE00)
			return(0xD800 | (code & 0xFF));
		code = code & 0xFF;
		return(0xD800 | (code - ((code > 0xEE) ? 0x5E : 0x70)));
	}

	return(FAILED);
}  /* end of static unsigned short _wansung_to_johap92(unsigned short). */
