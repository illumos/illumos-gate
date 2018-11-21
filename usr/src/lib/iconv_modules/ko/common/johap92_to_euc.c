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

static unsigned short _johap92_to_wansung(unsigned short code);

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	return((void*)MAGIC_NUMBER);
}  /* end of void* _icv_open(). */


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
		return((size_t)0);

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		if (!(*ib & 0x80))
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
			unsigned short	result;

			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			result = _johap92_to_wansung((unsigned short)(*ib)<<8 |
					(unsigned short)(*(ib + 1)));
			if (result != FAILED && result != ILLEGAL_SEQ)
			{
				if ((obtail - ob) < 2)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = (unsigned char)(result >> 8);
				*ob++ = (unsigned char)(result & 0xFF);
			}
			else
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}
			ib += 2;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*). */


/**** _ J O H A P 9 2 _ T O _ W A N S U N G ****/

static unsigned short _johap92_to_wansung(unsigned short code)
{
	short	ci, v, cf;
	short	mask;
	int	disp, i;
	int	ch1, ch2;
	long	cfbit;

	ch1 = code >> 8;
	ch2 = code & 0xff;

	if ((ch1 >= 0x84 && ch1 <= 0xd3) && ((ch2 >= 0x41 && ch2 <= 0x7e) ||
	    (ch2 >= 0x81 && ch2 <= 0xfe)))  /* Hangul */
	{
		ci = CHOSUNG(code) - 0x02;
		v = JOONGSUNG(code) - ((unsigned short)(JOONGSUNG(code) - 2) /
			8 * 2 + 3);
		cf = JONGSUNG(code) - (unsigned short)JONGSUNG(code) / 18;

		if (v < 0)
			return(0xA4A0 + Y19_32[CHOSUNG(code) - 1]);
		if (ci < 0)
		{
			if (cf <= 1)
				return(0xA4BF + v);
			return(ILLEGAL_SEQ);
		}

		for (cfbit = cmp_bitmap[ci][v], disp = 0, i = 0; i < cf; i++)
		{
			if (cfbit & BIT_MASK)
				disp++;
			cfbit >>= 1;
		}

		if (!(cfbit & BIT_MASK))
			return(ILLEGAL_SEQ);

		code = cmp_srchtbl[ci][v] + disp;
		mask = cmp_srchtbl[ci][v] & 0xff;
		if ((mask + disp) > 0xfe)
			code += SKIP;

		return(code);
	}
	else if ((ch2 >= 0x31 && ch2 <= 0x7e) || (ch2 >= 0x91 && ch2 <= 0xfe))
	{
		if (ch1 >= 0xe0 && ch1 <= 0xf9)  /* Hanja */
		{
			code = (0xca + (ch1 - 0xe0) * 2 + ch2 / 0xa1) << 8;
			return(code | ((ch2 > 0xa0) ? ch2
				: ch2 + 0x70 - ((ch2 / 0x91) * 0x12)));
		}
		else if (ch1 >= 0xd9 && ch1 <= 0xde)  /* Graphic characters */
		{
			code = (0xa1 + (ch1 - 0xd9) * 2 + ch2 / 0xa1) << 8;
			return(code | ((ch2 > 0xa0) ? ch2
				: ch2 + 0x70 - ((ch2 / 0x91) * 0x12)));
		}
		else if (ch1 == 0xd8)  /* User definable characters */
			return((ch2 > 0xa0) ? 0xfe00 | ch2 : 0xc900
					| (ch2 + 0x70 - ((ch2 / 0x91) * 0x12)));
	}

	return(FAILED);
}  /* end og static unsigned short _johap92_to_wansung(unsigned short). */
