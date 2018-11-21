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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 */


#include <stdlib.h>
#include <errno.h>
#include <widec.h>
#include "common_def.h"
#include "common_han.h"
#include "utf_euc_api.h"
#include "common_defs.h"

#define ESC		0x1B
#define SO		0x0E
#define SI		0x0F

typedef struct __conv_desc {
	enum { NOT_DEFINED_YET, KSC5601 }	designator;
	enum { ASCII, HANGUL }	 		state;
} _conv_desc;

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	cd->designator = NOT_DEFINED_YET;
	cd->state = ASCII;

	return((void*)cd);
}  /* end of int _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(_conv_desc* cd)
{
	if (!cd)
		errno = EBADF;
	else
		free((void*)cd);
}  /* end of void _icv_close(_conv_desc*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(_conv_desc* cd, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!cd)
	{
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
	{
		if (cd->state == HANGUL)
		{
			if (outbufleft && *outbufleft >= 1 && outbuf && *outbuf)
			{
				**outbuf = SI;
				(*outbuf)++;
				(*outbufleft)--;
			}
			else
			{
				errno = E2BIG;
				return((size_t)-1);
			}
		}

		cd->designator = NOT_DEFINED_YET;
		cd->state = ASCII;
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

			/* Hangul string ends */
			if (cd->state == HANGUL) {
				*ob++ = SI;
				cd->state = ASCII;
			}
			*ob++ = *ib++;
		}
		else if ((*ib & 0xF0) == 0xE0)	/* 16 bits */
		{
			hcode_type utf8_code, euc_code;

			if ((ibtail - ib) < 3)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (!is_valid_utf8_string(ib, 3))
		        {
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
		        }

			utf8_code.byte.byte1 = 0;
			utf8_code.byte.byte2 = *ib;
			utf8_code.byte.byte3 = *(ib + 1);
			utf8_code.byte.byte4 = *(ib + 2);

			euc_code = _utf8_to_wansung(utf8_code);

			if (euc_code.code != 0) {
				/* If find something -> EUC code */

				/* if the first time of Hangul -> put Mark */
				if (cd->designator ==  NOT_DEFINED_YET) {
					*ob++ = ESC;
					*ob++ = '$';
					*ob++ = ')';
					*ob++ = 'C';
					cd->designator = KSC5601;
				}

				/* if the first Hangul in a string */
				if (cd->state == ASCII) {
					*ob++ = SO;
					cd->state = HANGUL;
				}

				/* MSB clear for 7-bits encoding */
				euc_code.wansung.msb1 = 0;
				euc_code.wansung.msb2 = 0;

				*ob++ = euc_code.byte.byte3;
				*ob++ = euc_code.byte.byte4;
			}
			else
			{
				/* Let's assume the code is non-identical. */
				if ((obtail - ob) < 2)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}

				/* non identical character == ASCII */
				if (cd->state == HANGUL) {
					*ob++ = SI;
					cd->state = ASCII;
				}
				*ob++ = NON_IDENTICAL;
				*ob++ = NON_IDENTICAL;
				ret_val += 2;
			}
			ib += 3;
		}
		else  /* 11, 21, 26 & 31 bits codes won't be able to convert. */
		{
			short int offset;

			if ((*ib & 0xE0) == 0xC0)  /* 11 */
				offset = 2;
			else if ((*ib & 0xF0) == 0xE0)  /* 16 */
				offset = 3;
			else if ((*ib & 0xF8) == 0xF0)  /* 21 */
				offset = 4;
			else if ((*ib & 0xFC) == 0xF8)  /* 26 */
				offset = 5;
			else if ((*ib & 0xFE) == 0xFC)  /* 31 */
				offset = 6;
			else  /* Illegal sequence. */
				offset = 1;

			if ((ibtail - ib) < offset)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (!is_valid_utf8_string(ib, offset))
		        {
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
		        }

			ib += offset;

			/* Let's assume the code is non-identical. */
			offset = (offset > 2) ? 2 : 1;
			if ((obtail - ob) < offset)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}

			/* non identical character == ASCII */
			if (cd->state == HANGUL) {
				*ob++ = SI;
				cd->state = ASCII;
			}

			*ob++ = NON_IDENTICAL;
			if (offset > 1)
				*ob++ = NON_IDENTICAL;
			ret_val += offset;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*).*/
