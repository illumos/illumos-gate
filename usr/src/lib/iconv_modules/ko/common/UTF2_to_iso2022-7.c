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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */


#include <stdlib.h>
#include <errno.h>
#include "ktable.h"
#include "utf_iso2022.h"


/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	RESET_CONV_DESC();
	cd->designated = 0;
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
	extern unsigned short _johap_to_wansung(unsigned short, unsigned short,
						unsigned short);
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

	/* To keep up with libc.so's iconv(), inbufleft checkings are added. */
	if (!inbuf || !(*inbuf) || !inbufleft || !(*inbufleft))
	{
		if (cd->state == WANSUNG && outbufleft && *outbufleft >= 1 &&
		    outbuf && *outbuf)
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

		RESET_CONV_DESC();
		cd->designated = 0;
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
			PROCESS_PRIOR_CVC();

			if ((obtail - ob) < (cd->state == WANSUNG ? 2 : 1))
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			if (cd->state == WANSUNG)
			{
				*ob++ = SI;
				cd->state = ASCII;
			}
			*ob++ = *ib++;
		}
		else if ((*ib & 0xF0) == 0xE0)	/* 16 bits */
		{
			unsigned long	u;

			if ((ibtail - ib) < 3)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			u = ((unsigned long)(*ib) << 16) |
			      ((unsigned long)(*(ib + 1)) << 8) |
			      (unsigned long)(*(ib + 2));
			if (u == 0xE1859F ||
			    (u >= 0xE18480 && u <= 0xE18492))  /* Ci */
			{
				PROCESS_PRIOR_CVC();

				cd->ci = (u == 0xE1859F) ? CVC_FILL
							   : u - 0xE18480;
				cd->prev_state = CI;
			}
			else if (u == 0xE185A0 ||
				 (u >= 0xE185A1 && u <= 0xE185B5))  /* V */
			{
				if (cd->prev_state != E && cd->prev_state != CI)
					PROCESS_PRIOR_CVC();

				cd->v = (u == 0xE185A0) ? CVC_FILL
							  : u - 0xE185A1;
				cd->prev_state = V;
			}
			else if ((u >= 0xE186A8 && u <= 0xE186BF) ||
				 (u >= 0xE18780 && u <= 0xE18782))  /* Cf */
			{
				if (cd->prev_state != E && cd->prev_state != V)
					PROCESS_PRIOR_CVC();

				cd->cf = u - ((u >= 0xE18780) ? 0xE18766
								 : 0xE186A6);
				cd->prev_state = CF;

				PROCESS_PRIOR_CVC();
			}
			else if (u >= 0xE082A1 && u <= 0xEFBFA6)
			{
				register int	h, i, j, l;
				short		num;

				PROCESS_PRIOR_CVC();

				num = (cd->designated) ?
					(cd->state == ASCII ? 3 : 2) :
					(cd->state == ASCII ? 7 : 6);
				if ((obtail - ob) < num)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}

				for (l = 0, h = MAX_U2ISO2022_NUM; l < h; )
				{
					i = (l + h) / 2;
					if (utf82iso2022_tbl[i].utf8 == u)
						break;
					else if (utf82iso2022_tbl[l].utf8 == u)
					{
						i = l;
						break;
					}
					else if (utf82iso2022_tbl[h].utf8 == u)
					{
						i = h;
						break;
					}
					else if (utf82iso2022_tbl[i].utf8 < u)
						l = i + 1;
					else
						h = i - 1;
				}

				if (utf82iso2022_tbl[i].utf8 != u)
				{
					/* Let's assume the code is non-
					 * identical. */
					if (cd->designated &&
					    cd->state == WANSUNG)
					{
						if (ob >= obtail)
						{
							errno = E2BIG;
							ret_val = (size_t)-1;
							break;
						}
						*ob++ = SI;
						cd->state = ASCII;
					}
					*ob++ = NON_IDENTICAL;
					*ob++ = NON_IDENTICAL;
					ret_val += 2;
				}
				else
				{
					if (!cd->designated)
					{
						*ob++ = ESC;
						*ob++ = '$';
						*ob++ = ')';
						*ob++ = 'C';
						cd->designated = 1;
					}
					if (cd->state == ASCII)
					{
						*ob++ = SO;
						cd->state = WANSUNG;
					}
					*ob++ = (char)
						((utf82iso2022_tbl[i].code >> 8)
							& 0x7F);
					*ob++ = (char)(utf82iso2022_tbl[i].code
							& 0x7F);
				}
			}
			else
			{
				PROCESS_PRIOR_CVC();

				/* Let's assume the code is non-identical. */
				if ((obtail - ob) < 2)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
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

			PROCESS_PRIOR_CVC();

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
			ib += offset;

			/* Let's assume the code is non-identical. */
			offset = (offset > 2) ? 2 : 1;
			if ((obtail - ob) < offset)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
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
}  /* end of size_t _icv_iconv(_conv_desc*, char**, size_t*, char**, size_t*).*/
