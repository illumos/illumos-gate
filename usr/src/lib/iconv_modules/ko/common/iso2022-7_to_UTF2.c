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
#include "iso2022_utf.h"


/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	cd->designator = NDY;
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
		cd->designator = NDY;
		cd->state = ASCII;
		return((size_t)0);
	}

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		if (cd->designator == KSC5601)
		{
			unsigned short	wcode;
			unsigned long	ci, v, cf;
			char		result;
			extern char	_wansung_to_utf8(unsigned long*,
						unsigned long*,
						unsigned long*,
						unsigned short);

			if (*ib == SI)
			{
				cd->state = ASCII;
				ib++;
				continue;
			}
			else if (*ib == SO)
			{
				cd->state = WANSUNG;
				ib++;
				continue;
			}
			else if ((*ib == ' ' && cd->state == WANSUNG) ||
				 cd->state == ASCII)
			{
				if (ob >= obtail)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = *ib++;
				continue;
			}

			/* Pure KS C 5601 Wansung code */
			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (*ib < 0x21 || *ib > 0x7D || *(ib + 1) < 0x21 ||
			    *(ib + 1) == 0x7F)
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}

			if ((result = _wansung_to_utf8(&ci, &v, &cf,
					(((unsigned short)*ib << 8) |
					 ((unsigned short)*(ib + 1) & 0xFF) |
					 0x8080)))
			    == HANGUL)
			{
				if ((obtail - ob) < (cf ? 9 : 6))
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = (char)((ci >> 16) & 0xFF);
				*ob++ = (char)((ci >> 8) & 0xFF);
				*ob++ = (char)(ci & 0xFF);
				*ob++ = (char)((v >> 16) & 0xFF);
				*ob++ = (char)((v >> 8) & 0xFF);
				*ob++ = (char)(v & 0xFF);
				if (cf)
				{
					*ob++ = (char)((cf >> 16) & 0xFF);
					*ob++ = (char)((cf >> 8) & 0xFF);
					*ob++ = (char)(cf & 0xFF);
				}
			}
			else if (result == HANJA_OR_SYMBOL)
			{
				if ((obtail - ob) < 3)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = (char)((ci >> 16) & 0xFF);
				*ob++ = (char)((ci >> 8) & 0xFF);
				*ob++ = (char)(ci & 0xFF);
			}
			else  /* FAILED - this means input char isn't belong to
			       *	  input codeset. */
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}
			ib += 2;

		}
		else
		{
			if (*ib == ESC)
			{
				if ((ibtail - ib) < 4)
				{
					errno = EINVAL;
					ret_val = (size_t)-1;
					break;
				}

				if (*(ib + 1) == '$' && *(ib + 2) == ')' &&
				    *(ib + 3) == 'C')
				{
					cd->designator = KSC5601;
					ib += 4;
					continue;
				}
			}

			if (ob >= obtail)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(_conv_desc*, char**, size_t*, char**, size_t*).*/
