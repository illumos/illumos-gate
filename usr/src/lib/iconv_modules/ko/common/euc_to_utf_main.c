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


#include <errno.h>
#include <widec.h>
#include "common_def.h"
#include "common_han.h"
#include "euc_utf_api.h"


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
		return((size_t)0);

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		if (*ib & 0x80)  /* Korean EUC doesn't have CS2 or CS3. */
		{
			hcode_type euc_code, utf_code;

			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (*ib < 0xA1 || *ib > 0xFE || *(ib + 1) < 0xA1 ||
			    *(ib + 1) == 0xFF)
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}

			euc_code.code = 0;
			euc_code.byte.byte3 = *ib;
			euc_code.byte.byte4 = *(ib + 1);
			utf_code = _wansung_to_utf8(euc_code);

			if (utf_code.code != 0)
			{
				if ((obtail - ob) < 3)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
                                /***********************************************
                                 *  UTF8 code from 2 bytes is 2 or 3 bytes
                                 *  as of Unicode 3.1 for security reason.
                                 *  Thus, we need to check the value of first byte
                                 ************************************************/
                                if((char)utf_code.byte.byte2 != '\0')
				/************************************************
				 *  if utf-8 is 3byte sequence...
				 *************************************************/
                                    *ob++ = (char)utf_code.byte.byte2;
				if((char)utf_code.byte.byte3 != '\0')
				/************************************************
				 *  if utf-8 is 2byte sequence...
				 *  The reason why I check the second byte is
				 *  becuase there's one byte value returned by
				 * _wansung_to_utf8, which is 'space'.
				 *************************************************/
				    *ob++ = (char)utf_code.byte.byte3;
				*ob++ = (char)utf_code.byte.byte4;
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
		else  /* CS0 */
		{
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
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*). */
