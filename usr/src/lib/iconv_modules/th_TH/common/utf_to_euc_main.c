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
#include "common_thai.h"
#include "utf_euc_api.h"

#include "common_defs.h"
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
		else if ((*ib & 0xF0) == 0xE0)	/* 16 bits */
		{
			hcode_type utf8_code, euc_code;

			if ((ibtail - ib) < 3)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

            /* UNICODE 3.2 :eliminate non-secure UTF-8 sequence  */
			if (*(ib+1)<valid_min_2nd_byte[*ib] || *(ib+1)>valid_max_2nd_byte[*ib])
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}
			else if ((*(ib+2)&0xC0)^0x80)
			{
				errno = EILSEQ;
			        ret_val = (size_t)-1;
				break;
			}
			else if (*ib==0xEF && *(ib+1)==0xBF && (*(ib+2)==0xBF || *(ib+2)==0xBE))
			{ /*U+FFFE , U+FFFF*/
				errno = EILSEQ;
			        ret_val = (size_t)-1;
				break;
			}

			utf8_code.byte.byte1 = 0;
			utf8_code.byte.byte2 = *ib;
			utf8_code.byte.byte3 = *(ib + 1);
			utf8_code.byte.byte4 = *(ib + 2);

			euc_code = _utf8_to_eucTH(utf8_code);

			if (euc_code.code != 0) {
				/* If find something -> EUC code */
				*ob++ = euc_code.byte.byte4;
			}
			else
			{
				/* Let's assume the code is non-identical. */
				if ((obtail - ob) < 1)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = NON_IDENTICAL;
				ret_val += 1;
			}
			ib += 3;
		}
		else  /* 11, 21, 26 & 31 bits codes won't be able to convert. */
		{
			short int offset;

			errno = 0;
			offset = number_of_bytes_in_utf8_char[*ib];
			if (offset == ICV_TYPE_ILLEGAL_CHAR )
			{
				errno = EILSEQ;
			}
			else if (ibtail-ib < offset)
			{
				errno = EINVAL;
			}
			else if (*(ib+1)<valid_min_2nd_byte[*ib] || *(ib+1)>valid_max_2nd_byte[*ib])
			{
				errno = EILSEQ;
			}
			else /* check the remaining byte [0x80, 0xBF] */
			{
				int i;
				for(i=2;i<offset;i++)
				{
					if ((*(ib+i) & 0xC0) ^ 0x80)
					{
						errno = EILSEQ;
						break;
					}
				}
			}
			if(errno)
			{
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
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*).*/
