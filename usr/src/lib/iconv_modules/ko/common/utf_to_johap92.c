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
#include "hangulcode.h"
#include "ktable.h"
#include "utf_johap92.h"
#include "common_defs.h"

#define	MSB	0x80	/* mask for most-significant-bit */
typedef enum _USTATE {U0 = 0, U1, U2, U3, U4, U5, U6,UX} USTATE;

typedef struct _icv_state {
	unsigned char _buffer[6];
	USTATE _ustate;
	unsigned short _count;
	int _errno;
} _iconv_st;

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_iconv_st *st;
	if((st = (_iconv_st *) malloc(sizeof(_iconv_st))) == NULL){
		errno = ENOMEM;
		return ((void *) -1);
	}
	st->_ustate = U0;
	st->_errno = 0;
	st->_count = 0;
/*
	RESET_CONV_DESC();
*/
	return ((void *) st);
}  /* end of int _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(_iconv_st* st)
{
	if(!st)
		errno = EBADF;
	else
		free(st);
}  /* end of void _icv_close(int*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(_iconv_st* st, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	hcode_type utf8_code, johap92_code;

	if(st == NULL){
		errno = EBADF;
		return ((size_t) -1);
	}

	if (!inbuf || !(*inbuf)){
		st->_ustate = U0;
		st->_errno = 0;
		return((size_t)0);
	}

	st->_errno = 0;
	errno = 0;

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;


	while (ib < ibtail)
	{
		unsigned char first_byte;
		switch(st->_ustate){
		case U0:	/* begining of new utf-8 char sequence */
			if((*ib & MSB) == 0){	/* MSB is off, so ASCII */
				if(ob >= obtail){
					errno = E2BIG;
					ret_val = (size_t) -1;
					break;
				}
				*ob++ = *ib++;

			} else { 	/* Now, begining of UTF-8 */
				if((*ib & 0xe0) == 0xc0){
				/* 2-byte utf-8				*/
				/* true if *ib is (0xc0 ~ 0xdf) 	*/
				/* but, need to filter out the range 	*/
				/* 0xc0 ~ 0xc1				*/

					if(number_of_bytes_in_utf8_char[(unsigned char) *ib] ==
					    ICV_TYPE_ILLEGAL_CHAR)
						st->_errno = errno = EILSEQ;
					else {
						st->_ustate = U1;
						st->_buffer[0] = *ib;
					}
				} else if((*ib & 0xf0) == 0xe0){
				/* 3 byte utf-8				*/
				/* if *ib is (0xe0 ~ 0xef)		*/
					st->_ustate = U2;
					st->_buffer[0] = *ib;
				} else {
				/* 4 byte utf-8				*/
				/* true if *ib is (0xf0 ~ 0xff)		*/
				/* but, need to screen out the range	*/
				/* 0xf5 ~ 0xff				*/
					if(number_of_bytes_in_utf8_char[(unsigned char) *ib] ==
					    ICV_TYPE_ILLEGAL_CHAR)
						st->_errno = errno = EILSEQ;
					else {
						st->_ustate = U4;
						st->_buffer[0] = *ib;

					}
				}
				st->_count++;
				ib++;
			}
			break;
		case U1:	/* we are getting 2nd byte of 2byte utf-8	*/
				/* convert it right here			*/
			if((*ib & 0xc0) == MSB){
				st->_ustate = UX;
				st->_buffer[1] = *ib;
				st->_count++;
				continue;/* Now, we gotta do the real conversion*/
					 /* becuase we just came to an the last	*/
					 /* byte of utf-8 character		*/
			} else {
				ib++;
				st->_errno = errno = EILSEQ;
				ret_val = (size_t) -1;
				break;
			}
			break;
		case U2:	/* 2nd byte of 3byte utf-8			*/
			first_byte = (unsigned char) st->_buffer[0];
				/* basic utf-8 validity check first...		*/
			if((*ib & 0xc0) == MSB){
				/* if okay, then what about the range of this byte?	*/
				/* if the first byte is 0xed, it is illegal sequence	*/
				/* if the second one is between 0xa0 and 0xbf		*/
				/* because surrogate section is ill-formed		*/

				if((unsigned char)*ib < valid_min_2nd_byte[first_byte] ||
				    (unsigned char)*ib > valid_max_2nd_byte[first_byte]){
					st->_errno = errno = EILSEQ;
				} else {
					st->_ustate = U3;
					st->_buffer[1] = *ib;
					st->_count++;
				}

			} else {
				st->_errno = errno = EILSEQ;
			}
			ib++;
			break;
		case U3:	/* 3rd byte of 3byte utf-8			*/
			if((*ib & 0xc0) == MSB){
				st->_ustate = UX;
				st->_buffer[2] = *ib;
				st->_count++;
				continue;/* Now, we gotta do the real conversion*/
					 /* becuase we just came to an the last */
					 /* byte of utf-8 character		*/
			} else {
				st->_errno = errno = EILSEQ;
				ret_val = (size_t) -1;
				ib++;
				break;
			}
			break;
		case U4:	/* 2nd byte of 4byte utf-8			*/
			first_byte = st->_buffer[0];
			if((*ib & 0xc0) == MSB){
				if((unsigned char)*ib < valid_min_2nd_byte[first_byte] ||
				  (unsigned char)*ib > valid_max_2nd_byte[first_byte]){
					st->_errno = errno = EILSEQ;
				} else {
					st->_ustate = U5;
					st->_buffer[1] = *ib;
					st->_count++;
				}
			} else {
				st->_errno = errno = EILSEQ;
			}
			ib++;
			break;
		case U5:	/* 3rd byte of 4byte utf-8			*/
			if((*ib & 0xc0) == MSB){
				st->_ustate = U6;
				st->_buffer[2] = *ib;
				st->_count++;
			} else {
				st->_errno = errno = EILSEQ;
			}
			ib++;
			break;
		case U6:	/* 4th byte of 4byte utf-8			*/
			if((*ib & 0xc0) == MSB){
				if((obtail - ob) < 2){
					st->_errno = errno = E2BIG;
				} else {
					*ob++ = NON_ID_CHAR;
					*ob++ = NON_ID_CHAR;
					st->_ustate = U0;
				}
			} else {
				st->_errno = errno = EILSEQ;
			}
			ib++;
			break;
		case UX:
			/*******************************************************
			 * convert valid utf-8 sequence gathered in the
			 * st->_buffer to euc
			 *******************************************************/
			utf8_code.code = 0;
			switch(st->_count){
			case 2: /* 2byte utf-8 code */
				utf8_code.byte.byte3 = st->_buffer[0];
				utf8_code.byte.byte4 = st->_buffer[1];
				break;
			case 3: /* 3byte utf-8 code */
				utf8_code.byte.byte2 = st->_buffer[0];
				utf8_code.byte.byte3 = st->_buffer[1];
				utf8_code.byte.byte4 = st->_buffer[2];
				break;
			}
			unsigned short _utf8_to_jahap92(utf_code.code)

			if (euc_code.code != 0) {
			/* If find something -> EUC code */
                                *ob++ = euc_code.byte.byte3;
                                *ob++ = euc_code.byte.byte4;
                        }
                        else
                        {
                                /* Let's assume the code is not identifiable */
                                if ((obtail - ob) < 2)
                                {
                                        errno = E2BIG;
                                        ret_val = (size_t)-1;
                                }
                                *ob++ = NON_IDENTICAL;
                                *ob++ = NON_IDENTICAL;
                                ret_val += 2;
                        }
			st->_ustate = U0;
			st->_count = 0;
			ib++;
			break;
		default:	/* You are not supposed to get here...		*/
				/* But, just only for the integrity		*/
			st->_errno = errno = EILSEQ;
			st->_ustate = U0;
			st->_count = 0;
			break;

		}
		if(st->_errno){
#ifdef DEBUG
			fprintf(stderr,  "st->_errno=%d\tst->_ustate=%d\n", st->_errno, st->_ustate);
#endif /* DEBUG */
			break;
		}

	}
	if(errno) return ((size_t) -1);

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*).*/









unsigned short _utf8_to_jahap92(unsigned long utf_code)
{
	int low, mid, high;
	low = 0, high = MAX_U2J92_NUM;
	while(low < high){
		mid = (low + high)/2;
		if(utf8_to_johap92_tbl[mid].utf8 = utf_code){
			break;
		} else if(utf8_to_johap92_tbl[mid].utf8 > utf_code){
			high = mid - 1;
		} else if(utf8_to_johap92_tbl[mid].utf8 < utf_code){
			low = mid + 1;
		}
	}
}
