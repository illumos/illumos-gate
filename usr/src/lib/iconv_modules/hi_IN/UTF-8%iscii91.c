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
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include "iscii.h"
#include "common_defs.h"

#define MSB          0x80    /* most significant bit */
#define ONEBYTE      0xff    /* right most byte */

#define REPLACE_CHAR '?'

#define utf8_len(Ch) (Ch < 0x80 ? 1 : (Ch  < 0xe0 ? 2 : (Ch < 0xf0 ? 3 : (Ch < 0xf8 ? 4 : (Ch < 0xfc ? 5 : 6)))))

#define analyze_utf8(Ch, Mask, nBytes) \
    if (Ch < 128) { \
        nBytes = 1; \
        Mask = 0x7f; \
      } else if ((Ch & 0xe0) == 0xc0) { \
        nBytes = 2; \
        Mask = 0x1f; \
    } else if ((Ch & 0xf0) == 0xe0) { \
        nBytes = 3; \
        Mask = 0x0f; \
    } else if ((Ch & 0xf8) == 0xf0) { \
        nBytes = 4; \
        Mask = 0x07; \
    } else if ((Ch & 0xfc) == 0xf8) { \
        nBytes = 5; \
        Mask = 0x03; \
    } else if ((Ch & 0xfe) == 0xfc) { \
        nBytes = 6; \
        Mask = 0x01; \
    } else \
        nBytes = -1;

#define ucs2_from_utf8(mUCS, Ch, Ct, Mask, Len)   \
    (mUCS) = (Ch)[0] & (Mask); \
    for ((Ct) = 1; (Ct) < (Len); ++(Ct))  { \
        if ( ( (Ch)[(Ct)] & 0xc0) != 0x80) { \
             (mUCS) = -1; \
            break; \
        } \
        (mUCS) <<= 6; \
        (mUCS) |= ((Ch)[(Ct)] & 0x3f); \
    } \


typedef struct _icv_state {
    char    aATR;
    uchar_t   keepc[4];
    int     halant_context; /* preceded by the Halant character or not */
    int     _ustate;
    int     _errno;
} _iconv_st;

enum _CSTATE { U0, U1, U2, U3, U4, U5, U6 };

/*
 * Open; called from iconv_open()
 */
void *
_icv_open()
{
    _iconv_st *st;

    if ((st = (_iconv_st*)malloc(sizeof(_iconv_st))) == NULL) {
        errno = ENOMEM;
        return ((void*)-1);
    }

    bzero(st, sizeof(_iconv_st));
    st->aATR = 0x42; /* Devanagiri */

    return ((void*)st);
}

typedef enum { t_NONE, t_NUKTA, t_EXT, t_HALANT, t_DOUBLE_DANDA } Type;

static int
traverse_table(Entry *entry, int num,  ucs_t ucs, Type *type)
{
    int i=0;
    int retc=0;

    *type = t_NONE;

    for ( ; i < num; ++i ) {
        Entry en = entry[i];

        if (en.count == NUKTA || en.count == EXT || en.count == HALANT || en.count == DOUBLE_DANDA) {
            if ( ucs < en.ucs ) break;
            if ( ucs == en.ucs ) { /* found */
	        if ( en.count == NUKTA ) *type = t_NUKTA;
	        if ( en.count == EXT ) *type = t_EXT;
	        if ( en.count == HALANT ) *type = t_HALANT;
	        if ( en.count == DOUBLE_DANDA ) *type = t_DOUBLE_DANDA;
		retc = en.iscii;
                break;
            }
        } else {
           if ( ucs < en.ucs ) break;
           if ( ucs >= en.ucs && ucs < en.ucs + en.count ) {
               retc = en.iscii + ( ucs - en.ucs );
               break;
           }
        }
    }

    return retc;
}

static int
ucs_to_iscii(ucs_t uiid, char **outbuf, size_t *outbytesleft, int isc_type, int *halant_context)
{
    int nBytesRet = 0 ;
    Type type = t_NONE;
    int iscii;
    Entries en = unicode_table[isc_type];

    if ( *outbytesleft == 0 ) {
        errno = E2BIG;
        return 0;
    }

    iscii = traverse_table(en.entry, en.items,  uiid, &type);
    if ( iscii == 0 ) {
        **outbuf = REPLACE_CHAR;
        nBytesRet ++;
    } else {
        if ( type != t_NONE ) {

            /* buggy code */
            if ( *outbytesleft < 2 ) {
                errno = E2BIG;
                return 0;
            }

            switch (type)
            {
              case t_NUKTA:
		**outbuf = (uchar_t) iscii;
		*(*outbuf+1) = ISC_nukta;
                nBytesRet = 2;

		break;
              case t_EXT:
                **outbuf =  ISC_ext;
                *(*outbuf+1) = (uchar_t) iscii;
                nBytesRet = 2;

                break;
              case t_HALANT:
                if ( (uiid == UNI_ZWJ || uiid == UNI_ZWNJ) && *halant_context )
                 {
                   if ( uiid == UNI_ZWJ ) **outbuf = ISC_nukta; /* soft halant */
		   else **outbuf = ISC_halant; /* explicit halant */

		   nBytesRet = 1;
                 } /* consume the UNI_ZWNJ or UNI_ZWJ if *halant_context is 0 */

                break;
              case t_DOUBLE_DANDA:
                **outbuf =  ISC_danda;
                *(*outbuf+1) = (uchar_t) iscii;
                nBytesRet = 2;
                break;
              case t_NONE:
                /* Not reached */
                break;
            }
        } else {
            **outbuf = (uchar_t) iscii;
            nBytesRet = 1;
        }
    }

    /* if iscii == ISC_halant but type == t_HALANT, set *halant_context to 0 */
    if ( iscii == ISC_halant && type == t_NONE ) *halant_context = 1;
    else *halant_context = 0;

    return nBytesRet;
}

/*
 * Close; called from iconv_close()
 */
void
_icv_close(_iconv_st *st)
{
    if (!st)
        errno = EBADF;
    else
        free(st);
}

/*
 * Conversion routine; called from iconv()
 */
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
       char **outbuf, size_t *outbytesleft)
{
    int n=0;

    if (st == NULL)    {
        errno = EBADF;
        return ((size_t) -1);
    }


    if (inbuf == NULL || *inbuf == NULL) {  /* Reset request. */
        st->aATR = 0x42; /* Devangiri */
        st->_ustate = U0;
        st->_errno = 0;
        return ((size_t) 0);
    }

    st->_errno = errno = 0;

    while (*inbytesleft > 0 && *outbytesleft > 0) {

        uchar_t first_byte;

        switch ( st->_ustate ) {
        case U0:
            if ((**inbuf & MSB) == 0) {     /* ASCII */
                **outbuf = **inbuf;
                (*outbuf)++; (*outbytesleft)--;
            } else if ((**inbuf & 0xe0) == 0xc0) { /* 0xc2..0xdf */

	        /* invalid sequence if the first byte is either 0xc0 or 0xc1 */
	        if ( number_of_bytes_in_utf8_char[((uchar_t) **inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
		   errno = EILSEQ;
	        else {
                   st->_ustate = U1;
                   st->keepc[0] = **inbuf;
		}
            } else if ((**inbuf & 0xf0) == 0xe0) {
                st->_ustate = U2;
                st->keepc[0] = **inbuf;
            } else {
	        /* four bytes of UTF-8 sequences */
	        if ( number_of_bytes_in_utf8_char[((uchar_t) **inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
                   errno = EILSEQ;
	        else {
		   st->_ustate = U4;
		   st->keepc[0] = **inbuf;
		}
            }
            break;
        case U1:
            if ((**inbuf & 0xc0) == MSB) { /* U+0080 -- U+07FF */
                **outbuf = REPLACE_CHAR;
                (*outbuf)++;
                (*outbytesleft)--;
                st->_ustate = U0;
            } else {
                errno = EILSEQ;
            }
            break;
        case U2:

	    first_byte = st->keepc[0];

	    /* if the first byte is 0xed, it is illegal sequence if the second
	     * one is between 0xa0 and 0xbf because surrogate section is ill-formed
	     */
	    if (((uchar_t) **inbuf) < valid_min_2nd_byte[first_byte] ||
		((uchar_t) **inbuf) > valid_max_2nd_byte[first_byte] )
	        errno = EILSEQ;
            else {
                st->_ustate = U3;
                st->keepc[1] = **inbuf;
            }
	    break;
        case U3:
            if ((**inbuf & 0xc0) == MSB) {
                unsigned char    mChar = st->keepc[0];
                ucs_t    ucsid = 0;
                int     i=0, mask=0, len=0;
                ISCII   isc_type;

                st->keepc[2] = **inbuf;

                analyze_utf8(mChar, mask, len);

                ucs2_from_utf8(ucsid, (char *)&st->keepc[0], i, mask, len);

	        /* 0xfffe and 0xffff should not be allowed */
	        if ( ucsid == 0xFFFE || ucsid == 0xFFFF )
		  {
		     errno = EILSEQ;
		     break;
		  }

                get_script_types(ucsid, isc_type);
                if ( isc_type != NUM_ISCII && st->aATR != aTRs[isc_type] ) {
                    if ( *outbytesleft < 2 ) {
                        errno = E2BIG;
                        return (size_t)-1;
                    }

                    **outbuf = (uchar_t)ISC_atr;
                    (*outbuf)++;
                    **outbuf = aTRs[isc_type];
                    (*outbuf)++;
                    (*outbytesleft)-=2;
                    st->aATR = aTRs[isc_type];
                }

                /* UNI_INV, UNI_ZWJ, UNI_ZWNJ would occur within any India Script as
                   Consonant invisible, explicit halant and soft halant */
                if ( ucsid == UNI_INV || ucsid == UNI_ZWNJ || ucsid == UNI_ZWJ )
                   isc_type = isc_TYPE[ st->aATR - 0x42 ];

                if ( isc_type == NUM_ISCII ) {
                    if ( *outbytesleft < 1 ) {
                        errno = E2BIG;
                        return (size_t)-1;
                    }

                    **outbuf = REPLACE_CHAR;
                    (*outbuf)++;
                    (*outbytesleft)--;
                } else {
                    n = ucs_to_iscii(ucsid, outbuf, outbytesleft, isc_type, &st->halant_context);
                    if ( n > 0 ) {
                        (*outbuf) += n;
                        (*outbytesleft) -= n;
                    } else if ( errno == E2BIG ) {
		        /* n == 0 if the ZWJ or ZWNJ has been consumed without error */
                        st->_errno = errno;
                        errno = E2BIG;
                        return (size_t)-1;
                    }
                }
            } else {
                errno = EILSEQ;
                return (size_t)-1;
            }
            st->_ustate = U0;
            break;
	case U4:

	    first_byte = st->keepc[0];

	    /* if the first byte is 0xf0, it is illegal sequence if
	     * the second one is between 0x80 and 0x8f
	     * for Four-Byte UTF: U+10000..U+10FFFF
	     */
	    if (((uchar_t) **inbuf) < valid_min_2nd_byte[first_byte] ||
		((uchar_t) **inbuf) > valid_max_2nd_byte[first_byte] )
	        errno = EILSEQ;
	    else {
	        st->_ustate = U5;
	        st->keepc[1] = **inbuf;
	    }
	    break;
	case U5:
	    if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
	     {
		st->_ustate = U6;
		st->keepc[2] = **inbuf;
	     }
	    else
	        errno = EILSEQ;
	    break;
	case U6:
	    if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
	     {
		st->keepc[3] = **inbuf;
		st->_ustate = U0;

		/* replace with REPLACE_CHAR */
		**outbuf = REPLACE_CHAR;
                (*outbuf)++;
                (*outbytesleft)--;
	     }
	    else
	        errno = EILSEQ;
	    break;
        }

        if (errno)
            break;

        (*inbuf)++;
        (*inbytesleft)--;
       }    /* end of while loop */

    if (errno) return (size_t) -1;

    if (*inbytesleft == 0 && st->_ustate != U0) {
        errno = EINVAL;
        return (size_t)-1;
    }

    if (*inbytesleft > 0 && *outbytesleft == 0) {
        errno = E2BIG;
        return((size_t)-1);
    }

    return (size_t)(*inbytesleft);
}
