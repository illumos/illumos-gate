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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define	MSB	0x80

#define NON_ID_CHAR_BYTE1 0x21  /* non-identified character */
#define NON_ID_CHAR_BYTE2 0x75  /* non-identified character */

#define gbk_2nd_byte(v)   ( (v) >= 0x40 && (v) <= 0xfe && (v) != 0x7f )
#define gbk4_2nd_byte(v)  ( (v) >= 0x30 && (v) <= 0x39 )
#define gbk4_3rd_byte(v)   ( (v) >= 0x81 && (v) <= 0xfe )
#define gbk4_4th_byte(v)  gbk4_2nd_byte(v)

enum	_GSTATE { G0, G1, G2, G3, G4};


typedef struct _icv_state {
	char	_lastc;
	short	_gstate;
} _iconv_st;

/*
 * Open; called from iconv_open()
 */
void *
_icv_open()
{
	_iconv_st *st;

	if ((st = (_iconv_st *)malloc(sizeof(_iconv_st))) == NULL) {
		errno = ENOMEM;
		return ((void *) -1);
	}

	st->_gstate = G0;
	return ((void *)st);
}


/*
 * Close; called from iconv_close()
 */
void
_icv_close(_iconv_st *st)
{
	if (st == NULL)
		errno = EBADF;
	else
		free(st);
}


/*
 * Actual conversion; called from iconv()
 */
/*=======================================================================
 * 				30-39
 *			 |--------------------------|
 *      +----------------|--------------------+     |
 *      V   MSB          |  MSB       ascii  |      | 81-fe
 *  +-> G0 ------------> G1 ------> G2 -------+    G3------G4
 *  | ascii  (~{)    ^   MSB        | |(~})   	     30-39 |
 *  +----+               +----------+  ---------------------
 *=======================================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t*inbytesleft,
			char **outbuf, size_t*outbytesleft)
{
	if (st == NULL) {
		errno = EBADF;
		return -1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->_gstate = G0;
		return 0;
	}

	errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if ( **inbuf & MSB ) {
		   if(*outbytesleft >=2) {
		    **outbuf = '~';
                    *(*outbuf+1) = '{';
		    (*outbuf) += 2, (*outbytesleft) -= 2;
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		    } else {
			errno = E2BIG;
			return (size_t)-1;
                    }

		} else {
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		    if (**inbuf == '~') {
		    **outbuf = '~';
		    (*outbuf)++, (*outbytesleft)--;
		    }
		}
		break;
	    case G1:
		if ( gbk4_2nd_byte((unsigned char) **inbuf )) {
			st->_lastc = **inbuf;
			st->_gstate = G3;
		} else if ( **inbuf  & MSB ) {
		   if(*outbytesleft >=2) {
			**outbuf = st->_lastc - 0x80;
			*(*outbuf+1) = **inbuf - 0x80;
			(*outbuf) += 2, (*outbytesleft) -= 2;
			st->_gstate = G2;
		    } else {
                        errno = E2BIG;
                        return (size_t)-1;
                    }
                } else if ( gbk_2nd_byte((unsigned char ) **inbuf )) {
                        if ( *outbytesleft >= 2 ) {
                                **outbuf = NON_ID_CHAR_BYTE1;
                                *(*outbuf +1) = NON_ID_CHAR_BYTE2;
                                (*outbuf) += 2, (*outbytesleft) -= 2;
                                st->_gstate = G2;
                        } else {
                                errno = E2BIG;
                                return (size_t)-1;
                        }
		} else {
		    errno = EILSEQ;
		    return (size_t)-1;
		}
		break;
	    case G2:
		if ( **inbuf & MSB ) {
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {
		   if(*outbytesleft >=3) {
		    **outbuf = '~';
                    *(*outbuf+1) = '}';
                    *(*outbuf+2) = **inbuf;
		    (*outbuf) += 3, (*outbytesleft) -= 3;
		    st->_gstate = G0;
		    }else {
                        errno = E2BIG;
                        return (size_t)-1;
                    }

		}
		break;
	    case G3:
		if ( gbk4_3rd_byte( (unsigned char)**inbuf )) {
		    st->_lastc = **inbuf;
		    st->_gstate = G4;
		} else {
			errno = EILSEQ;
			return (size_t)-1;
		}
		break;
	    case G4:
		if ( gbk4_4th_byte( (unsigned char) **inbuf )) {
			if ( *outbytesleft >= 2 ) {
				**outbuf = NON_ID_CHAR_BYTE1;
				*(*outbuf +1) = NON_ID_CHAR_BYTE2;
				(*outbuf) += 2, (*outbytesleft) -= 2;
				st->_gstate = G2;
			} else {
				errno = E2BIG;
				return (size_t)-1;
			}
		} else {
			errno = EILSEQ;
			return (size_t)-1;
		}
		break;
	    default:
		errno = EILSEQ;
		return (size_t)-1;
	    }

	    (*inbuf)++, (*inbytesleft)--;
	    if (errno)
		return -1;
	}

	if (st->_gstate != G0 && st->_gstate != G2 && *inbytesleft == 0) {
		errno = EINVAL;
		return (size_t)-1;
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return -1;
	}
	return (*inbytesleft);
}
