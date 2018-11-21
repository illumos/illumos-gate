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
#include "iscii.h"

#define MSB        0x80    /* most significant bit */
#define ONEBYTE    0xff    /* right most byte */

#define REPLACE_CHAR1  0xEF     /* invalid conversion character */
#define REPLACE_CHAR2  0xBF
#define REPLACE_CHAR3  0xBD

#define UTF8_SET1B(b,v)      \
    (b[0]=(v&0x7f))

#define UTF8_SET2B(b,v)      \
    (b[0]=(0xc0|((v>>6)&0x1f))); \
    (b[1]=(0x80|((v&0x3f))))

#define UTF8_SET3B(b,v)      \
    (b[0]=(0xe0|((v>>12)&0xf))); \
    (b[1]=(0x80|((v>>6)&0x3f))); \
    (b[2]=(0x80|((v&0x3f))))

typedef struct _icv_state {
     char    keepc[3];    /* keepc[0] is attr, keepc[1] and keepc[2] are lookup-ed */
     short   pState;      /* Previous State */
     int    _errno;
} _iconv_st;

enum _CSTATE { S_BASIC, S_ATR, S_EXT, S_NONE };

#define have_nukta(isc_type) ( nukta_type[isc_type] != NULL )
#define have_EXT(isc_type) ( EXT_type[isc_type] != NULL )
#define FIRST_CHAR  0xA0

static int copy_to_outbuf(ucs_t uniid, char *buf, size_t buflen);

static ucs_t
get_nukta(uchar iscii, int type)
{
    int indx = iscii - FIRST_CHAR;
    int *iscii_nukta = nukta_type[type];

    return ((indx >= 0) ? iscii_nukta[indx] : 0 );
}

static ucs_t
get_EXT(uchar iscii, int type)
{
    int indx = iscii - FIRST_CHAR;
    int *iscii_EXT = EXT_type[type];

    return ((indx >= 0) ? iscii_EXT[indx] : 0 );
}

static ucs_t
traverse_table(Entry *entry, int num,  uchar iscii)
{
    int i=0;
    ucs_t retucs=0;

    for ( ; i < num; ++i ) {
        Entry en = entry[i];

        if ( iscii < en.iscii ) break;
        if ( iscii >= en.iscii && iscii < en.iscii + en.count ) {
             retucs = en.ucs + ( iscii - en.iscii );
             break;
        }
    }

    return retucs;
}

/*
 * the copy_to_outbuf has to be called before the st->keepc needs to changed.
 * if E2BIG error, keep st->keepc. Will flush it at the beginning of next
 * _icv_iconv() invocation
 */
int
iscii_to_utf8(_iconv_st *st, char *buf, size_t buflen)
{
#define DEV_ATR 0x42
    ucs_t uniid;
    int   nBytes=0;
    ISCII isc_type = isc_TYPE[st->keepc[0] - DEV_ATR];
    Entries en = iscii_table[isc_type];
    /* unsigned int  keepc0 = (unsigned int) (st->keepc[0] & ONEBYTE); */
    unsigned int  keepc1 = (unsigned int) (st->keepc[1] & ONEBYTE);
    unsigned int  keepc2 = (unsigned int) (st->keepc[2] & ONEBYTE);

    if (keepc1 == 0xFF) { /* FFFD */
        if ( buflen < 3 ) {
            errno = E2BIG;
            return 0;
        }

        *buf = (char)REPLACE_CHAR1;
        *(buf+1) = (char)REPLACE_CHAR2;
        *(buf+2) = (char)REPLACE_CHAR3;
        return (3);
    }

    if (keepc2 == 0) { /* Flush Single Character */

        if (keepc1 & MSB) {    /* ISCII - Non-Ascii Codepoints */
            uniid = traverse_table(en.entry, en.items, keepc1);
        } else  /* ASCII */
            uniid = keepc1;

        if ( (nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
        st->keepc[1] = 0;

    } else {
        /* keepc[1] and keepc[2] != 0 */
        if (keepc1 & MSB) {

	    switch (keepc1)
	     {
	      case ISC_ext:

		if ( have_EXT(isc_type) && is_valid_ext_code(keepc2) )
		  {  /* EXT only supported in Devanagari script */

                     uniid = get_EXT(keepc2, isc_type);
                     if ((nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
		  }
		else
		     errno = EILSEQ;

	        st->keepc[1] = st->keepc[2] = 0;
		break;
	      case ISC_halant:
                /* test whether there has enough space to hold the converted bytes */
                if ((keepc2 == ISC_halant || keepc2 == ISC_nukta) && buflen < 6 )
                    goto E2big;

                uniid = traverse_table(en.entry, en.items, keepc1);
                if ((nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
                st->keepc[1] = st->keepc[2];

                if ( keepc2 == ISC_halant || keepc2 == ISC_nukta )
                  {
                     int nbytes_2 = 0;
                     if (keepc2 == ISC_halant) uniid = UNI_ZWNJ; /* explicit Halant */
                     if (keepc2 == ISC_nukta) uniid = UNI_ZWJ; /* soft Halant */

                     if ((nbytes_2 = copy_to_outbuf(uniid, buf+nBytes, buflen)) == 0) goto E2big;
                     st->keepc[1] = st->keepc[2] = 0;

                     nBytes += nbytes_2;
                  }

                break;
	      case ISC_danda:
		if ( isc_type == DEV && keepc2 == ISC_danda )
		  { /* only in Devanagari script, it works */
		     uniid = UNI_DOUBLE_DANDA;
                     if ((nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
                     st->keepc[1] = st->keepc[2] = 0;

		     break;
		  }

		/* fall into default case, convert the DANDA if it isn't DOUBLE_DANDA */
		/* FALLTHRU */
	      default:

		uniid = traverse_table(en.entry, en.items, keepc1);

                if ( have_nukta(isc_type) &&  keepc2 == ISC_nukta) {
		    /* then try to test whether it is Nukta Cases */
                    int    ucs;

                    if (( ucs = get_nukta(keepc1, isc_type)) != 0 ) {

                       uniid = ucs;

                       if ( (nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
                       st->keepc[1] = st->keepc[2] = 0;
                    } else {
                       if ( (nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
                       st->keepc[1] = st->keepc[2];
                    }
                } else {
                    if ( (nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
                    st->keepc[1] = st->keepc[2];
                }
		break;
	     } /* end of switch */
        } else { /* ASCII */
            uniid = keepc1;
            if ( (nBytes = copy_to_outbuf(uniid, buf, buflen)) == 0) goto E2big;
            st->keepc[1] = st->keepc[2];
        }
        st->keepc[2] = 0;
    }

E2big:
    return nBytes;
}

static int
copy_to_outbuf(ucs_t uniid, char *buf, size_t buflen)
{
    if (uniid > 0) {
        if (uniid <= 0x7f) {
            if (buflen < 1) {
                errno = E2BIG;
                return(0);
            }
            UTF8_SET1B(buf, uniid);
            return (1);
        }

        if (uniid >= 0x80 && uniid <= 0x7ff) {
            if (buflen < 2) {
                errno = E2BIG;
                return(0);
            }
            UTF8_SET2B(buf, uniid);
            return (2);
        }

        if (uniid >= 0x800 && uniid <= 0xffff) {
            if (buflen < 3) {
                errno = E2BIG;
                return(0);
            }
            UTF8_SET3B(buf, uniid);
            return (3);
        }
    } else { /* Replacement Character */
        if ( buflen < 3 ) {
            errno = E2BIG;
            return 0;
        }

        *buf = (char)REPLACE_CHAR1;
        *(buf+1) = (char)REPLACE_CHAR2;
        *(buf+2) = (char)REPLACE_CHAR3;
        return (3);
    }

    /* This code shouldn't be reached */
    return (0);
}

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
    st->keepc[0] = DEV_ATR;
    st->pState = S_BASIC;

    return ((void*)st);
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
    int   n;
    short curState;

    if (st == NULL) {
        errno = EBADF;
        return ((size_t) -1);
    }

    if (inbuf == NULL || *inbuf == NULL) { /* Reset request */
        st->keepc[0] = DEV_ATR;
        st->pState = S_BASIC;
        st->_errno = 0;
        return ((size_t)0);
    }

    /* flush if possible */
    if ( st->_errno == E2BIG ) {
        n = iscii_to_utf8(st, *outbuf, *outbytesleft);
        (*outbuf) += n;
        (*outbytesleft) -= n;
    }

    st->_errno = errno = 0; /* reset internal and external errno */

    /* a state machine for interpreting ISCII code */
    while (*inbytesleft > 0 && *outbytesleft > 0) {
        unsigned int curChar = (unsigned int)(**inbuf & ONEBYTE);
        unsigned int prevChar = (unsigned int)(st->keepc[1] & ONEBYTE);

        if (curChar == ISC_ext)
            curState = S_EXT;
        else if (curChar == ISC_atr)
            curState = S_ATR;
        else
            curState = S_BASIC;

        switch (curState) {
        case S_BASIC:
            if (prevChar == 0)
                st->keepc[1] = curChar;
            else
                st->keepc[2] = curChar;

            if (st->pState == S_ATR) {
                /* clear the keepc[1], which is part of attribute */
                st->keepc[1] = 0;
                /* change the attribute for Indian Script Fonts */
                if ((curChar >= 0x42) && (curChar <= 0x4b) && curChar != 0x46) {
                    st->keepc[0] = curChar;
                }
                /* other attributes such as display attributes would be ignored */
            } else { /* Handle Cases and Flush */

                if ((curChar > 0 && curChar <= 0x7f) || prevChar != 0) {
                    n=iscii_to_utf8(st, *outbuf, *outbytesleft);
                    if (n > 0) {
                        (*outbuf) += n;
                        (*outbytesleft) -= n;
                    } else   /* don't return immediately, need advance the *inbuf */
                         st->_errno = errno;
                }
            }
            break;
        case S_ATR:
        case S_EXT: /* Do nothing */
            if (st->pState == S_BASIC) { /* Flush */
                if ( st->keepc[1] == 0 )
                 {
                   if (curState == S_EXT) st->keepc[1] = ISC_ext;
                   break;
                 }
                n = iscii_to_utf8(st, *outbuf, *outbytesleft);
                if (n > 0) {
                    (*outbuf) += n;
                    (*outbytesleft) -= n;
                } else /* don't return immediately */
                    st->_errno = errno;

                if (curState == S_EXT) st->keepc[1] = ISC_ext;
            } else {
                errno = EILSEQ;
                return (size_t)-1;
            }

            break;
        default:  /* should never come here */
            st->_errno = errno = EILSEQ;
            st->pState = S_BASIC;    /* reset state */
            break;
        }

        st->pState = curState;

        (*inbuf)++;
        (*inbytesleft)--;

        if (errno)
            return(size_t)-1;
    }

    if (*inbytesleft > 0 && *outbytesleft == 0) {
        /* in this case, the st->_errno is zero */
        errno = E2BIG;
        return(size_t)-1;
    }

    return (size_t)(*inbytesleft);
}
