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
 * Copyright (c) 2008, by Sun Microsystems, Inc.
 * All rights reserved.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#define __NEED_UNI_2_TCVN__
#include <unicode_tcvn.h>	/* Unicode to TCVN  mapping table */
#include "common_defs.h"
#define NON_ID_CHAR '?'     /* non-identified character */

typedef struct _icv_state {
    int     _errno;    /* internal errno */
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

    st->_errno = 0;
    return ((void *) st);
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
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
    int             utf8_len = 1;
    int             no_id_char_num = 0;
    unsigned char   *op = (unsigned char*)*inbuf;
#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UCS-2 --> TCVN5712  ==========\n");
#endif
    if (st == NULL) {
        errno = EBADF;
        return ((size_t) -1);
    }

    if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
        st->_errno = 0;
        return ((size_t) 0);
    }

    st->_errno = 0; /* Rreset internal errno */
    errno = 0;      /* Rreset external errno */

    /* Convert UTF-8 encoding to TCVN5712 */
    while (*inbytesleft > 0 && *outbytesleft > 0) {
        unsigned long uni = 0;
        unsigned char ch = 0;
        unsigned long temp1 = 0,
                      temp2 = 0,
                      temp3 = 0;

        if(0x00 == (*op & 0x80)) {
            /* 1 byte UTF-8 Charater.*/
             uni = (unsigned short)*op;
             utf8_len = 1;
             goto conving;
        }

        if (*inbytesleft < 2)
            goto errexit;
        if ( 0xc0 == (*op & 0xe0) &&
                0x80 == (*(op + 1) & 0xc0) ) {
            /* 2 bytes UTF-8 Charater.*/
            temp1 = (unsigned short)(*op & 0x1f);
            temp1 <<= 6;
            temp1 |= (unsigned short)(*(op + 1) & 0x3f);
            uni = temp1;
            utf8_len = 2;
            goto conving;
        }

        if (*inbytesleft < 3)
           goto errexit;
        if ( 0xe0 == (*op & 0xf0) &&
                0x80 == (*(op + 1) & 0xc0) &&
                0x80 == (*(op + 2) & 0xc0) ) {
            /* 3bytes UTF-8 Charater.*/
            temp1 = (unsigned short)(*op &0x0f);
            temp1 <<= 12;
            temp2 = (unsigned short)(*(op+1) & 0x3F);
            temp2 <<= 6;
            temp1 = temp1 | temp2 | (unsigned short)(*(op+2) & 0x3F);
            uni = temp1;
            utf8_len = 3;
            goto conving;
        }

        if (*inbytesleft < 4)
            goto errexit;
        if ( 0xf0 == (*op & 0xf8) &&
                0x80 == (*(op + 1) & 0xc0) &&
                0x80 == (*(op + 2) & 0xc0) ) {
            /* 4bytes UTF-8 Charater.*/
            temp1 = *op &0x07;
            temp1 <<= 18;
            temp2 = (*(op+1) & 0x3F);
            temp2 <<= 12;
            temp3 = (*(op+1) & 0x3F);
            temp3 <<= 6;
            temp1 = temp1 | temp2 | temp3 |(unsigned long)(*(op+2) & 0x3F);
            uni = temp1;
            utf8_len = 4;
            goto conving;
        }

        /* unrecognize byte. */
        st->_errno = errno = EILSEQ;
        errno = EILSEQ;
        return ((size_t)-1);

conving:
        if (uni_2_tcvn(uni, &ch) == 1) {
            **outbuf = ch;
        } else {
            **outbuf = NON_ID_CHAR;
            no_id_char_num += 1;
        }
        (*outbuf) += 1;
        (*outbytesleft) -= 1;
        op += utf8_len;
        (*inbytesleft) -= utf8_len;

    }

    return ((size_t)no_id_char_num);

errexit:
    st->_errno = errno = EINVAL;
    errno = EINVAL;
    return ((size_t)-1);
}
