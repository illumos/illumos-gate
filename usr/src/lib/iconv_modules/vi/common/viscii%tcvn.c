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
#define __NEED_VISCII_2_TCVN__
#include <viscii_tcvn.h>     /* VISCII <-> TCVN mapping table */
#include "common_defs.h"


#define NON_ID_CHAR '?'     /* non-identified character */

typedef struct _icv_state {
    int     _errno;     /* internal errno */
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
    int     unconv = 0;
#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): viscii -->tcvn   ==========\n");
#endif
    if (st == NULL) {
        errno = EBADF;
        return ((size_t) -1);
    }

    if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
        st->_errno = 0;
        return ((size_t) 0);
    }

    st->_errno = 0;     /* reset internal errno */
    errno = 0;          /* reset external errno */

    /* convert viscii encoding to tcvn. */
    while (*inbytesleft > 0 && *outbytesleft > 0) {
        unsigned char ch = 0;

        viscii_2_tcvn((unsigned char*)*inbuf, &ch);
        if (**inbuf != 0x0 && ch == 0) {
            unconv++;
            ch = NON_ID_CHAR;
        }

        **outbuf = ch;
        (*outbuf) += 1;
        (*outbytesleft) -= 1;
        (*inbuf)++;
        (*inbytesleft)--;

    }

    if ( *inbytesleft > 0 && *outbytesleft <= 0 ) {
         errno = E2BIG;
         return ((size_t)-1);
    }

    return ((size_t)unconv);


}
