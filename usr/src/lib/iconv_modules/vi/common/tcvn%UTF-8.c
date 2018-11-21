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
#define __NEED_TCVN_2_UNI__
#include <unicode_tcvn.h>	/* Unicode to tcvn mapping table */
#include <vi_combine.h>
#include "common_defs.h"


typedef struct _icv_state {
    int	_errno;		/* internal errno */
    unsigned short last;
} _iconv_st;


static int binsearch(unsigned long x, Combine_map v[], int n);

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
    int             unidx = -1;
#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): TCVN5712 -->UCS-2   ==========\n");
#endif
    if (st == NULL) {
        errno = EBADF;
        return ((size_t) -1);
    }

    if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
        st->_errno = 0;
        return ((size_t) 0);
    }

    st->_errno = 0;     /* Reset internal errno */
    errno = 0;          /* Reset external errno */

    /* Convert tcvn encoding to UCS-2 */
    while (*inbytesleft > 0 && *outbytesleft > 0) {
        unsigned long uni = 0;

        tcvn_2_uni((unsigned char*)*inbuf, &uni);
        if (st->last != 0) {
            if (ISCOMB_UNI(uni)) {
                /*
                 * Composed characters with combine character
                 */
                unsigned int k = 0;
                switch (uni) {
                    case 0x0300: k = 0; break;
                    case 0x0301: k = 1; break;
                    case 0x0303: k = 2; break;
                    case 0x0309: k = 3; break;
                    case 0x0323: k = 4; break;
                    default:
                        break;
                }
                unidx =  binsearch(st->last, vi_comb_data, VOWEL_NUM);
                if (unidx >= 0) {
                    uni = vi_comb_data[unidx].composed[k];
                } else {
                    errno = EBADF;
                }
                st->last = 0;

            } else {
                if (st->last < 0x80) {
                    *(*outbuf)++ = (char)st->last;
                    (*outbytesleft) -= 1;
                } else if (st->last >= 0x0080 && st->last <= 0x07ff) {
                    if (*outbytesleft < 2) {
                        errno = E2BIG;
                        return((size_t)-1);
                    }
                    *(*outbuf)++ = (char)((st->last >> 6) & 0x1f) | 0xc0;
                    *(*outbuf)++ = (char)(st->last & 0x3f) | 0x80;
                    (*outbytesleft) -= 2;
                } else if (st->last >= 0x0800) {
                    if (*outbytesleft < 3) {
                        errno = E2BIG;
                        return((size_t)-1);
                    }
                    *(*outbuf)++ = (char)((st->last >> 12) & 0xf) | 0xe0;
                    *(*outbuf)++ = (char)((st->last >>6) & 0x3f) | 0x80;
                    *(*outbuf)++ = (char)(st->last & 0x3f) | 0x80;
                    (*outbytesleft) -= 3;
                }
            }
            st->last = 0;
        } else {
            if (uni >= 0x0041 && uni <= 0x01b0
                && ((tcvn_comp_bases_mask[(uni-0x0040) >> 5] >> (uni & 0x1f)) & 1)) {
                /*
                 * uni is vowel, it's a possible match with combine character.
                 * Buffer it.
                 * */
                st->last = uni;
                (*inbuf)++;
                (*inbytesleft)--;
                continue;
            }
        }

        if (uni < 0x80) {
            *(*outbuf)++ = (char)uni;
            (*outbytesleft) -= 1;
        } else if (uni >= 0x0080 && uni <= 0x07ff) {
            if (*outbytesleft < 2) {
                errno = E2BIG;
                return((size_t)-1);
            }
            *(*outbuf)++ = (char)((uni >> 6) & 0x1f) | 0xc0;
            *(*outbuf)++ = (char)(uni & 0x3f) | 0x80;
            (*outbytesleft) -= 2;
        } else if (uni >= 0x0800 && uni <= 0xffff) {
            if (*outbytesleft < 3) {
                errno = E2BIG;
                return((size_t)-1);
            }
            *(*outbuf)++ = (char)((uni >> 12) & 0xf) | 0xe0;
            *(*outbuf)++ = (char)((uni >>6) & 0x3f) | 0x80;
            *(*outbuf)++ = (char)(uni & 0x3f) | 0x80;
            (*outbytesleft) -= 3;
        }

	(*inbuf)++;
        (*inbytesleft)--;
    }

    if ( *inbytesleft > 0 && *outbytesleft <= 0 ) {
        errno = E2BIG;
        st->last = 0;
        return ((size_t)-1);
    }

    if (st->last !=0 ) {
        if (st->last < 0x80) {
            *(*outbuf)++ = (char)st->last;
            (*outbytesleft) -= 1;
        } else if (st->last >= 0x0080 && st->last <= 0x07ff) {
            if (*outbytesleft < 2 ) {
                errno = E2BIG;
                return((size_t)-1);
            }
            *(*outbuf)++ = (char)((st->last >> 6) & 0x1f) | 0xc0;
            *(*outbuf)++ = (char)(st->last & 0x3f) | 0x80;
            (*outbytesleft) -= 2;
        } else if (st->last >= 0x0800) {
            if (*outbytesleft < 3) {
                errno = E2BIG;
                return((size_t)-1);
            }
            *(*outbuf)++ = (char)((st->last >> 12) & 0xf) | 0xe0;
            *(*outbuf)++ = (char)((st->last >>6) & 0x3f) | 0x80;
            *(*outbuf)++ = (char)(st->last & 0x3f) | 0x80;
            (*outbytesleft) -= 3;
        }
        st->last = 0;
    }

    return ((size_t)(*inbytesleft));

}

/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, Combine_map v[], int n)
{
    int low = 0;
    int mid = 0;
    int high = n - 1;

    low = 0;
    while (low <= high) {
        mid = (low + high) / 2;
        if (x < v[mid].base)
            high = mid - 1;
        else if (x > v[mid].base)
            low = mid + 1;
        else
            /* found match */
            return mid;
    }

    /* no match */
    return (-1);
}
