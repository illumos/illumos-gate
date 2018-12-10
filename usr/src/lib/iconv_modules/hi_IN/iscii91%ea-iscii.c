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
#include <ctype.h>
#include <strings.h>
#include <stdlib.h>
#include "ea-iscii.h"

#define MSB          0x80
#define REPLACE_CHAR '?'

typedef enum { SPACE, ASCII, ISCII } CONTEXT;

typedef struct _icv_state {
    CONTEXT context;
} _iconv_st;

static uchar
traverse_table(Entry *entry , int num, uchar iscii, uchar *type)
{
    int   i = 0;
    uchar ea_iscii=0;

    *type = 0;

    for ( ; i < num; ++i) {
        Entry en = entry[i];

	if ( iscii < en.iscii ) break;

        if ( en.count == NUKTA || en.count == MATRA || en.count ==
             COMBINED_MATRA_NUKTA ) {
	     if ( iscii == en.iscii ) {
                 *type = en.count;
                 ea_iscii = en.ea_iscii;
                 break;
             }
        } else {
             if ( iscii >= en.iscii && iscii < en.iscii + en.count ) {
                 ea_iscii = (iscii - en.iscii) + en.ea_iscii;
                 break;
             }
        }
    }

    return ea_iscii;
}

void *
_icv_open()
{
    _iconv_st *st;

    if ((st = (_iconv_st*)malloc(sizeof(_iconv_st))) == NULL) {
        errno = ENOMEM;
        return ((void*)-1);
    }

    bzero(st, sizeof(_iconv_st));

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

size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
       char **outbuf, size_t *outbytesleft)
{
    if (st == NULL) {
        errno = EBADF;
        return ((size_t) -1);
    }

    if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
        return ((size_t)0);
    }

    /* a state machine for interpreting ISCII code */
    while (*inbytesleft > 0 && *outbytesleft > 0) {
        uchar c = (uchar)**inbuf;

        if ( c & MSB ) {

             uchar type, ea_iscii;

             if ( st->context != ISCII ) {

                 if ( st->context != SPACE ) {
                    /* force to insert ' ' between ASCII and ISCII */
                    **outbuf = 0x20;
                    (*outbuf)++;
                    (*outbytesleft)--;
                    st->context = SPACE;
                 }

                 if ( *outbytesleft < 1 ) {
                     errno = E2BIG;
                     /* don't advance */
                     return (size_t)-1;
                 }

                 st->context = ISCII;
                 **outbuf = LEADING_BYTE;
                 (*outbuf)++;
                 (*outbytesleft)--;
             }

             if ((ea_iscii = traverse_table(isc_eaiscii_tbl,
			sizeof(isc_eaiscii_tbl)/sizeof(Entry), c, &type ))) {
                 switch ( type ) {
                 case MATRA:
                      if ( *outbytesleft < 2 ) {
                         errno = E2BIG;
                         return (size_t)-1;
                      }

                      **outbuf = FIRST_VOWEL;
                      *(*outbuf+1) = ea_iscii;
                      (*outbuf) += 2;
                      (*outbytesleft) -= 2;
                      break;
                 case NUKTA:
                      if ( *outbytesleft < 2 ) {
                         errno = E2BIG;
                         return (size_t)-1;
                      }

                      **outbuf = ea_iscii;
                      *(*outbuf+1) = NUKTA_VALUE;
                      (*outbuf) += 2;
                      (*outbytesleft) -= 2;
                      break;
                 case COMBINED_MATRA_NUKTA:
                      if ( *outbytesleft < 3 ) {
                         errno = E2BIG;
                         return (size_t)-1;
                      }

                      **outbuf = FIRST_VOWEL;
                      *(*outbuf+1) = ea_iscii;
                      *(*outbuf+2) = NUKTA_VALUE;
                      (*outbuf) += 3;
                      (*outbytesleft) -= 3;
                      break;
                 case 0:
                      if ( *outbytesleft < 1 ) {
                         errno = E2BIG;
                         return (size_t)-1;
                      }

                      **outbuf = ea_iscii;
                      (*outbuf)++;
                      (*outbytesleft)--;
                      break;
                 }
             } else { /* REPLACE_CHAR */
                 if ( *outbytesleft < 1 ) {
                    errno = E2BIG;
                    return (size_t)-1;
                 }

                 **outbuf = REPLACE_CHAR;
                 (*outbuf)++;
                 (*outbytesleft)--;
             }
        } else { /* ASCII */
             if ( st->context == ISCII && !isspace(c) ) {
                 /* force to insert ' ' between ASCII and ISCII */
                 **outbuf = 0x20;
                 (*outbuf)++;
                 (*outbytesleft)--;
                 st->context = SPACE;
             }

             if ( *outbytesleft < 1 ) {
                errno = E2BIG;
                return (size_t)-1;
             }

             **outbuf = c;
             (*outbuf)++;
             (*outbytesleft)--;

             st->context = ASCII;
             if ( isspace(c) )
                  st->context = SPACE;
        }

        (*inbuf)++;
        (*inbytesleft)--;
    }

    if ( *inbytesleft > 0 && *outbytesleft == 0 ) {
         errno = E2BIG;
         return ((size_t)-1);
    }

    return ((size_t)(*inbytesleft));
}
