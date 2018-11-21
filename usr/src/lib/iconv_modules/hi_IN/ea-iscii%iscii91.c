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
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include "ea-iscii.h"

#define MSB          0x80
#define REPLACE_CHAR '?'
#define EA_START     0x40

#define get_vowel(a)  EAISCII_vowel_type[(a) - EA_START]
#define get_nukta_value(a)  EAISCII_nukta_type[(a) - EA_START]
#define is_first_vowel(a) ((a) == FIRST_VOWEL)
#define is_nukta(a) ((a) == NUKTA_VALUE)

typedef enum { SPACE, ASCII, POSSIBLE_ISCII, ISCII } CONTEXT;
typedef struct _icv_state {
    uchar   keepc;    /* if is_vowel is true, store the char following the FIRST_VOWEL */
    CONTEXT context;
    int     is_vowel;
} _iconv_st;

static uchar
traverse_table(Entry *entry , int num, uchar ea_iscii)
{
    int   i=0;
    uchar iscii=0;

    for ( ; i < num; ++i) {
        Entry en = entry[i];

        if ( ea_iscii < en.ea_iscii ) break;
        if ( ea_iscii >= en.ea_iscii && ea_iscii < en.ea_iscii + en.count ) {
            iscii = (ea_iscii - en.ea_iscii) + en.iscii;
            break;
        }
    }

    return iscii;
}

/*
 * run in ISCII context.
 * ea_iscii being 0: flush the keepc
 * flag return 0: don't decide iscii yet, need to advance the next char in outbuf
 */
static uchar
get_iscii(_iconv_st *st, uchar ea_iscii, int *flag)
{
    uchar iscii = 0;

    if ( st->keepc == 0 ) {
        if ( ea_iscii == 0 ) { *flag = 0; return 0; }
        if ( ea_iscii < EA_START ) return 0; /* invalid iscii */

        if ( get_nukta_value(ea_iscii) || is_first_vowel(ea_iscii) ) {
            /* do nothing except store ea_iscii into st->keepc */
            *flag = 0;
            st->keepc = ea_iscii;
        } else {
            iscii = traverse_table( eaiscii_isc_tbl,
                       sizeof(eaiscii_isc_tbl)/sizeof(Entry), ea_iscii);
        }
    } else {
       uchar vowel, nukta_value;

       if ( st->is_vowel ) {
           /* need decide whether it is 0xAE or 0xB2 case */
           if ( ea_iscii >= EA_START && is_nukta(ea_iscii) ) {
               if ( st->keepc == 0x73 ) iscii = 0xAE;
               if ( st->keepc == 0x76 ) iscii = 0xB2;
               st->keepc = 0;
           } else {
               iscii = get_vowel(st->keepc);
               st->keepc = ea_iscii;
           }
           st->is_vowel = 0;
           goto end;
       }

       if ( is_first_vowel(st->keepc) ) {
           if ( (ea_iscii >= EA_START) && (vowel = get_vowel(ea_iscii)) ) {
                if ( ea_iscii == 0x73 || ea_iscii == 0x76 ) {
                    st->keepc = ea_iscii;
                    *flag = 0;
                    st->is_vowel = 1;
                } else {
                    st->keepc = 0;
                    iscii = vowel;
                }
           } else {
                iscii = traverse_table( eaiscii_isc_tbl,
                       sizeof(eaiscii_isc_tbl)/sizeof(Entry), st->keepc);
                st->keepc = ea_iscii;
           }
       } else if ( (st->keepc >= EA_START) && (nukta_value = get_nukta_value(st->keepc))) {
           if ( ea_iscii >= EA_START && is_nukta(ea_iscii) ) {
                st->keepc = 0;
                iscii = nukta_value;
           } else {
                iscii = traverse_table( eaiscii_isc_tbl,
                       sizeof(eaiscii_isc_tbl)/sizeof(Entry), st->keepc);
                st->keepc = ea_iscii;
           }
       } else {
           iscii = traverse_table( eaiscii_isc_tbl,
                  sizeof(eaiscii_isc_tbl)/sizeof(Entry), st->keepc);
           st->keepc = ea_iscii;
       }
    }

end:
    return iscii;
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

        if ( c & MSB ) { errno = EILSEQ; return (size_t)-1; }

        switch (st->context) {
        case SPACE:
            if ( c == LEADING_BYTE ) st->context = POSSIBLE_ISCII;
            else {
                if ( !isspace(c) ) st->context = ASCII;
                **outbuf = c;
                (*outbuf)++;
                (*outbytesleft)--;
            }
            break;
        case ASCII:
            if ( isspace(c) ) st->context = SPACE;
            **outbuf = c;
            (*outbuf)++;
            (*outbytesleft)--;
            break;
        case POSSIBLE_ISCII:
            /* it is impossible to represent with 'xx' one ASCII word that starts with 'x' */
            if ( !isspace(c) ) { st->context = ISCII; continue; } /* don't advance */

            **outbuf = LEADING_BYTE;  /* the previous 'x' */
            (*outbuf)++;
            (*outbytesleft)--;
            st->context = ASCII;

            if (*outbytesleft < 1) {
                errno = E2BIG;
                return (size_t)-1;
            }

            **outbuf = c;
            (*outbuf)++;
            (*outbytesleft)--;
            st->context = SPACE;

            break;
        case ISCII:
            if ( isspace(c) ) {
                uchar iscii;
                int flag = 1;

                /* flush keepc */
                iscii = get_iscii(st, 0, &flag);
                if (flag) {
                    if ( iscii ) **outbuf = iscii;
                    else **outbuf = REPLACE_CHAR;

                    (*outbuf)++;
                    (*outbytesleft)--;
                }

                if ( *outbytesleft < 1 ) {
                    errno = E2BIG;
                    return (size_t)-1;
                }

                **outbuf = c;
                (*outbuf)++;
                (*outbytesleft)--;
                st->context = SPACE;
            } else {
               uchar iscii;
               int   flag = 1;

               iscii = get_iscii(st, c, &flag);
               if (flag) {
                   if ( iscii ) **outbuf = iscii;
                   else **outbuf = REPLACE_CHAR;

                   (*outbuf)++;
                   (*outbytesleft)--;
               }
            }
            break;
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
