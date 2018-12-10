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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "tab_lookup.h"   	/* table lookup data types */

int bisearch(unsigned long val, _icv_state *st, int n);

#define MSB     0x80    /* most significant bit */
#define MBYTE   0x8e    /* multi-byte (4 byte character) */
#define PMASK   0xa0    /* plane number mask */
#define ONEBYTE 0xff    /* right most byte */

/* non-identified character */
#define UTF8_NON_ID_CHAR1 0xEF
#define UTF8_NON_ID_CHAR2 0xBF
#define UTF8_NON_ID_CHAR3 0xBD

enum _USTATE    { C0, C1, C2 };


int ibm_to_utf8(_icv_state *st, char    *buf, size_t  buflen);


/*
 * Actual conversion; called from iconv()
 * Input is UTF-8 data.
 * first convert to UCS2
 */
size_t
_icv_iconv(_icv_state *st, char **inbuf, size_t *inbytesleft,
                        char **outbuf, size_t *outbytesleft)
{
/*
 * Actual conversion; called from iconv()
 */

        int             n;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): IBM --> UTF8     ==========\n");
#endif

        if (st == NULL) {
                errno = EBADF;
                return ((size_t) -1);
        }

        if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
                st->ustate = C0;
                st->_errno = 0;
		st->shift = SHIFT_IN;
                return ((size_t) 0);
        }

        st->_errno = 0;         /* reset internal errno */
        errno = 0;              /* reset external errno */

        /* a state machine for interpreting UTF8 code */
        while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (**inbuf) {
		case SHIFT_OUT :
			if (st->shift == SHIFT_IN) {
				st->shift = SHIFT_OUT;
				(*inbuf)++;
				(*inbytesleft)--;
				continue;
			}
			break;
		case SHIFT_IN :
			if (st->shift == SHIFT_OUT) {
				st->shift = SHIFT_IN;
				(*inbuf)++;
				(*inbytesleft)--;
				continue;
			}
			break;
		}

                switch (st->ustate) {
                case C0 :
			/* the input is ascii, single byte, convert it */
			if (st->shift == SHIFT_IN) {
				st->keepc[0] = 0x0;
				st->keepc[1] = **inbuf;
				st->ustate = C2;
				continue;
			 }

			/* two bytes character */
		        st->keepc[0] = (**inbuf);
			st->ustate = C1;
		        break;
                case C1 :
		        st->keepc[1] = (**inbuf);
			st->ustate = C2;
			continue;
		case C2 :
                        n = ibm_to_utf8(st, *outbuf, *outbytesleft);
                        if (n > 0) {
                                (*outbuf) += n;
                                (*outbytesleft) -= n;
                        } else {
                                st->_errno = errno;
                                return((size_t)-1);
                        }
                        st->ustate = C0;
                        st->_errno = 0;
                        break;

                default:                        /* should never come here */
                        st->_errno = errno = EILSEQ;
                        st->ustate = C0;        /* reset state */
                        break;
                }


                (*inbuf)++;
                (*inbytesleft)--;

                if (st->_errno) {
#ifdef DEBUG
    fprintf(stderr, "!!!!!\tst->_errno = %d\tst->ustate = %d\n",
                st->_errno, st->ustate);
#endif
                        break;
                }

                if (errno)
                        return((size_t)-1);
        }

        if (*outbytesleft == 0) {
                errno = E2BIG;
                return((size_t)-1);
        }
        return (*inbytesleft);
}

/*
 * IBM code --> (Unicode)
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
int ibm_to_utf8(st, buf, buflen)
_icv_state *st;
char    *buf;
size_t  buflen;
{
        unsigned long   ibm_val;       /* Big-5 value */
        int             unidx;          /* Unicode index */
        unsigned long   uni_val;        /* Unicode */

        ibm_val = ((st->keepc[0]&ONEBYTE) << 8) + (st->keepc[1]&ONEBYTE);
#ifdef DEBUG
    fprintf(stderr, "%x\t", ibm_val);
#endif


        unidx = bisearch(ibm_val, st, st->table_size);

        if (unidx >= 0)
	{
            if ( st->left_to_right )
                uni_val = st->table[unidx].right_code;
            else
                uni_val = st->table[unidx].left_code;
        }

#ifdef DEBUG
    fprintf(stderr, "unidx = %d, unicode = %x\t", unidx, uni_val);
#endif

        if (unidx >= 0) {       /* do Unicode to UTF8 conversion */
		if (uni_val <= 0x07f) {
			if (buflen < 1) {
				errno = E2BIG;
				return 0;
			}
			*buf = uni_val;
			return 1;
		}
                if (uni_val >= 0x0080 && uni_val <= 0x07ff) {
                        if (buflen < 2) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in ibm_to_utf8()!!\n");
#endif
                                errno = E2BIG;
                                return(0);
                        }
                        *buf = (char)((uni_val >> 6) & 0x1f) | 0xc0;
                        *(buf+1) = (char)(uni_val & 0x3f) | 0x80;
#ifdef DEBUG
    fprintf(stderr, "%x %x\n", *buf&ONEBYTE, *(buf+1)&ONEBYTE);
#endif
                        return(2);
                }
                if (uni_val >= 0x0800 && uni_val <= 0xffff) {
                        if (buflen < 3) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in ibm_to_utf8()!!\n");
#endif
                                errno = E2BIG;
                                return(0);
                        }
                        *buf = (char)((uni_val >> 12) & 0xf) | 0xe0;
                        *(buf+1) = (char)((uni_val >>6) & 0x3f) | 0x80;
                        *(buf+2) = (char)(uni_val & 0x3f) | 0x80;
#ifdef DEBUG
    fprintf(stderr, "%x %x %x\n", *buf&ONEBYTE, *(buf+1)&ONEBYTE, *(buf+2)&ONEBYTE);
#endif
                        return(3);
                }
        }

        /* can't find a match in IBM --> UTF8 table or illegal UTF8 code */
        if (buflen < 3) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in ibm_to_utf8()!!\n");
#endif
                errno = E2BIG;
                return(0);
        }

        *buf     = (char)UTF8_NON_ID_CHAR1;
        *(buf+1) = (char)UTF8_NON_ID_CHAR2;
        *(buf+2) = (char)UTF8_NON_ID_CHAR3;

#ifdef DEBUG
    fprintf(stderr, "%c %c %c\n", *buf, *(buf+1), *(buf+2));
#endif
        return(3);
}
