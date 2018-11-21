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

#define MSB     0x80    /* most significant bit */
#define ONEBYTE 0xff    /* right most byte */

enum _USTATE    { U0, U1, U11, U2, U3, U4 };




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
/*=========================================================
 *
 *       State Machine for interpreting UTF8 code
 *
 *=========================================================
 *
 *               3 byte unicode
 *          +----->------->-------+
 *          |                     |
 *          ^                     v
 *          |  2 byte             U2 ---> U3
 *          |  unicode                    v
 * +------> U0 -------> U1                +-------->U4---+
 * ^  ascii |           |                           ^    |
 * |        |           +-------->--------->--------+    |
 * |        v                                            v
 * +----<---+-----<------------<------------<------------+
 *
 * +----<---+-----<------------<------------<------------+
 *
 *=========================================================*/

        char            c1, c2;
        int             n, unidx;
        unsigned long   ibm_code;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF8 --> IBM     ==========\n");
#endif

        if (st == NULL) {
                errno = EBADF;
                return ((size_t) -1);
        }

        if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
                st->ustate = U0;
                st->_errno = 0;
                return ((size_t) 0);
        }

        st->_errno = 0;         /* reset internal errno */
        errno = 0;              /* reset external errno */

        /* a state machine for interpreting UTF8 code */
        while (*inbytesleft > 0 && *outbytesleft > 0) {
                switch (st->ustate) {
                case U0:                /* assuming ASCII in the beginning */
                        if ((**inbuf & MSB) == 0) {     /* ASCII */
                                **outbuf = **inbuf;
                                (*outbuf)++;
                                (*outbytesleft)--;
                        } else {        /* Chinese character */
                                if ((**inbuf & 0xe0) == 0xc0) { /* 2 byte unicode */
                                        st->ustate = U1;
                                        st->keepc[0] = **inbuf;
                                } else if ((**inbuf & 0xf0) == 0xe0) {  /* 3 byte */
                                        st->ustate = U2;
                                        st->keepc[0] = **inbuf;
                                } else {        /* illegal unicode */
                                        /* st->_errno = errno = EINVAL; */
				/* possible UNICODE ko_KR-UTF8 */
				c1 =st->keepc[0] = **inbuf;
                                st->ustate = U11;
                                        break;
                                }
                        }
                        break;
                case U1:                /* 2 byte unicode */
                        if ((**inbuf & 0xc0) == MSB) {
                                st->ustate = U4;
                                st->keepc[1] = **inbuf;
                                c1 = (st->keepc[0]&0x1c)>>2;
                                c2 = ((st->keepc[0]&0x03)<<6) | ((**inbuf)&0x3f);
#ifdef DEBUG
    fprintf(stderr, "UTF8: %02x%02x   --> ",
        st->keepc[0]&ONEBYTE, st->keepc[1]&ONEBYTE);
#endif
                                continue;       /* should not advance *inbuf */
                        } else {
                                 st->_errno = errno = EINVAL;
                        }
                        break;
                case U11:                /* 3 byte unicode - 2nd byte */
				c2 =st->keepc[1] = **inbuf;
                                st->ustate = U4;
				continue;
			break;
                case U2:                /* 3 byte unicode - 2nd byte */
                        if ((**inbuf & 0xc0) == MSB) {
                                st->ustate = U3;
                                st->keepc[1] = **inbuf;
                        } else {
                                st->_errno = errno = EINVAL;
                        }
                        break;
                case U3:                /* 3 byte unicode - 3rd byte */
                        if ((**inbuf & 0xc0) == MSB) {
                                st->ustate = U4;
                                st->keepc[2] = **inbuf;
                                c1 = ((st->keepc[0]&0x0f)<<4) |
                                        ((st->keepc[1]&0x3c)>>2);
                                c2 = ((st->keepc[1]&0x03)<<6) | ((**inbuf)&0x3f);
#ifdef DEBUG
    fprintf(stderr, "UTF8: %02x%02x%02x --> ", st->keepc[0]&ONEBYTE,
                st->keepc[1]&ONEBYTE, **inbuf&ONEBYTE);
#endif
                                continue;       /* should not advance *inbuf */
                        } else {
                                st->_errno = errno = EINVAL;
                        }
                        break;
                case U4:
                        n = get_ibm_by_utf(st, c1, c2, &unidx, &ibm_code);
                        if (n != 0) {   /* legal unicode;illegal Big5 */
                                st->_errno = errno = EILSEQ;
                                break;
                        }

                        n = utf8_to_ibm(unidx, ibm_code,
                                        *outbuf, *outbytesleft);
                        if (n > 0) {
                                (*outbuf) += n;
                                (*outbytesleft) -= n;
                        } else {
                                st->_errno = errno;
                                return((size_t)-1);
                        }
                        st->ustate = U0;
                        st->_errno = 0;
                        break;
                default:                        /* should never come here */
                        st->_errno = errno = EILSEQ;
                        st->ustate = U0;        /* reset state */
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
 * Match IBM code by UTF8 code;
 * Return: = 0 - match from Unicode to IBM found
 *         = 1 - match from Unicode to IBM NOT found
 *
 * Since binary search of the UTF8 to IBM table is necessary, might as well
 * return index and IBM code matching to the unicode.
 */
int get_ibm_by_utf(st, c1, c2, unidx, ibm_code)
_icv_state	*st;
char            c1, c2;
int             *unidx;
unsigned long   *ibm_code;
{
        unsigned long   unicode;

        unicode = (unsigned long) ((c1 & ONEBYTE) << 8) + (c2 & ONEBYTE);
        *unidx = bisearch(unicode, st, st->table_size);
        if ((*unidx) >= 0)
	{
            if ( st->left_to_right )
                *ibm_code = st->table[*unidx].right_code;
	    else
                *ibm_code = st->table[*unidx].left_code;
	}
        else
                ;      /* match from UTF8 to IBM not found */
#ifdef DEBUG
    fprintf(stderr, "Unicode=%04x, idx=%5d, IBM=%x ", unicode, *unidx, *ibm_code);
#endif

        return(0);
}


/*
 * ISO/IEC 10646 (Unicode) --> IBM
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
int utf8_to_ibm(unidx, ibm_code, buf, buflen)
int             unidx;
unsigned long   ibm_code;
char            *buf;
size_t          buflen;

{
        unsigned long   val;            /* IBM value */
        char            c1, c2, ibm_str[3];

        if (unidx < 0)         /* no match from UTF8 to IBM */
	    ibm_code = (unsigned long)NON_ID_CHAR;

        {
                val = ibm_code & 0xffff;
                c1 = (char) ((val & 0xff00) >> 8);
                c2 = (char) (val & 0xff);
        }

        *buf = ibm_str[0] = c1;
        *(buf+1) = ibm_str[1] = c2;
        ibm_str[2] = NULL;

#ifdef DEBUG
    fprintf(stderr, "\t->%x %x<-\n", *buf, *(buf+1));
#endif


        if (buflen < 2) {
                errno = E2BIG;
                return(0);
        }

        return(2);
}
