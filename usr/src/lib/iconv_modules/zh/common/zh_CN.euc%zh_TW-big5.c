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
 *	Copyright(c) 1997, Sun Microsystems, Inc.
 *	All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gb2312_big5_CN.h>

#define NON_ID_CHAR '_'	/* non-identified character */
#define MSB 0x80
#define ONEBYTE 0xff

typedef struct _icv_state {
	char keepc[2];	/* maximum # byte of GB chararor */
	short cstate;
	int _errno;		/* internal errno */
} _iconv_st;

enum _CSTATE { C0, C1 };

int gb2312_2nd_byte(char inbuf);
int gb2312_to_big5(char keepc[], char *buf, size_t buflen);
int binsearch(unsigned long x, table_t table[], int n);

/*
 *	Open; called from iconv_open()
 */
void * _icv_open() {
	_iconv_st * st;

	if ((st = (_iconv_st *) malloc(sizeof(_iconv_st))) == NULL) {
		errno = ENOMEM;
		return ((void *) -1);
	}

	st->cstate = C0;
	st->_errno = 0;

	return ((void *) st);
}

/*
 *	Close; called from iconv_close()
 */
void _icv_close(_iconv_st * st) {
	if (!st)
		errno = EBADF;
	else
		free(st);
}

/*
 *	Actual conversion; called from iconv()
 */

size_t _icv_iconv(_iconv_st * st, char **inbuf, size_t *inbytesleft,
					char ** outbuf, size_t *outbytesleft) {
	int n;
	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) {	/* Reset request. */
		st->cstate = C0;
		st->_errno = 0;
		return ((size_t) 0);
	}

	errno = st->_errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->cstate) {
			case C0:
				if (**inbuf & MSB) {	/* gb2312 charactor */
					st->keepc[0] = (**inbuf);
					st->cstate = C1;
				} else {	/* ASCII */
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case C1:	/* GBK charactor 2nd byte */
				if (gb2312_2nd_byte(**inbuf) == 0) {
					st->keepc[1] = (**inbuf);
					n = gb2312_to_big5(st->keepc, *outbuf, *outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;

						st->cstate = C0;
					} else {
						st->_errno = errno = E2BIG;
					}
				} else {	/* illegal input */
					st->_errno = errno = EILSEQ;
				}
				break;
			default:	/* un-reachable */
				st->_errno = errno = EILSEQ;
				st->cstate = C0;
				break;
		}

		if (st->_errno)
			break;

		(*inbuf)++;
		(*inbytesleft)--;
	}

        if (errno) return ((size_t) -1);

        if (*inbytesleft == 0 && st->cstate != C0) {
                errno = EINVAL;
                return ((size_t) -1);
        }

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return (size_t)-1;
	}

	return (size_t)(*inbytesleft);
}

/*
 *	Test whether inbuf is a valid character for
 *	2nd byte of GB2312 charactor:
 *	Return:	0 --- valid GB2312 2nd byte
 *			1 --- invalid GB2312 2nd byte
 */
int gb2312_2nd_byte(inbuf)
char inbuf;
{

	unsigned int buf = (unsigned int) (inbuf & ONEBYTE);

	if ((buf >= 0xa1) && (buf <= 0xfe))
		return 0;
	return 1;
}

/*
 *	gb2312_to_big5: Convert gbk charactor to Big5.
 *	Return:	>0 --- converted with enough space in output buffer
 *			=0 --- no space in outbuf
 */

int gb2312_to_big5(char keepc[], char *buf, size_t buflen) {

	unsigned long gb_val;	/* GB2312 value */
	int index;
	unsigned long big5_val;	/* BIG5 value */

	if (buflen < 2) {
		errno = E2BIG;
		return 0;
	}

	gb_val = ((keepc[0] & ONEBYTE) << 8) + (keepc[1] & ONEBYTE);
	index = binsearch(gb_val, gb_big5_tab, BIG5MAX);
	if (index >= 0) {
		big5_val = gb_big5_tab[index].value;
		*buf = (big5_val >> 8) & ONEBYTE;
		*(buf + 1) = big5_val & ONEBYTE;
	} else
		*buf = *(buf + 1) = (char)NON_ID_CHAR;
	return 2;
}

/*
 *	binsearch()
 */
int binsearch(unsigned long x, table_t table[], int n) {
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) >> 1;
		if (x < table[mid].key)
			high = mid - 1;
		else if (x > table[mid].key)
			low = mid + 1;
		else
			return mid;
	}
	return -1;
}
