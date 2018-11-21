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
 *	Copyright(c) 2001 Sun Microsystems, Inc.
 *	All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <big5hk_gb18030.h>

#define NON_ID_CHAR '_'	/* non-identifier charactor */
#define MSB 0x80
#define ONEBYTE 0xff
#define gbk_4th_byte(v)  ( ((v) >= 0x30) && ((v) <= 0x39) )

typedef struct _icv_state {
	char keepc[2];	/* maximum # byte of HKSCS charactor */
	short cstate;
	int _errno;		/* internal errno */
} _iconv_st;

enum _CSTATE { C0, C1 };

int binsearch(unsigned long x, table_t table[], int n);
int hkscs_2nd_byte(char inbuf);
int hkscs_to_gbk2k(char keepc[], char *buf, size_t buflen);

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
				if (**inbuf & MSB) {	/* hkscs charactor */
					st->keepc[0] = (**inbuf);
					st->cstate = C1;
				} else {	/* ASCII */
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case C1:	/* hkscs charactor 2nd byte */
				if (hkscs_2nd_byte(**inbuf) == 0) {
					st->keepc[1] = (**inbuf);
					n = hkscs_to_gbk2k(st->keepc, *outbuf, *outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;

						st->cstate = C0;
					} else {
						st->_errno = errno = E2BIG;
					}
				} else {	/* illegal input */
					st->_errno = errno =EILSEQ;
				}
				break;
			default:
				st->_errno = errno = EILSEQ;
				st->cstate = C0;
				break;
		}

		if (st->_errno) break;

		(*inbuf) ++;
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
 *	2nd byte of HKSCS charactor:
 *	Return:	0 --- valid HKSCS 2nd byte
 *			1 --- invalid HKSCS 2nd byte
 */
int hkscs_2nd_byte(inbuf)
char inbuf;
{
	unsigned int buf = (unsigned int)(inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0xfe))
		return 0;
	return 1;
}

/*
 *	hkscs_to_gbk2k: Convert hkscs to gbk.
 *	Return:	>0 --- converted with enough space in output buffer
 *			=0 --- no space in outbuf
 */

int hkscs_to_gbk2k(char keepc[], char *buf, size_t buflen) {

	unsigned long gbk_val;
	int index, len;
	unsigned long hkscs_val;

	if (buflen < 2) {
		errno = E2BIG;
		return 0;
	}

	hkscs_val = ((keepc[0] & ONEBYTE) << 8) + (keepc[1] & ONEBYTE);
	index = binsearch(hkscs_val, hkscs_gbk2k_tab, MAX_HKSCS_NUM);
	if (index >= 0) {
		char c;

		gbk_val = hkscs_gbk2k_tab[index].value;
		c =  gbk_val & ONEBYTE;
		if ( gbk_4th_byte( (unsigned char)c ) ) {

			if ( buflen < 4 ) {
				errno = E2BIG;
				return 0;
			}

			*buf = ( gbk_val >> 24) & ONEBYTE;
			*(buf + 1) = (gbk_val >> 16) & ONEBYTE;
			*(buf + 2) = (gbk_val >> 8) & ONEBYTE;
			*(buf + 3) = c;

			len = 4;
		} else {
			*buf = (gbk_val >> 8) & ONEBYTE;
			*(buf + 1) = c;

			len = 2;
		}
	} else {
		*buf = *(buf + 1) = (char)NON_ID_CHAR;
		len = 2;
	}
	return len;
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
