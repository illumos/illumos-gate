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
 *	Copyright(c) 2001, Sun Microsystems, Inc.
 *	All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gb18030_big5hk.h>

#define NON_ID_CHAR '_'	/* non-identified character */
#define MSB 0x80
#define ONEBYTE 0xff

#define gbk4_2nd_byte(v)  ( (v) >= 0x30 && (v) <= 0x39 )
#define gbk4_3rd_byte(v)   ( (v) >= 0x81 && (v) <= 0xfe )
#define gbk4_4th_byte(v)  gbk4_2nd_byte(v)

int binsearch(unsigned long x, table_t table[], int n);
int gbk_2nd_byte(char inbuf);
int gbk_to_hkscs(char keepc[], char *buf, size_t buflen);
int gbk4_to_hkscs(char keepc[], char *buf, size_t buflen);

typedef struct _icv_state {
	char keepc[4];	/* maximum # byte of GB chararor in two bytes area */
	short cstate;
	int _errno;		/* internal errno */
} _iconv_st;

enum _CSTATE { C0, C1, C2, C3 };

/*=======================================================
 *
 *   State Machine for interpreting GBK code
 *
 *=======================================================
 *
 *                                  3rd C
 *                              C2--------> C3
 *                              ^            |
 *                        2nd C |      4th C |
 *                     1st C    |            |
 *    +--------> C0 ----------> C1           |
 *    |    ascii |        2nd C |            |
 *    ^          v              v            V
 *    +----<-----+-----<--------+-----<------+
 *
 *=======================================================*/
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
				if (**inbuf & MSB) {	/* gb charactor */
					st->keepc[0] = (**inbuf);
					st->cstate = C1;
				} else {	/* ASCII */
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case C1:	/* GBK charactor 2nd byte */
				if (gbk_2nd_byte(**inbuf) == 0) {
					st->keepc[1] = (**inbuf);
					n = gbk_to_hkscs(st->keepc, *outbuf, *outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;

						st->cstate = C0;
					} else {
						st->_errno = errno = E2BIG;
					}
				} else if ( gbk4_2nd_byte((unsigned char)**inbuf) ) {
					st->keepc[1] = (**inbuf);
					st->cstate = C2;
				} else {	/* illegal input, don't reset state */
					st->_errno = errno = EILSEQ;
				}
				break;
			case C2:
				if ( gbk4_3rd_byte((unsigned char)**inbuf) ) {
					st->keepc[2] = (**inbuf);
					st->cstate = C3;
				} else {
					/* illegal input, don't reset state */
					st->_errno = errno = EILSEQ;
				}
				break;
			case C3:
				if ( gbk4_4th_byte((unsigned char)**inbuf) ) {
					st->keepc[3] = (**inbuf);

                                        n = gbk4_to_hkscs(st->keepc, *outbuf, *outbytesleft);
                                        if (n > 0) {
                                                (*outbuf) += n;
                                                (*outbytesleft) -= n;

						st->cstate = C0;
                                        } else {
                                                st->_errno = errno = E2BIG;
                                        }

				} else {
					/* illegal input, don't reset state */
					st->_errno = errno = EILSEQ;
				}
				break;
			default:	/* un-reachable */
				st->_errno = errno = EILSEQ;
				st->cstate = C0;
				break;
		}

		if (st->_errno) break;

		(*inbuf)++;
		(*inbytesleft)--;
	}

	if (errno) return ((size_t) -1);

	if ( *inbytesleft == 0 && st->cstate != C0 ) {
		errno = EINVAL;
		return ((size_t) -1);
	}

	if ( *inbytesleft > 0 && *outbytesleft == 0 ) {
		errno = E2BIG;
		return ((size_t) -1);
	}

	return (size_t)(*inbytesleft);
}

/*
 *	Test whether inbuf is a valid character for
 *	2nd byte of GB2312 charactor:
 *	Return:	0 --- valid GBK 2nd byte
 *			1 --- invalid GBK 2nd byte
 */
int gbk_2nd_byte(inbuf)
char inbuf;
{

	unsigned int buf = (unsigned int) (inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0x7e))
		return 0;
	if ((buf >= 0x80) && (buf <= 0xfe))
		return 0;
	return 1;
}

/*
 *	gbk_to_hkscs: Convert gbk charactor to hkscs.
 *	Return:	>0 --- converted with enough space in output buffer
 *			=0 --- no space in outbuf
 */

int gbk_to_hkscs(char keepc[], char *buf, size_t buflen) {

	unsigned long gbk_val;	/* GBK value */
	int index;
	unsigned long hkscs_val;	/* hkscs value */

	if (buflen < 2) {
		errno = E2BIG;
		return 0;
	}

	gbk_val = ((keepc[0] & ONEBYTE) << 8) + (keepc[1] & ONEBYTE);
	index = binsearch(gbk_val, gbk_hkscs_tab, GBKMAX);
	if (index >= 0) {
		hkscs_val = gbk_hkscs_tab[index].value;
		*buf = (hkscs_val >> 8) & ONEBYTE;
		*(buf + 1) = hkscs_val & ONEBYTE;
	} else
		*buf = *(buf + 1) = (char)NON_ID_CHAR;
	return 2;
}

int gbk4_to_hkscs(char keepc[], char *buf, size_t buflen) {

	unsigned long gbk_val;	/* GBK value */
	int index;
	unsigned long hkscs_val;	/* hkscs value */

	if (buflen < 2) {
		errno = E2BIG;
		return 0;
	}

	gbk_val = ((keepc[0] & ONEBYTE) << 24) + ((keepc[1] & ONEBYTE) << 16) +
		  ((keepc[2] & ONEBYTE) << 8 ) + (keepc[3] & ONEBYTE);
	index = binsearch(gbk_val, gbk4_hkscs_tab, GBK4MAX);
	if (index >= 0) {
		hkscs_val = gbk4_hkscs_tab[index].value;
		*buf = (hkscs_val >> 8) & ONEBYTE;
		*(buf + 1) = hkscs_val & ONEBYTE;
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

#ifdef DEBUG
main(int argc, char * argv[]) {
	_iconv_st * ist;
	char * inbuf = "以下所列的每一标题代表一个已安装并注册了联机提示的 产品系列 。";
	char * outbuf;
	char * ib, * oub;
	int inbyteleft;
	int outbyteleft;

	ist = (_iconv_st *) _icv_open();
	inbyteleft = outbyteleft = 2 * strlen(inbuf);
	outbuf = (char *)malloc(outbyteleft);
	ib = inbuf;
	oub = outbuf;
	_icv_iconv(ist, &inbuf, &inbyteleft, &outbuf, &outbyteleft);
	printf("IN -- %s\n", ib);
	printf("OUT -- %s\n", oub);
}
#endif
