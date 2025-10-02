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
#include <big5_gb2312.h>

#define NON_ID_CHAR '_'	/* non-identifier charactor */
#define MSB 0x80
#define ONEBYTE 0xff

typedef struct _icv_state {
	char keepc[2];	/* maximum # byte of BIG5 charactor */
	short cstate;
	int _errno;		/* internal errno */
} _iconv_st;

enum _CSTATE { C0, C1 };

int big5_2nd_byte(char inbuf);
int big5_to_gb2312(char keepc[], char *buf, size_t buflen);
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
				if (**inbuf & MSB) {	/* big5 charactor */
					st->keepc[0] = (**inbuf);
					st->cstate = C1;
				} else {	/* ASCII */
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case C1:	/* Big5 charactor 2nd byte */
				if (big5_2nd_byte(**inbuf) == 0) {
					st->keepc[1] = (**inbuf);
					n = big5_to_gb2312(st->keepc, *outbuf, *outbytesleft);
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

		if (st->_errno)
			break;

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
 *	2nd byte of BIG5 charactor:
 *	Return:	0 --- valid BIG5 2nd byte
 *			1 --- invalid BIG5 2nd byte
 */
int big5_2nd_byte(inbuf)
char inbuf;
{
	unsigned int buf = (unsigned int)(inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0xfe))
		return 0;
	return 1;
}

/*
 *	big5_to_gb2312: Convert Big5 to gb2312.
 *	Return:	>0 --- converted with enough space in output buffer
 *			=0 --- no space in outbuf
 */

int big5_to_gb2312(char keepc[], char *buf, size_t buflen) {

	unsigned long gb_val;
	int index;
	unsigned long big5_val;

	if (buflen < 2) {
		errno = E2BIG;
		return 0;
	}

	big5_val = ((keepc[0] & ONEBYTE) << 8) + (keepc[1] & ONEBYTE);
	index = binsearch(big5_val, big5_gb_tab, BIG5MAX);
	if (index >= 0) {
		gb_val = big5_gb_tab[index].value;
		*buf = (gb_val >> 8) & ONEBYTE;
		*(buf + 1) = gb_val & ONEBYTE;
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int
main(int argc, char * argv[])
{
	_iconv_st * ist;
	char * inbuf = "\xa5\x48\xa4\x55\xa9\xd2\xa6\x43\xaa\xba\xa8\x43\xa4"
	    "\x40\xbc\xd0\xc3\x44\xa5\x4e\xaa\xed\xa4\x40\xad\xd3\xa4\x77"
	    "\xa6\x77\xb8\xcb\xa8\xc3\xaa\x60\xa5\x55\xa4\x46\xc1\x70\xbe"
	    "\xf7\xb4\xa3\xa5\xdc\xaa\xba\xb2\xa3\xab\x7e\xa8\x74\xa6\x43"
	    "\xa1\x43\xa8\x43\xa4\x40\xbc\xd0\xc3\x44\xa1\x5d\xa9\x4d\xb9"
	    "\xcf\xbc\xd0\xa1\x5e\xac\x4f\xa4\x40\xad\xd3\xa6\x43\xa5\x58"
	    "\xb8\xd3\xa8\x74\xa6\x43\xb4\xa3\xa5\xdc\xaa\xba\xb6\x57\xc3"
	    "\xec\xb1\xb5\xa1\x43";
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

	return (0);
}
#endif
