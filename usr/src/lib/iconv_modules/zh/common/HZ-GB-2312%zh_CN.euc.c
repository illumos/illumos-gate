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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define SI      0x0f
#define SO      0x0e
#define ESC     0x1b
#define	MSB	0x80

#define NON_ID_CHAR '_'

enum	_GSTATE { G0, G1, G2, G3, G4, G5};


typedef struct _icv_state {
	char	_lastc;
	short	_gstate;
} _iconv_st;

int
hz2gb(char in_byte1, char in_byte2, char *buf, int buflen);

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

	st->_gstate = G0;
	return ((void *)st);
}


/*
 * Close; called from iconv_close()
 */
void
_icv_close(_iconv_st *st)
{
	if (st == NULL)
		errno = EBADF;
	else
		free(st);
}


/*
 * Actual conversion; called from iconv()
 */
/*=======================================================================
 *
 *         ~          {     Chinese
 * +-> G0 -----> G1 ----> G2 ----> G3
 * |   | ascii   | ascii  |~}      |
 * +----------------------+--------+
 *=======================================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t*inbytesleft,
			char **outbuf, size_t*outbytesleft)
{
	int	n;

	if (st == NULL) {
		errno = EBADF;
		return -1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->_gstate = G0;
		return 0;
	}

	errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if ( **inbuf == '~' ) {
		    st->_gstate = G1;
		} else if (!((**inbuf) & MSB)) {	/* ASCII */
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		} else {
		    errno = EILSEQ;
		    return (size_t)-1;
		}
		break;
	    case G1:
		if ( **inbuf == '{' ) {
		    st->_gstate = G2;
		} else if (**inbuf == '~') {
		    **outbuf = '~';
		    (*outbuf)++, (*outbytesleft)--;
		    st->_gstate = G0;
		} else {
		    errno = EILSEQ;
		    return -1;
		}
		break;
	    case G2:
		if ( **inbuf == '~' ) {
		    st->_gstate = G4;
		} else {
		    st->_lastc = **inbuf;
		    st->_gstate = G3;
		}
		break;
	    case G3:
		n = hz2gb(st->_lastc, **inbuf, *outbuf, *outbytesleft);
		if (n > 0) {
		    (*outbuf) += n, (*outbytesleft) -= n;
		} else {
		    errno = E2BIG;
		    return -1;
		}
		st->_gstate = G2;
		break;
	    case G4:
		if ( **inbuf == '}' ) {
		    st->_gstate = G0;
		} else {
		    errno = EILSEQ;
		    return -1;
		}

		break;
	    }

	    (*inbuf)++, (*inbytesleft)--;
	    if (errno)
		return -1;
	}

	if ( st->_gstate != G0 && *inbytesleft == 0 ) {
	    errno = EINVAL;
	    return (size_t)-1;
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return -1;
	}
	return (*inbytesleft);
}


int
hz2gb(in_byte1, in_byte2, buf, buflen)
char	in_byte1, in_byte2;
char	*buf;
int	buflen;
{

	if ( buflen < 2 )
	    return 0;
	*buf = in_byte1 | MSB;
	*(buf+1) = in_byte2 | MSB;
	return 2;
}
