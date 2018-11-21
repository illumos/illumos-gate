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
 * Copyright(c) 1998 Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define SI      0x0f
#define SO      0x0e
#define	MSB	0x80
#define	MSB_OFF	0x7f
#define ESC     0x1b

#define NON_ID_CHAR '_'

enum	_GSTATE { G0, G1, G2, G3 };

typedef struct _icv_state {
	char	_lastc;
	short	_gstate;
} _iconv_st;


int gb_to_iso(char in_byte1, char in_byte2, char *buf, int buflen);

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
 *
 *                       +----------------------------------+
 *          MSB          V   MSB       ascii            MSB | (SO)
 *  +-> G0 ------------> G1 ------> G2 ------------> G3 ----+
 *  | ascii  (ESC,SO)    ^   MSB    |  (SI)   ^ ascii |
 *  +----+               +----------+         +-------+
 */
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
	int	n;

	if (st == NULL) {
		errno = EBADF;
		return (size_t)-1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request */
		if (st->_gstate == G1) {
		    if (outbytesleft && *outbytesleft >= 1
				&& outbuf && *outbuf) {
			**outbuf = SI;
			(*outbuf)++;
			(*outbytesleft)--;
		    } else {
			errno = E2BIG;
			return((size_t)-1);
		    }
		}
		st->_gstate = G0;
		return (size_t)0;
	}

	errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if (**inbuf & MSB) {
		    if (*outbytesleft < 5) {
			errno = E2BIG;
			return (size_t)-1;
		    }
		    **outbuf = ESC;
		    *(*outbuf+1) = '$';
		    *(*outbuf+2) = ')';
		    *(*outbuf+3) = 'A';
		    *(*outbuf+4) = SO;
		    (*outbuf) += 5, (*outbytesleft) -= 5;
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {		/* ASCII */
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		}
		break;
	    case G1:
		if (**inbuf & MSB) {
		    n = gb_to_iso(st->_lastc, **inbuf, *outbuf, *outbytesleft);
		    if (n > 0) {
			(*outbuf) += n, (*outbytesleft) -= n;
			st->_gstate = G2;
		    } else {
			errno = E2BIG;
			return (size_t)-1;
		    }
	        } else {
		    errno = EILSEQ;
		}
		break;
	    case G2:
		if (**inbuf & MSB) {
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {
		    if (*outbytesleft < 2) {
			errno = E2BIG;
			return (size_t)-1;
		    }
		    **outbuf = SI;
		    *(*outbuf+1) = **inbuf;
		    (*outbuf) += 2, (*outbytesleft) -= 2;
		    st->_gstate = G3;
		}
		break;
	    case G3:
		if (**inbuf & MSB) {
		    **outbuf = SO;
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {
		    **outbuf = **inbuf;
		}
		(*outbuf)++, (*outbytesleft)--;
		break;
	    }

	    (*inbuf)++, (*inbytesleft)--;
	    if (errno)
		return (size_t)-1;
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return (size_t)-1;
	}
	return ((size_t)(*inbytesleft));
}


/*
 * return: > 0 - converted with enough space
 *	   = 0 - no space in outbuf
 */
int
gb_to_iso(in_byte1, in_byte2, buf, buflen)
char	in_byte1, in_byte2;
char	*buf;
int	buflen;
{
	if ( buflen < 2 )
		return 0;
	*buf = in_byte1 & MSB_OFF;
	*(buf+1) = in_byte2 & MSB_OFF;
	return 2;
}


/*
 * ====================================================================
 * enconv functions
 * ====================================================================
 */

typedef struct _enconv_st {
	char	_lastc;
	short	_gstate;
} _enconv_st;


/*
 * Open; called from enconv_open()
 */
void *
_cv_open()
{
	_enconv_st *st;

	if ((st = (_enconv_st *)malloc(sizeof(_enconv_st))) == NULL) {
		return ((void *) -1);
	}

	st->_gstate = G0;
	return ((void *)st);
}


/*
 * Close; called from enconv_close()
 */
void
_cv_close(_enconv_st *st)
{
	if (st != NULL)
		free(st);
}


/*
 * Actual conversion; called from enconv()
 *
 *                       +----------------------------------+
 *          MSB          V   MSB       ascii            MSB | (SO)
 *  +-> G0 ------------> G1 ------> G2 ------------> G3 ----+
 *  | ascii  (ESC,SO)    ^   MSB    |  (SI)   ^ ascii |
 *  +----+               +----------+         +-------+
 */
size_t
_cv_enconv(_enconv_st *st, char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
	int	n;

	if (st == NULL) {
		return -1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request */
		st->_gstate = G0;
		return 0;
	}

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if (**inbuf & MSB) {
		    if (*outbytesleft < 5) {
			return (*inbytesleft);
		    }
		    **outbuf = ESC;
		    *(*outbuf+1) = '$';
		    *(*outbuf+2) = ')';
		    *(*outbuf+3) = 'A';
		    *(*outbuf+4) = SO;
		    (*outbuf) += 5, (*outbytesleft) -= 5;
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {		/* ASCII */
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		}
		break;
	    case G1:
		if (**inbuf & MSB) {
		    n = gb_to_iso(st->_lastc, **inbuf, *outbuf, *outbytesleft);
		    if (n > 0) {
			(*outbuf) += n, (*outbytesleft) -= n;
			st->_gstate = G2;
		    } else {
			(*inbuf)++, (*inbytesleft)--;
			return (*inbytesleft);
		    }
	        }
		break;
	    case G2:
		if (**inbuf & MSB) {
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {
		    if (*outbytesleft < 2) {
			return (*inbytesleft);
		    }
		    **outbuf = SI;
		    *(*outbuf+1) = **inbuf;
		    (*outbuf) += 2, (*outbytesleft) -= 2;
		    st->_gstate = G3;
		}
		break;
	    case G3:
		if (**inbuf & MSB) {
		    **outbuf = SO;
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {
		    **outbuf = **inbuf;
		}
		(*outbuf)++, (*outbytesleft)--;
		break;
	    }

	    (*inbuf)++, (*inbytesleft)--;
	}

	return (*inbytesleft);
}
