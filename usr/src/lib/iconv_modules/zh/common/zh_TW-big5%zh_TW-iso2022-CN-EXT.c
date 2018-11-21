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


/*
   Converts From:	Taiwanese BIG5 encoding
   Converts To:		ISO2022-CN-EXT encoding.

   NOTE: This file was created using vi editor with tabstop set to 4.
		 To view this file correctly set tabstop appropriately.
		 e.g. for vi use command	ESC:se ts=4
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "big5_cns11643.h"	/* Big5 to CNS 11643 mapping table */

#define MSB			0x80	/* The most significant bit */
#define ONEBYTE		0xff	/* The right most byte */

#define SI		0x0f	/* shift in */
#define SO		0x0e	/* shift out */
#define SS2		0x4e	/* SS2 low byte. High byte is ESC */
#define SS3		0x4f	/* SS3 low byte. High byte is ESC */
#define ESC		0x1b	/* The Escape character */
#define NON_ID_CHAR	'_' /*Substitute this for all unidentified characters*/

/* GET_PLANEC() - Gets the corresponding ISO assigned plane character for
                  the CNS11643 plane */
static const char plane_char[] = "0GHIJKLMNOPQRSTUV";
#define GET_PLANEC(i)	(plane_char[(i)])

typedef struct _icv_state {
	char	keepc[2];	/* Save the recieved bytes here */
	short	cstate;		/* Current state the state machine is in.
				   These states are C0 or C1*/
	char	ishiftfunc;	/* The currently active shift funtion SI or SO
				   in the output ISO buffer */
	int	iSOplane;	/* The current CNS11643 plane which is
				   assigned to the SOdesignation in the output
				   ISO buffer. Only CNS11643 plane 1 can be
				   assigned to SOdesignation */
	int	iSS2plane;	/* The current CNS11643 plane which is
				   assigned to the SS2designation in the output
				   ISO buffer. Only CNS11643 plane 2 can be
				   assigned to SS2designation */
	int	iSS3plane; 	/* The current CNS11643 plane which is
				   assigned to the SS3designation in the output
				   ISO buffer. All CNS11643 planes >= 3 are
				   assigned to SS3designation */
	size_t	nonidcount; /* Keeps track of skipped input bytes in conversion */
	int	_errno;		/* Internal error number */
} _iconv_st;

enum _CSTATE	{ C0, C1 };

static int isbig5(unsigned char*);
static int hascns(char*);
static int ascii_to_iso(char, _iconv_st*, char**, size_t*);
static int big5_to_iso(int, _iconv_st*, char**, size_t*);
static int getcnsbytes(int, char*, int*);
static int binsearch(unsigned long, table_t[], int);


/*
 * _icv_open: Called from iconv_open. Allocates and initializes _iconv_st
 *            structure. Returns pointer to the structure as (void *).
 */


void *
_icv_open()
{
	_iconv_st  *st;

#ifdef DEBUG
	fprintf(stderr, "_icv_open(): Come into!\n");
#endif
	/* Allocate */
	if ((st = (_iconv_st *) malloc(sizeof(_iconv_st))) == NULL){
		errno = ENOMEM;
#ifdef DEBUG
	fprintf(stderr, "Error\n");
#endif
		return ((void *) -1);
	}

	/* Initialize */
	st->cstate = C0;
	st->ishiftfunc = SI;
	st->iSOplane = -1;
	st->iSS2plane = -1;
	st->iSS3plane = -1;
	st->nonidcount = 0;
	st->_errno = 0;

#ifdef DEBUG
	fprintf(stderr, "====== _icv_open(): Big5 --> ISO2022-CN-EXT =====\n");
#endif

	/* Return struct */
	return ((void *) st);
}



/*
 * _icv_close: Called from iconv_close(). Frees the _iconv_st structure as
 *	       pointed by the argument.
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
 * _icv_iconv: Called from iconv(). Does the convertion from BIG5 to
 *	       ISO2022-CN-EXT.
 */
/*=======================================================
 *
 *   State Machine for interpreting Big-5 code
 *
 *=======================================================
 *
 *                     1st C
 *    +--------> C0 ----------> C1
 *    |    ascii |        2nd C |
 *    ^          v              v
 *    +----<-----+-----<--------+
 *
 *=======================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{

	int n, idx;

#ifdef DEBUG
    fprintf(stderr, "=== _icv_iconv(): Big5 --> ISO2022-CN-EXT =====\n");
#endif

	if (st == NULL) {
	    errno = EBADF;
	    return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL ||
	    inbytesleft == NULL || *inbytesleft == 0) { /* Reset request */
	    if (st->ishiftfunc == SO) {
		if (outbytesleft && *outbytesleft >= 1  && outbuf && *outbuf) {
		    **outbuf = SI;
		    (*outbuf)++;
		    (*outbytesleft)--;
		} else {
		    errno = E2BIG;
		    return((size_t) -1);
		}
	    }
	    st->cstate = C0;
	    st->ishiftfunc = SI;
	    st->iSOplane = -1;
	    st->iSS2plane = -1;
	    st->iSS3plane = -1;
	    st->nonidcount = 0;
	    st->_errno = 0;
	    return ((size_t) 0);
	}

	st->_errno = 0;
	errno = 0;

	/* Before we use *inbytesleft or *outbytesleft we should confirm that
	inbytesleft and outbytesleft are non-NULL. I am considering inbytesleft
	or *inbytesleft having 0 value as a reset request. I am considering
	outbytesleft having 0 value as no space in output buffer. Also, here
	itself I am verifying that outbuf and *outbuf should be non-NULL pointers
	so I do not have to worry about them being NULL below in the conversion
	sub-routines. I also confirm here that *outbytesleft should be > 0 before
	we can continue further */

	if (outbytesleft == NULL || *outbytesleft == 0 ||
		outbuf == NULL || *outbuf == NULL){
	    errno = E2BIG;
	    return ((size_t)-1);
	}

	/* A state machine for interpreting Big-5 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->cstate) {
	    case C0:
		if (**inbuf & MSB) { /* May have got the first byte ofa BIG5 code */

		    st->keepc[0] = **inbuf;		/*Save byte */
		    st->cstate = C1;	/* Go to the next state where
					   the next BIG5 byte is recieved */
		    st->nonidcount += 1;/* Until we have verified that this and
					   the next byte make a valid BIG5 code
					   we shall consider this as an
					   unidentified byte */
		} else if (**inbuf == ESC || **inbuf == SI || **inbuf == SO){

		    /* We should not process these ASCII control codes as these
		       have special significance in the output ISO encoding.
		       Instead we will output NON_ID_CHAR and continue processing */

		    n = ascii_to_iso(NON_ID_CHAR, st, outbuf, outbytesleft);
		    if (n < 0) /* Insufficient space in the outbuf */
			    return ((size_t)-1); /* The errno etc. are set in ascii_to_iso */
		    st->nonidcount += 1;
		} else { /* Got ASCII code */
		    n = ascii_to_iso(**inbuf, st, outbuf, outbytesleft);
		    if (n < 0) /* Insufficient space in the outbuf */
			return ((size_t)-1);
		}
		break;

	    case C1:
		st->keepc[1] = (**inbuf);
		if (isbig5((unsigned char*) st->keepc) == 0) {
		    if ((idx = hascns(st->keepc)) >= 0){
			n = big5_to_iso(idx, st, outbuf, outbytesleft);
			if (n < 0) /* Insufficient space in the outbuf */
			    return ((size_t)-1);
			st->nonidcount -= 1; /* The first byte of this big5 saved in
						state C0 is confirmed valid BIG5 High
						byte and is processed correctly */

		    } else { /* Valid BIG5 but has no CNS encoding */
			/* We will output the NON_ID_CHAR character */
			n = ascii_to_iso(NON_ID_CHAR, st, outbuf, outbytesleft);
			if (n < 0) /* Insufficient space in the outbuf */
			    return ((size_t)-1);
			n = ascii_to_iso(NON_ID_CHAR, st, outbuf, outbytesleft);
			if (n < 0) /* Insufficient space in the outbuf */
			    return ((size_t)-1);
			st->nonidcount -= 1; /* Include the 2nd byte also as
						    unidentified byte */
		    }
		} else { /* Input character is not BIG5 encoding */
		    st->nonidcount += 1;
		    st->_errno = errno = EILSEQ; /* This will cause the code to
						    break out of while loop below
						    to return to the caller */

		}
		st->cstate = C0; /* Go to the initial state */
		break;

	    default:		/* Should never come here */
		fprintf(stderr,
	 "_icv_iconv():Big5-->ISO2022-CN-EXT: Should not have come here\n");
		st->_errno = errno = EILSEQ;
		st->cstate = C0;
		break;

	    } /* end switch */

	    (*inbuf)++;
	    (*inbytesleft)--;

	    if (st->_errno)
		    break; /* Break out of while loop */

	    if (errno) /* We set st->_errno before we set errno. If errno is set
				      somewhere else we handle that here */
		return ((size_t)-1);

	} /* end while */

/* We now have to handle the case where we have successfully processed the
   previous input character which exhausted the output buffer. This is handled
   by the while loop. However, since there are more input characters that
   haven't been processed yet, we need to set the errno appropriately and
   return -1. */
	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return ((size_t)-1);
	}

	return (*inbytesleft + st->nonidcount);

}


/*
 * Big-5 encoding range:
 *	High byte: 0xA1 - 0xFE				(94 encoding space)
 *	Low byte:  0x40 - 0x7E, 0xA1 - 0xFE	(157 encoding space)
 *	Plane #1:  0xA140 - 0xC8FE			(6280 encoding space)
 *	Plane #2:  0xC940 - 0xFEFE			(8478 encoding space)
 *	Total:	   94 * 157 = 14,758		(14758 encoding space)
 */
static int isbig5(unsigned char *twobytes)
{
	if (twobytes[0] >= 0xa1 && twobytes[0] <= 0xfe)
	    if ((twobytes[1] >= 0x40 && twobytes[1] <= 0x7e) ||
					(twobytes[1] >= 0xa1 && twobytes[1] <= 0xfe))
		return (0);
	return(-1);
}


/*
 * hascns() : checks whether we have a CNS 11643 code for the big5 character
 *			  code. If exists returns the index of the big5 character in the
 *			  big5 to CNS table else returns -1.
 */
static int hascns(char* big5mbchar)
{

	int idx;
	unsigned long big5code;

	big5code = (unsigned long) ((big5mbchar[0] & ONEBYTE) << 8) +
										(big5mbchar[1] & ONEBYTE);

	idx = binsearch(big5code, big5_cns_tab, MAX_BIG5_NUM);

	return (idx); /* binsearch returns -1 if not found, else index */
}


/* ascii_to_iso() : If required, outputs the SI shift function. Outputs the
 *					character. If there is insufficient space in the output
 *					buffer, it flags the error and returns -1. On success it
 *					returns 0.
 */
static int ascii_to_iso(char c, _iconv_st *st, char **outbuf,
							size_t *outbytesleft)
{
	if (st->ishiftfunc != SI){
	    **outbuf = SI;
	    (*outbuf)++;
	    (*outbytesleft)--;
	    st->ishiftfunc = SI;

	    if (*outbytesleft < 1){ /* Do we now have space for ASCII character?*/
		    st->_errno = errno = E2BIG;
		    return (-1);
	    }
	}

	**outbuf = c;
	(*outbuf)++;
	(*outbytesleft)--;

	/* Each line in ISO is expected to have the character set information
	   for the Chinese characters in that line. This facilitates text
	   scrollling. Hence, on encountering newline reset designations to
	   unknown */
	if (c == '\n'){
	    st->iSOplane = -1;
	    st->iSS2plane = -1;
	    st->iSS3plane = -1;
	}

	return (0);

}



/* big5_to_iso() : Converts the Big5 code, for which the index idx in
 *				   the big5 to cns table is provided as an argument, to
 *				   its corresponding ISO2022-CN-EXT code. This may
 *				   require outputting of SO shift function and/or
 *				   the designations. In case we do not have sufficient
 *				   space in the outbuf to to do the convertion we flag error
 *				   and return -1
 */
static int big5_to_iso(int idx, _iconv_st *st, char **outbuf,
							size_t *outbytesleft)
{

	char cnsbytes[2];
	int cnsplane;
	int ret;

	ret = getcnsbytes(idx, cnsbytes, &cnsplane);
	if (ret < 0){
	    /* This means that the cnscode is invalid. Should have been taken
	       care of in function hascns() and thus this code should never come
	       here. We catch this by the error message below */
	    fprintf(stderr,
	      "big5_to_iso():Big5->ISO2022-CN-EXT:gencnsbyte() rejected cnscode\n");
	    st->_errno = errno = EILSEQ;
	    return (0);
	}

	switch (cnsplane) {
	case 1:
	    if (st->iSOplane != cnsplane){ /* Is SODESIGNATION set to this plane?*/
		/* Output Escape sequence to set the SODESIGNATION to plane 1 */
		/* Before that check that we have space in outbuf for it */
		if (*outbytesleft < 4){
			st->_errno = errno = E2BIG;
			return (-1);
		}

		**outbuf = ESC;
		*(*outbuf+1) = '$';
		*(*outbuf+2) = ')';
		*(*outbuf+3) = GET_PLANEC(cnsplane);
		(*outbuf) += 4;
		(*outbytesleft) -= 4;
		st->iSOplane = cnsplane;
	    }

	    /* Check the current shift function whether it is SO. If not
	       set the SO shift function after confirming that you have
	       space for it. */
	    if (st->ishiftfunc != SO){
		if (*outbytesleft < 1){
		    st->_errno = errno = E2BIG;
		    return (-1);
		}

		**outbuf = SO;
		(*outbuf)++;
		(*outbytesleft)--;
		st->ishiftfunc = SO;
	    }
	    break;

	case 2:
	    if (st->iSS2plane != cnsplane){ /* Is SS2DESIGNATION set tothis plane ? */
		/* Output escape sequence to set SS2DESIGNATION to plane 2 */
		/* Before that check that we have space in outbuf for it */
		if (*outbytesleft < 4){
			st->_errno = errno = E2BIG;
			return (-1);
		}

		**outbuf = ESC;
		*(*outbuf+1) = '$';
		*(*outbuf+2) = '*';
		*(*outbuf+3) = GET_PLANEC(cnsplane);
		(*outbuf) += 4;
		(*outbytesleft) -= 4;
		st->iSS2plane = cnsplane;
	    }

	    /* Output the SS2 shift function only when we have sufficient space
	       for the 2 cns code bytes also */
	    if (*outbytesleft < 4){
		st->_errno = errno = E2BIG;
		return (-1);
	    }

	    **outbuf = ESC;
	    *(*outbuf+1) = SS2;
	    (*outbuf) += 2;
	    (*outbytesleft) -= 2;

	    break;

	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 12:
	case 14:
	case 15:
	case 16:
	    if (st->iSS3plane != cnsplane){ /* Is SS3DESIGNATION set tothis plane? */
		/* Output escape sequence to set SS3DESIGNATION to cnsplane */
		/* Before that check that we have space in outbuf for it */
		if (*outbytesleft < 4){
			st->_errno = errno = E2BIG;
			return (-1);
		}

		**outbuf = ESC;
		*(*outbuf+1) = '$';
		*(*outbuf+2) = '+';
		*(*outbuf+3) = GET_PLANEC(cnsplane);
		(*outbuf) += 4;
		(*outbytesleft) -= 4;
		st->iSS3plane = cnsplane;

	    }

	    /* Output the SS3 shift function only when we have sufficient space
	       for the 2 cns code bytes also */
	    if (*outbytesleft < 4){
		st->_errno = errno = E2BIG;
		return (-1);
	    }

	    **outbuf = ESC;
	    *(*outbuf+1) = SS3;
	    (*outbuf) += 2;
	    (*outbytesleft) -= 2;

	    break;

	default: /* Should have been taken care of in caller of this funcion */

	    /* This means that the cnscode is invalid. Should have been taken
	       care of in function hascns() and thus this code should never
	       come here. We catch this by the error message below */
	    fprintf(stderr, "big5_to_iso():Big5->ISO2022-CN-EXT:Rejecting cnscode\n");
	    st->_errno = errno = EILSEQ;
	    return (0);

	    break;

	} /* end switch */

	/* Output the cns code */
	if (*outbytesleft < 2){
	    st->_errno = errno = E2BIG;
	    return (-1);
	}

	**outbuf = cnsbytes[0];
	*(*outbuf+1) = cnsbytes[1];
	(*outbuf) += 2;
	(*outbytesleft) -= 2;


	return (0);

}


static int getcnsbytes(int idx, char *cnsbytes, int *cnsplane)
{

	unsigned long cnscode;
	unsigned long val;
	int plane;

	cnscode = big5_cns_tab[idx].value;

	plane = (int) (cnscode >> 16);
	switch (plane) {
	case 0x21:	/* 0x8EA1 - G */
	case 0x22:	/* 0x8EA2 - H */
	case 0x23:	/* 0x8EA3 - I */
	case 0x24:	/* 0x8EA4 - J */
	case 0x25:	/* 0x8EA5 - K */
	case 0x26:	/* 0x8EA6 - L */
	case 0x27:	/* 0x8EA7 - M */
	case 0x28:	/* 0x8EA8 - N */
	case 0x29:	/* 0x8EA9 - O */
	case 0x2a:	/* 0x8EAA - P */
	case 0x2b:	/* 0x8EAB - Q */
	case 0x2c:	/* 0x8EAC - R */
	case 0x2d:	/* 0x8EAD - S */
	case 0x2f:	/* 0x8EAF - U */
	case 0x30:	/* 0x8EB0 - V */
	    *cnsplane = plane - 0x20;	/* so that we can use GET_PLANEC() */
	    break;

	case 0x2e:	/* 0x8EAE - T */
	    *cnsplane = 3;		/* CNS 11643-1992. Why is this returning 3?  */
	    break;

	default:
	    return (-1); /* Should not have happened */
	    break;
	}

	val = cnscode & 0xffff;
	cnsbytes[0] = (val & 0xff00) >> 8;
	cnsbytes[1] = val & 0xff;

	return (0);

}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, table_t v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
	    mid = (low + high) / 2;
	    if (x < v[mid].key)
		high = mid - 1;
	    else if (x > v[mid].key)
		low = mid + 1;
	    else	/* found match */
		return mid;
	}
	return (-1);	/* no match */
}
