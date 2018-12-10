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
#include <stdlib.h>
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */


/*
   Converts From:	ISO2022-CN-EXT encoding.
   Converts To:		Taiwanese EUC encoding ( CNS11643 ) and big5 encoding

 */

#include "iso2022-cn.h"

/* Forward reference the functions constrained to the scope of this file */
static int process_esc_seq(char, _iconv_st *);
static int ascii_to_euc(char, _iconv_st *, unsigned char **, size_t *);
static int iscns( _iconv_st * );


extern int errno;

/*
 * _icv_open: Called from iconv_open(). Allocates and initializes _iconv_st
 *            structure. Returns pointer to the structure as (void *).
 */


void *
_icv_open()
{
	_iconv_st  *st;

	/* Allocate */
	if (( st = (_iconv_st *) malloc( sizeof( _iconv_st ))) == NULL ){
	    errno = ENOMEM;
	    return ((void *) -1);
	}

	/* Initialize */
	st->Sfunc = SI;
	st->SSfunc = NONE;
	st->ESCstate = OFF;
	st->firstbyte = True;
	st->numsav = 0;
	st->SOcharset = NULL;		/* no default charset */
	st->SS2charset = NULL;		/* no default charset */
	st->SS3charset = NULL;		/* no default charset */
	st->nonidcount = 0;
	st->_errno = 0;

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
	if (st == NULL )
	    errno = EBADF;
	else
	    free(st);
}


/*
 * _icv_iconv: Called from iconv(). Does the convertion from ISO2022-CN-EXT
 *			   to CNS11643
 */
/*=======================================================
 *
 *   State machine for interpreting ISO2022-CN-EXT code
 *
 *=======================================================
 *
 *
 *=======================================================*/

size_t
iso2022_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
			unsigned char **outbuf, size_t *outbytesleft, int (*convert)() )
{

	int ret, n;

	if (st == NULL) {
	    errno = EBADF;
	    return ((size_t) -1);
	}

	if ( inbuf == NULL || *inbuf == NULL || inbytesleft == NULL ||
			*inbytesleft <= 0 ) { /* Reset request */
	    st->Sfunc = SI;
	    st->SSfunc = NONE;
	    st->ESCstate = OFF;
	    st->firstbyte = True;
	    st->numsav = 0;
	    st->SOcharset = NULL;
	    st->SS2charset = NULL;
	    st->SS3charset = NULL;
	    st->nonidcount = 0;
	    st->_errno = 0;
	    return ((size_t) 0);
	}

	st->_errno = 0;
	errno = 0;

	/* Before we use *inbytesleft or *outbytesleft we should confirm that
	inbytesleft and outbytesleft are non-NULL. I am considering inbytesleft
	or *inbytesleft having 0 or negative value as a reset request. I am
	considering outbytesleft having 0 value as no space in output buffer.
	Also, here itself I am verifying that outbuf and *outbuf should be non-NULL
	pointers so I do not have to worry about them being NULL below in the
	conversion sub-routines. I also confirm here that *outbytesleft should be
	greater than 0 before we can continue further */

	if ( outbytesleft == NULL || *outbytesleft <= 0 ||
			outbuf == NULL || *outbuf == NULL ) {
	    errno = E2BIG;
	    return((size_t)-1);
	}

	/* A state machine to interpret ISO, driven by the shift functions SI, SO */

	do {
	    if (st->firstbyte == False) { /* Is SO, SS2, SS3 second byte */
		st->keepc[1] = **inbuf;
		n = (*convert)( st, outbuf, outbytesleft, iscns(st) );
		if ( n < 0 )
		    return((size_t)-1); /* Insufficient space in output buffer */
		else if ( n > 0 ){ /* No CNS for this Chinese code */
		    n = ascii_to_euc(NON_ID_CHAR, st, outbuf, outbytesleft);
		    if ( n < 0 )
			return((size_t)-1);
		    st->nonidcount += 1;
		} else
		    st->nonidcount -= 1; /* The first byte identified as
						valid Chinese byte and is
						processed */
		st->firstbyte = True;
		st->SSfunc = NONE;	/* If we just processed SS bytes,
					   this will reset SSfunc to NONE. If
					   we just processed SO bytes, this was
					   already NONE */
	    } else if ( st->SSfunc != NONE ) { /* We are currently expecting
						 SS2 or SS3 Chinese bytes */
		    st->keepc[0] = **inbuf;
		    st->nonidcount += 1;
		    st->firstbyte = False;
	    } else if ( **inbuf == ESC && st->ESCstate == OFF ) {
		    st->nonidcount += 1; /* For the ESC character */
		    st->ESCstate = E0;
	    } else if ( st->ESCstate != OFF ) { /* Continue processing the
						  escape sequence */
		ret = process_esc_seq( **inbuf, st );
		if ( ret == DONE ) { 	/* ESC seq interpreted correctly.
					     Switch off the escape machine */
		    st->ESCstate = OFF;
		} else if ( ret == INVALID ){
		    if (st->Sfunc == SI){	/* An invalid ESC sequence
						 encountered.  Process
						 the text saved in
						 st->savbuf as ASCII. Switch
						 off the escape machine */
			n = ascii_to_euc( **inbuf, st, outbuf, outbytesleft );
			if ( n < 0 ) /* Insufficient space in output buffer */
				return((size_t)-1);
			st->nonidcount -= st->numsav; /* Since invalid Esc
						       sequence is outputted
						       as ASCII */
		    } else if (st->Sfunc == SO) { /* An invalid ESC sequence
						     encountered. Don't know
						     what to do. So flag
						     error illegal seq. It is
						     wise not to continue
						     processing input. Switch
						     off the escape machine */
			st->_errno = errno = EILSEQ;
			st->nonidcount += 1; /* For this character */
		    }
		    st->numsav = 0; 	 /* Discard the saved characters of
					    invalid sequence */
		    st->ESCstate = OFF;
		} /* more char. needed for escape sequence */
	    } else if (st->Sfunc  == SI) {
		/* Switch state to SO only if SOdesignation is set. */
		if ( **inbuf == SO && st->SOcharset != NULL ){
		    st->Sfunc = SO;
		} else { /* Is ASCII */
		    n = ascii_to_euc(**inbuf, st, outbuf, outbytesleft );
		    if ( n < 0 ) /* Insufficient space in output buffer */
			return((size_t)-1);
		}
	    } else if (st->Sfunc  == SO) {
		if ( **inbuf == SI ){ /* Switch state to SO */
		    st->Sfunc = SI;
		}
		else {
		    st->keepc[0] = **inbuf;
		    st->nonidcount += 1;
		    st->firstbyte = False;
		}
	    }
	    else
		fprintf(stderr,
		    "_icv_iconv():ISO-CN-EXT->CNS:Should never have come here\n");

	    (*inbuf)++;
	    (*inbytesleft)--;

	    if ( st->_errno)
		break; /* Break out of while loop */

	    if (errno) /* We set st->_errno before we set errno. If errno is set
				      somewhere else we handle that here */
		return((size_t)-1);

	} while (*inbytesleft > 0 && *outbytesleft > 0);


/* We now have to handle the case where we have successfully processed the
   previous input character which exhausted the output buffer. This is handled
   by the while loop. However, since there are more input characters that
   haven't been processed yet, we need to set the errno appropriately and
   return -1. */
	if ( *inbytesleft > 0 && *outbytesleft == 0) {
	    errno = E2BIG;
	    return((size_t)-1);
	}
	return (*inbytesleft + st->nonidcount);
}


static int
process_esc_seq( char c, _iconv_st *st )
{

	switch(st->ESCstate){
	case E0:
	    switch (c){
	    case SS2LOW:
		if ( st->SS2charset == NULL ){
		    /* We do not expect SS2 shift function before
		       SS2 designation is set */
		    st->savbuf[0] = ESC;
		    st->numsav = 1;
		    return(INVALID);
		}
		st->SSfunc = SS2;
		/* Since valid ESC sequence remove the ESC from the
		   nonidcount */
		st->nonidcount -= 1;
		return(DONE);
	    case SS3LOW:
		if ( st->SS3charset == NULL ){
		    /* We do not expect SS3 shift function before
		       SS3 designation is set */
		    st->savbuf[0] = ESC;
		    st->numsav = 1;
		    return(INVALID);
		}
		st->SSfunc = SS3;
		/* Since valid ESC sequence remove the ESC from the
		   nonidcount */
		st->nonidcount -= 1;
		return(DONE);
	    case '$':
		st->nonidcount += 1; /* ESC sequence not complete yet */
		st->ESCstate = E1;
		return(NEEDMORE);
	    default:
		st->savbuf[0] = ESC;
		st->numsav = 1;
		return(INVALID);
	    } /* end switch */


	case E1:
	    switch (c){
	    case ')':
		st->nonidcount += 1; /* ESC sequence not complete yet */
		st->ESCstate = E2;
		return(NEEDMORE);
	    case '*':
		st->nonidcount += 1; /* ESC sequence not complete yet */
		st->ESCstate = E3;
		return(NEEDMORE);
	    case '+':
		st->nonidcount += 1; /* ESC sequence not complete yet */
		st->ESCstate = E4;
		return(NEEDMORE);
	    default:
		st->savbuf[0] = ESC;
		st->savbuf[1] = '$';
		st->numsav = 2;
		return(INVALID);
	    }

	case E2:
	    st->SOcharset = c;
	    /* Since valid ESC sequence remove decriment nonidcount
	       appropriately for all earlier characters in escape sequence */
	    st->nonidcount -= 3;
	    return(DONE);

	case E3:
	    st->SS2charset = c;
	    /* Since valid ESC sequence remove decriment nonidcount
	       appropriately for all earlier characters in escape sequence */
	    st->nonidcount -= 3;
	    return(DONE);

	case E4:
	    st->SS3charset = c;
	    /* Since valid ESC sequence remove decriment nonidcount
	       appropriately for all earlier characters in escape sequence */
	    st->nonidcount -= 3;
	    return(DONE);

	default:
	    fprintf(stderr,
		    "process_esc_seq():ISO-CN-EXT->CNS:Should never have come here\n");
	    st->_errno = errno = EILSEQ;
	    return(DONE);

	} /* end switch */
}


static int
ascii_to_euc( char c, _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft )
{

	int i;

	if ( *outbytesleft < (1 + st->numsav) ) {
	    st->_errno = errno = E2BIG;
	    return (-1);
	}

	for ( i=0; i < st->numsav; i++ ) {
	    *(*outbuf)++ = (unsigned char) st->savbuf[i];
	    (*outbytesleft)--;
	}

	*(*outbuf)++ = (unsigned char) c;
	(*outbytesleft)--;

	return(0);
}


static int
iscns( _iconv_st *st )
{
	int plane_no = -1;

	if ( st->SSfunc == NULL && st->SOcharset == 'G' )
	    plane_no = 1;
	else if ( st->SSfunc == SS2 && st->SS2charset == 'H' )
	    plane_no = 2;
	else if ( st->SSfunc == SS3 )
	    switch ( st->SS3charset ){
	    case 'I': plane_no = 3; break;
	    case 'J': plane_no = 4; break;
	    case 'K': plane_no = 5; break;
	    case 'L': plane_no = 6; break;
	    case 'M': plane_no = 7; break;
	    }
	return (plane_no);
}
