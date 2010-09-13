/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lssmb.c:	Contains all code specific to the  MS-NET file server.
 *		Undef SMBSERVER to remove SMB support.
 */


#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/tiuser.h>

#include "lsparam.h"
#include "lssmbmsg.h"
#include "lsdbf.h"


#ifdef	SMBSERVER


/*
 * Dlevel	- Debug level for DEBUG((level, ... ) type calls
 * Msnet	- Who is logging this message (the SMB code is)
 */

#define Dlevel	3
#define Msnet	"SMB parser:"

extern char *malloc();
char	*bytes_to_ascii();
void	getword(char *addr, short *w);

/*
 * In the event of an error, it may be necessary to send a response to
 * the remote node before closing the virtual circuit.  The following
 * is the return message that should be sent.  (Initially, I am not
 * bothering to send the response message; I am assuming that the
 * MS-NET client will be able to figure out that things went wrong, but
 * we may find that is not the case.
 */

static unsigned char errbuf[] = {
/* NegProt Return	*/	0xff, 'S', 'M', 'B', 0x72,
/* ERRSRV		*/	0x2,
				0,
/* SMBerror		*/	0x1, 0,
				0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0,
				0, 0,
				0, 0, 0, 0,
/* wcnt == 1		*/	1,
/* no dialects		*/	0xff, 0xff,
				0, 0
};


/*
 * s m b s e r v i c e
 *
 * Function called by listener process when it receives a connect
 * request from a node that wants to talk Microsoft's MS-NET Core
 * Protocol...the functions gets called after the listener forks.
 */

void
smbservice(bp, bufsize, argv)
char *bp;		/* pointer to message buffer */
int bufsize;		/* size of message */
char **argv;		/* server arguments */
{
	char *server = *argv;	/* path of server 		*/
	char logbuf[256];
	char **args;
	int i, m_size;
	int twos, nulls;
	char *p, *q;
	short size;

	/*
	 * Is this really a correct negotiate protocol message?
	 */

	if (*(bp+FSP_COM) != FSPnegprot){
		sprintf(logbuf, "%s: Bad Command Code, 0x%x", 
			Msnet, *(bp+FSP_COM));
		goto badexit;
	}

	/*
	 * Are there exactly 0 argument words in the message?
	 */

	if (*(bp+FSP_WCNT) != 0){
		sprintf(logbuf, "%s: Incorrect # of Parameter Words, 0x%x",
			Msnet, *(bp+FSP_WCNT));
		goto badexit;
	}

	/*
	 * get the size of the data in the message
	 */

	p = bp + FSP_PARMS;
	getword(p, &size);

	/*
	 * make sure the data is valid; it should have a series of
	 * "dialect" strings, which are of the form [02 string 00].
	 * if(twos == nulls) then the data is well formed, else something
	 * is wrong.
	 */

	twos = nulls = 0;
	p += 2;
	for(q = p; q < p + size; ++q){
		if(*q == '\0')
			nulls++;
		else if(*q == 02)
			twos++;
	}

	if(twos != nulls){
		sprintf(logbuf, "%s: Bad Data Format, twos=%d, nulls=%d",
			Msnet, twos, nulls);
		goto badexit;
	}

	/*
	 * Count the number of arguments that were passed
	 * to me by the listener...
	 */

	for(i=0, args=argv; *args; ++args, ++i)
		;

	/*
	 * There are a few kinds of arguments that I will pass to the server:
	 *
	 * -D<string>	- means "the client speaks this dialect . . ."
	 * 		  there me be more than one of these, if the client
	 * 		  is able to speak multiple dialects.
	 *
	 * Any arguments passed to me by the listener will be passed along
	 * as is . . .
	 *
	 * Allocate an array of "char *"s that will let me point to all
	 * of the following:
	 * 1.	As many -D options as are needed (the exact number is
	 *  	contained in the variable "twos"),
	 *  2.	One -A option for the single logical name
	 *  	of the client,
	 *  3.	As many positions as are needed to pass along the arguments
	 *  	passed to me by the listener (variable "i"),
	 *  4.	The name of the Server executable file (always arg[0]), and
	 *  5.  "Ascii-ized" version of input message as last arg.
	 *  6.	A NULL terminator.
	 */

	m_size = sizeof(char *) * (twos + i + 4);
	if((args = (char **)malloc((unsigned)m_size)) == 0){
		sprintf(logbuf, "%s: Can't malloc arg space, %d bytes", 
			Msnet, m_size);
		goto badexit;
	}

	/*
	 * put together the first argument to exec(2) which should be
	 * the full pathname of the executable server file.
	 */

	args[0] = server;

	/*
	 * Send dialect strings down, in order of preference
	 */

	for(i=1, q=p; q < p + size; ++i, ++q){
		q = strchr(q, 02);		/* find start of string */

		m_size = strlen(++q) + 1 + 2;
		if((args[i] = malloc((unsigned)m_size)) == 0){
			sprintf(logbuf, 
				"%s: Can't malloc Server Path buf, %d bytes",
				Msnet, m_size);
			goto badexit;
		}

		strcpy(args[i], "-D");
		strcat(args[i], q);		/* put -Ddialect\0 in arglist */
		q = strchr(q, '\0');		/* find end of string */
	}

	/*
	 * Add in arguments that were passed to me by the listener
	 * first arg is server path, so we ignore that.
	 */

	for( ++argv; *argv; ++argv, ++i)
		args[i] = *argv;

	/*
	 * add ascii-ized version of message
	 */

	args[i++] = bytes_to_ascii(bp, bufsize);

	/*
	 * NULL terminate the list
	 */

	args[i] = NULL;

	exec_cmd((dbf_t *)0, args);
	return;			/* error logged in start_server */

badexit:
	logmessage(logbuf);
}


/*
 * g e t w o r d
 *
 * move a word from an arbitrary position in a character buffer, into
 * a short, and flip the bytes.
 * (NOTE that word is a 16-bit iapx-286 word).
 */

void
getword(char *addr, short *w)
{
	lobyte(*w) = *addr++;
	hibyte(*w) = *addr;
}

/* b y t e s _ t o _ a s c i i
 *	Routine to convert a binary array to a printable sequence of
 *	characters.  For example, if the input to this routine were:
 *
 *	inbuf = "012", and n = 3
 *
 *	then the output would be a pointer to the string:
 *
 *	"303132"
 *
 *	No assumption is made about NULL terminators on input, because
 *	it is probably binary, and not a string.
 */


char *
bytes_to_ascii(inbuf, n)
char *inbuf;		/* initialized buffer of binary data */
int n;			/* size of input buffer */
{
	char *outbuf;	/* return string */
	char *p;	/* scratch pointer */
	int i;		/* scratch variable */

	/* malloc 2x space for output plus one for NULL */
	if (outbuf = malloc(n * 2 + 1)) {
		/* Fill in output buffer, with 2 character, capitalized hex. */
		for (i = 0, p = outbuf; i < n; ++inbuf, p += 2, ++i) {
			sprintf(p, "%2.2X", *inbuf);
		}
		return(outbuf);
	}
	else
		return(NULL);
}



#else

void
smbservice(bp, size, argv)
char *bp;		/* pointer to message buffer */
int size;		/* size of message */
char **argv;		/* server arguments */
{
	logmessage("SMB service NOT supported");
}

#endif	/* SMBSERVICE */
