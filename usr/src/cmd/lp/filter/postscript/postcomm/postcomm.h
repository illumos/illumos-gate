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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 *
 * A few special definitions used by the program that sends jobs to PostScript
 * printers. Most, if not all the testing, was done on a QMS PS-800 printer.
 *
 * POSTBEGIN, if it's not NULL, is some PostScript code that's sent to the
 * printer before any of the input files. It's not terribly important since the
 * same thing can be accomplished in other ways, but it is convenient. POSTBEGIN
 * is initialized so as to disable job timeouts. The string can also be set on
 * the command line using the -P option.
 *
 */


#define POSTBEGIN	"statusdict /waittimeout 0 put\n"


/*
 *
 * Status lines returned by the printer usually look like,
 *
 *
 *	%%[ status: idle; source serial 25 ]%%
 *	%%[ status: waiting; source serial 25 ]%%
 *	%%[ status: initializing; source serial 25 ]%%
 *	%%[ status: busy; source serial 25 ]%%
 *	%%[ status: printing; source serial 25 ]%%
 *	%%[ status: PrinterError: out of paper; source serial 25 ]%%
 *	%%[ status: PrinterError: no paper tray; source serial 25 ]%%
 *
 *
 * although the list isn't meant to be complete.
 *
 * The following constants are used to classify some of the different printer
 * states. readline() reads status lines from ttyi and converts everything to
 * lower case. getstatus() interprets the text that readline() stores in sbuf[]
 * and returns integer codes that classify the printer status. Those codes are
 * used in routines start(), send(), and done() to figure out what's happening
 * and what should be done next.
 *
 */


#define WAITING		0		/* printer wants more data */
#define BUSY		1		/* processing data already sent */
#define PRINTING	2		/* printing a page */
#define IDLE		3		/* ready to start the next job */
#define ENDOFJOB	4		/* readline() builds this up on EOF */
#define PRINTERERROR	5		/* PrinterError - eg. out of paper */
#define ERROR		6		/* some kind of PostScript problem */
#define FLUSHING	7		/* throwing out the rest of the job */
#define INITIALIZING	8		/* printer's booting */
#define DISCONNECT	9		/* from Datakit */
#define UNKNOWN		10		/* in case we missed anything */
#define NOSTATUS	11		/* no response from the printer */


/*
 *
 * An array of type Status is used, in getstatus(), to figure out the printer's
 * current state. Just helps convert strings representing the current state into
 * integer codes that other routines use.
 *
 */


typedef struct {

	char	*state;			/* printer's current status */
	int	val;			/* value returned by getstatus() */

} Status;


/*
 *
 * STATUS is used to initialize an array of type Status that translates the
 * ASCII strings returned by the printer into appropriate codes that can be used
 * later on in the program. State strings should all be entered in lower case.
 * readline() converts characters to lower before adding them to sbuf[]. If you
 * add any states, do it in lower case only, and be sure to add the new status
 * descriptions before the UNKNOWN entry. The lookup in getstatus() terminates
 * when it finds the printer state or encounters an entry with NULL in the state
 * field.
 *
 */


#define STATUS								\
									\
	{								\
	    "waiting", WAITING,						\
	    "busy", BUSY,						\
	    "printing", PRINTING,					\
	    "idle", IDLE,						\
	    "endofjob", ENDOFJOB,					\
	    "printererror", PRINTERERROR,				\
	    "error", ERROR,						\
	    "flushing", FLUSHING,					\
	    "initializing", INITIALIZING,				\
	    "conversation ended.\n", DISCONNECT,			\
	    NULL, UNKNOWN						\
	}


/*
 *
 * The baud rate can be set on the command line using the -b option. If you omit
 * it BAUDRATE will be used.
 *
 */


#define BAUDRATE	B9600


/*
 *
 * An array of type Baud is used, in routine getbaud(), to translate ASCII
 * strings into termio values that represent the requested baud rate.
 *
 */


typedef struct {

	char	*rate;			/* string identifying the baud rate */
	short	val;			/* and its termio.h value */

} Baud;


/*
 *
 * BAUDTABLE initializes the array that's used to translate baud rate requests
 * into termio values. It needs to end with an entry that has NULL assigned to
 * the rate field.
 *
 */


#define BAUDTABLE							\
									\
	{								\
	    "9600", B9600,						\
	    "B9600", B9600,						\
	    "19200", EXTA,						\
	    "19.2", EXTA,						\
	    "B19200", EXTA,						\
	    "EXTA", EXTA,						\
	    "1200", B1200,						\
	    "B1200", B1200,						\
	    "B4800", B4800,						\
	    "4800", B4800,						\
	    NULL, B9600							\
	}


/*
 *
 * A few miscellaneous definitions. BLOCKSIZE is the default size of the buffer
 * used for reading the input files (changed with the -B option). BUFSIZE is
 * the size of the character array used to store printer status lines - don't
 * make it too small!
 *
 */


#define BLOCKSIZE	1024
#define BUFSIZE		512


/*
 *
 * Finally we'll declare a few of the non-integer valued functions used in
 * postio.c.
 *
 */


char	*malloc();
char	*strtok();


