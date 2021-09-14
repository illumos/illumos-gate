/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_POSTIO_POSTIO_H
#define	_POSTIO_POSTIO_H

/*
 *
 * Definitions used by the program that sends jobs to PostScript printers.
 *
 * POSTBEGIN, if it's not NULL, is some PostScript code that's sent to the
 * printer before any of the input files. It's not terribly important since
 * the same thing can be accomplished in other ways, but this approach is
 * convenient. POSTBEGIN is initialized so as to disable job timeouts. The
 * string can also be set on the command line using the -P option.
 *
 */

#define	POSTBEGIN	"%!PS\nstatusdict /waittimeout 0 put\n"

/*
 * The following help determine where postio is when it's running - either
 * in the START, SEND, or DONE states. Primarily controls what's done in
 * getstatus().
 * RADIAN occasionally had problems with two way conversations. Anyway this
 * stuff can be used to prevent status queries while we're transmitting a
 * job. Enabled by the -q option.
 *
 */

#define	NOTCONNECTED	0
#define	START		1
#define	SEND		2
#define	DONE		3

/*
 * Previous versions of postio only ran as a single process. That was (and
 * still * is) convenient, but meant we could only flow control one direction.
 * Data coming back from the printer occasionally got lost, but that didn't
 * often hurt (except for lost error messages). Anyway I've added code that
 * lets you split the program into separate read and write processes, thereby
 * helping to prevent data loss in both directions. It should be particularly
 * useful when you're sending a job that you expect will be returning useful
 * data over the communications line.
 *
 * The next three definitions control what's done with data on communications
 * line.  The READ flag means the line can be read, while the WRITE flag means
 * it can be written. When we're running as a single process both flags are
 * set. I tried to overlay the separate read/write process code on what was
 * there and working for one process. The implementation isn't as good as it
 * could be, but should be safe. The single process version still works,
 * and remains the default.
 */

#define	READ		1
#define	WRITE		2
#define	READWRITE	3

/*
 * Messages generated on the printer and returned over the communications line
 * look like,
 *
 *	%%[ status: idle; source: serial 25 ]%%
 *	%%[ status: waiting; source: serial 25 ]%%
 *	%%[ status: initializing; source: serial 25 ]%%
 *	%%[ status: busy; source: serial 25 ]%%
 *	%%[ status: printing; source: serial 25 ]%%
 *	%%[ status: PrinterError: out of paper; source: serial 25 ]%%
 *	%%[ status: PrinterError: no paper tray; source: serial 25 ]%%
 *
 *	%%[ PrinterError: out of paper; source: serial 25 ]%%
 *	%%[ PrinterError: no paper tray; source: serial 25 ]%%
 *
 *	%%[ Error: undefined; OffendingCommand: xxx ]%%
 *	%%[ Flushing: rest of job (to end-of-file) will be ignored ]%%
 *
 * although the list isn't meant to be complete.
 *
 * The following constants are used to classify the recognized printer states.
 * readline() reads complete lines from ttyi and stores them in array mesg[].
 * getstatus() looks for the "%%[ " and " ]%%" delimiters that bracket printer
 * messages and if found it tries to parse the enclosed message. After the
 * lookup one of the following numbers is returned as an indication of the
 * existence or content of the printer message. The return value is used in
 * start(), send(), and done() to figure out what's happening and what can
 * be done next.
 */

#define	BUSY		0		/* processing data already sent */
#define	WAITING		1		/* printer wants more data */
#define	PRINTING	2		/* printing a page */
#define	IDLE		3		/* ready to start the next job */
#define	ENDOFJOB	4		/* readline() builds this up on EOF */
#define	PRINTERERROR	5		/* PrinterError - eg. out of paper */
#define	ERROR		6		/* some kind of PostScript error */
#define	FLUSHING	7		/* throwing out the rest of the job */
#define	INITIALIZING	8		/* printer is booting */
#define	DISCONNECT	9		/* from Datakit! */
#define	UNKNOWN		10		/* in case we missed anything */
#define	NOSTATUS	11		/* no response from the printer */

#define	WRITEPROCESS	12		/* dummy states for write process */
#define	INTERACTIVE	13		/* and interactive mode */

/*
 * An array of type Status is used, in getstatus(), to figure out the printer's
 * current state. Just helps convert strings representing the current state into
 * integer codes that other routines use.
 */

typedef struct {

	char	*state;			/* printer's current status */
	int	val;			/* value returned by getstatus() */

} Status;

/*
 * STATUS is used to initialize an array of type Status that translates the
 * ASCII strings returned by the printer into appropriate codes that can be
 * used later on in the program. getstatus() converts characters to lower
 * case, so if you add any entries make them lower case and put them in
 * before the UNKNOWN entry.
 * The lookup terminates when we get a match or when an entry with a NULL state
 * is found.
 *
 */

#define	STATUS								\
									\
	{								\
	    "busy", BUSY,						\
	    "waiting", WAITING,						\
	    "printing", PRINTING,					\
	    "idle", IDLE,						\
	    "endofjob", ENDOFJOB,					\
	    "printererror", PRINTERERROR,				\
	    "error", ERROR,						\
	    "flushing", FLUSHING,					\
	    "initializing", INITIALIZING,				\
	    NULL, UNKNOWN						\
	}

/*
 *
 * The baud rate can be set on the command line using the -b option. If you omit
 * it BAUDRATE will be used.
 *
 */

#define	BAUDRATE	B9600

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

#define	BAUDTABLE							\
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
	    "2400", B2400,						\
	    "B2400", B2400,						\
	    "B4800", B4800,						\
	    "4800", B4800,						\
	    "38400", EXTB,						\
	    "38.4", EXTB,						\
	    "B38400", EXTB,						\
	    "EXTB", EXTB,						\
	    "57600", B57600,						\
	    "57.6", B57600,						\
	    "76800", B76800,						\
	    "76.8", B76800,						\
	    "115200", B115200,						\
	    "115.2", B115200,						\
	    "153600", B153600,						\
	    "153.6", B153600,						\
	    "230400", B230400,						\
	    "230.4", B230400,						\
	    "307200", B307200,						\
	    "307.2", B307200,						\
	    "460800", B460800,						\
	    "460.8", B460800,						\
	    "921600", B921600,						\
	    "921.6", B921600,						\
	    "1000000", B1000000,					\
	    "1152000", B1152000,					\
	    "1500000", B1500000,					\
	    "2000000", B2000000,					\
	    "2500000", B2500000,					\
	    "3000000", B3000000,					\
	    "3500000", B3500000,					\
	    "4000000", B4000000,					\
	    NULL, B9600							\
	}

/*
 *
 * A few miscellaneous definitions. BLOCKSIZE is the default size of the buffer
 * used for reading the input files (changed with the -B option). MESGSIZE is
 * the size of the character array used to store printer status lines - don't
 * make it too small!
 *
 */

#define	BLOCKSIZE	2048
#define	MESGSIZE	512

#endif	/* _POSTIO_POSTIO_H */
