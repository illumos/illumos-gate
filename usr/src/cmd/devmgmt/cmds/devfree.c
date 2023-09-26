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

/*    Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved */

/*
 *	devfree key [device [...]]
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<stdio.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fmtmsg.h>
#include	<devmgmt.h>
#include	<values.h>
#include	<devtab.h>

/*
 *  Local definitions
 *	TRUE		Boolean TRUE value
 *	FALSE		Boolean FALSE value
 */
#ifndef		TRUE
#define		TRUE		('t')
#endif

#ifndef		FALSE
#define		FALSE		0
#endif


/*
 *  Exit codes:
 *	EX_OK		Exit code for all went well
 *	EX_ERROR	Exit code for something failed
 *	EX_TBLERR	Exit code for errors relating to device or lock tables
 *	EX_NOFREE	Exit code for free failed
 */

#define		EX_OK		0
#define		EX_ERROR	1
#define		EX_TBLERR	2
#define		EX_NOFREE	3


/*
 * Messages
 *	M_USAGE		Usage error
 *	M_INVKEY	Invalid key specified
 *	M_NOTRSVD	Attempting to free something not alloc'd
 *	M_NOTONKEY	Attempting to free with wrong key
 *	M_DEVTAB	Error opening the device table
 *	M_RSVTAB	Error opening the device-reservation table
 *	M_ERROR		Some internal error
 */

#define		M_USAGE		"usage: devfree key [device [...]]"
#define		M_INVKEY	"Invalid key: %s"
#define		M_NOTRSVD	"Device not reserved: %s"
#define		M_NOTONKEY	"Cannot unreserve device: %s"
#define		M_DEVTAB	"Cannot open the device table: %s"
#define		M_RSVTAB	"Cannot open the device-reservation table: %s"
#define		M_ERROR		"Internal error, errno=%d"


/*
 *  Local functions and static data
 *	stdmsg(r,l,s,m)		Macro for standard message generation
 *				r	MM_NRECOV or MM_RECOV (recoverability)
 *				l	Label
 *				s	Severity
 *				m	Message
 *	lbl			Buffer for the label-component of a message.
 *	msg			Buffer for the text-component of a message.
 */

#define	stdmsg(r, l, s, m)	\
	(void) fmtmsg(MM_PRINT | MM_UTIL | r, l, s, m, MM_NULLACT, MM_NULLTAG)

static	char	lbl[MM_MXLABELLN+1];
static	char	msg[MM_MXTXTLN+1];

/*
 *  devfree key [device [device [...]]]
 *
 *	This command frees devices that have been reserved using
 *	the devreserv command (or the devreserv() function).
 *
 *  Options:  None
 *
 *  Arguments:
 *	key		The key on which the device to free was allocated on.
 *			If omitted, all keys are assumed.
 *	device		The device to free.  If omitted, all devices allocated
 *			using the key are freed.
 *
 *  Command Values:
 *	EX_OK		0	Device(s) successfully freed
 *	EX_ERROR	1	A syntax error or other error occurred
 *	EX_TBLERR	2	A problem with device management tables
 *	EX_NOFREE	3	A requested device couldn't be freed
 */

int
main(int argc, char *argv[])
{
	/* Automatics */
	char			**argp;		/* Ptr to current argument */
	struct reservdev	**rsvd;		/* Ptr to list of locks */
	struct reservdev	**plk;		/* Running ptr to locks */
	char			*devtab;	/* Ptr to device table name */
	char			*rsvtab;	/* Ptr to dev-rsv-tbl name */
	char			*p;		/* Temp char pointer */
	int			argcount;	/* Number of args on cmd */
	long			lkey;		/* Key for locking (long) */
	int			key;		/* Key for locking */
	int			halt;		/* TRUE if we need to stop */
	int			sev;		/* Message severity */
	int			exitcode;	/* Value of command */
	int			syntaxerr;	/* Flag, TRUE if syntax error */
	int			exitcd;		/* Value for exit() */
	int			c;		/* Option character */
	const char		*errstr;


	/*
	 * Initializations
	 */

	/* Build a message label */
	if (p = strrchr(argv[0], '/'))
		p++;
	else
		p = argv[0];
	(void) strlcat(strcpy(lbl, "UX:"), p, sizeof (lbl));

	/*
	 * Make only the text component of messages appear
	 * (remove this in SVR4.1)
	 */
	(void) putenv("MSGVERB=text");


	/*
	 * Parse the options from the command line
	 */

	opterr = 0;
	syntaxerr = FALSE;
	while ((c = getopt(argc, argv, "")) != EOF) {
		switch (c) {
		default:
			syntaxerr = FALSE;
			break;
		}
	}


	/* Argument initializations */
	argp = &argv[optind];
	if ((argcount = argc-optind) < 1)
		syntaxerr = TRUE;


	/* If there's (an obvious) syntax error, write a message and quit */
	if (syntaxerr) {
		stdmsg(MM_NRECOV, lbl, MM_ERROR, M_USAGE);
		exit(EX_ERROR);
	}


	/*
	 *  devfree key
	 *
	 *	Free all devices that have been reserved using the key "key".
	 */

	if (argcount == 1) {

		/* Extract the key from the command */
		lkey = strtonum(*argp, 1, MAXINT, &errstr);
		if (errstr != NULL) {
			(void) snprintf(msg, sizeof (msg), M_INVKEY, *argp);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exit(EX_ERROR);
		}
		key = (int)lkey;

		/* Get the list of devices currently reserved */
		if (rsvd = reservdev()) {
			exitcd = EX_OK;
			for (plk = rsvd; *plk; plk++) {
				if ((*plk)->key == key)
					if (devfree(key, (*plk)->devname) != 0)
						exitcd = EX_NOFREE;
			}
		} else {
			if (((errno == ENOENT) || (errno == EACCES)) &&
			    (rsvtab = _rsvtabpath())) {
				(void) snprintf(msg, sizeof (msg), M_RSVTAB,
				    rsvtab);
				exitcd = EX_TBLERR;
				sev = MM_ERROR;
			} else {
				(void) snprintf(msg, sizeof (msg), M_ERROR,
				    errno);
				exitcd = EX_ERROR;
				sev = MM_HALT;
			}
			stdmsg(MM_NRECOV, lbl, sev, msg);
		}

		/* Done */
		exit(exitcd);
	}


	/*
	 *  devfree key device [...]
	 *
	 *	Free specific devices
	 */

	/* Open the device file (if there's one to be opened) */
	if (!_opendevtab("r")) {
		if (devtab = _devtabpath()) {
			(void) snprintf(msg, sizeof (msg), M_DEVTAB, devtab);
			exitcd = EX_TBLERR;
			sev = MM_ERROR;
		} else {
			(void) snprintf(msg, sizeof (msg), M_ERROR, errno);
			exitcd = EX_ERROR;
			sev = MM_HALT;
		}
		stdmsg(MM_NRECOV, lbl, sev, msg);
		exit(exitcd);
	}

	/* Extract the key from the command */
	lkey = strtonum(*argp, 1, MAXINT, &errstr);
	if (errstr != NULL) {
		(void) snprintf(msg, sizeof (msg), M_INVKEY, *argp);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exit(EX_ERROR);
	}
	key = (int)lkey;
	argp++;

	/* Loop through the list of devices to free */
	exitcode = EX_OK;
	halt = FALSE;
	while (!halt && *argp) {

		/* Try to free the device */
		if (devfree(key, *argp) != 0) {
			if ((errno == EACCES) || (errno == ENOENT)) {

				/* Can't get at reservation file */
				if (rsvtab = _rsvtabpath()) {
					exitcode = EX_TBLERR;
					(void) snprintf(msg, sizeof (msg),
					    M_RSVTAB, rsvtab);
					sev = MM_ERROR;
				} else {
					exitcode = EX_ERROR;
					(void) snprintf(msg, sizeof (msg),
					    M_ERROR, errno);
					sev = MM_HALT;
				}
				stdmsg(MM_NRECOV, lbl, sev, msg);
				halt = TRUE;
			} else if (errno == EPERM) {

				/* Wrong key */
				(void) snprintf(msg, sizeof (msg), M_NOTONKEY,
				    *argp);
				stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
				exitcode = EX_NOFREE;
			} else if (errno == EINVAL) {

				/* Device not reserved */
				(void) snprintf(msg, sizeof (msg), M_NOTRSVD,
				    *argp);
				stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
				exitcode = EX_NOFREE;
			} else {

				/* Some other strange error occurred */
				(void) snprintf(msg, sizeof (msg), M_ERROR,
				    errno);
				stdmsg(MM_NRECOV, lbl, MM_HALT, msg);
				exitcode = EX_ERROR;
				halt = TRUE;
			}
		}
		argp++;
	}

	/* Exit with the appropriate code */
	return (exitcode);
}
