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
/*      All Rights Reserved   */
  

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  listdgrp.c
 *
 *  Contains
 *	listdgrp	Writes on the standard output stream a list of devices
 *			that belong to the specified device group
 */

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<devmgmt.h>
#include	<devtab.h>
#include	<fmtmsg.h>


/*
 *  Local Definitions
 *	TRUE		Boolean TRUE value (if not already defined)
 *	FALSE		Boolean not-TRUE value (if not already defined)
 */

#ifndef	TRUE
#define	TRUE		('t')
#endif

#ifndef	FALSE
#define	FALSE		(0)
#endif

/*
 *  Messages:
 *	M_USAGE		Command usage error
 *	M_NODGRP	Device group not found
 *	M_DGRPTAB	Device-group table not found
 *	M_ERROR		Internal error
 */
 
#define	M_USAGE		"usage: listdgrp dgroup"
#define	M_NODGRP	"Device group not found: %s"
#define	M_DGRPTAB	"Cannot open device-group table: %s"
#define	M_ERROR		"Internal error, errno=%d"


/*
 *  Exit codes
 *	EX_OK		Exiting okay, no problem
 *	EX_ERROR	Some problem with the command
 *	EX_NODGRPTAB	Device group table could not be opened
 *	EX_NODGROUP	Device group couldn't be found
 */

#define	EX_OK		0
#define	EX_ERROR	1
#define	EX_NODGRPTAB	2
#define	EX_NODGROUP	3


/*
 *  Macros
 *	stdmsg(r,l,s,t)	    Write a message in standard format 
 *				r	Recoverability flag
 *				l	Label
 *				s	Severity
 *				t	Tag
 */

#define	stdmsg(r,l,s,t)	(void) fmtmsg(MM_PRINT|MM_UTIL|r,l,s,t,MM_NULLACT,MM_NULLTAG)

/*
 *  Global Variables
 */


/*
 *  Static Variables
 *
 *	lbl	Buffer for the message label
 */

static	char	lbl[MM_MXLABELLN+1];
static	char	msg[MM_MXTXTLN+1];

/*
 *  listdgrp <dgroup>
 *
 *	List the devices that belong to the device group <dgroup>.
 *	It writes the list to the standard output file (stdout)
 *	in a new-line list.
 *
 *  Returns:
 *	0	Ok
 *	1	Syntax or other error
 *	2	Device table can't be opened
 *	3	Device group doesn't exist
 */

int
main(int argc, char **argv)
{

	/* 
	 *  Automatic data
	 */

	char	      **devices;	/* List of devices in the group */
	char	      **pp;		/* Running pointer to device names */
	char	       *cmdname;	/* Simple command name */
	char	       *dgrptab;	/* The device-group table name */
	char	       *dgroup;		/* Device group to list */
	int		exitcode;	/* Value to return to the caller */
	int		sev;		/* Message severity */
	int		optchar;	/* Option char (from getopt()) */
	int		usageerr;	/* TRUE if syntax error on command */


	/* Build the message label from the (simple) command name */
	if ((cmdname = strrchr(argv[0], '/')) != (char *) NULL) cmdname++;
	else cmdname = argv[0];
	(void) strlcat(strcpy(lbl, "UX:"), cmdname, sizeof(lbl));

	/* Only write the text component of a message (this goes away in SVR4.1) */
	(void) putenv("MSGVERB=text");

	/* 
	 *  Parse the command line:
	 *	- Options
	 *	- Device group to display
	 */

	/* 
	 *  Extract options from the command line 
	 */

	/* Initializations */
	usageerr = FALSE;	/* No errors on the command line (yet) */

	/* 
	 *  Loop until all of the command line options have been parced 
	 *  (and don't let getopt() write messages) 
	 */

	opterr = FALSE;	
	while ((optchar = getopt(argc, argv, "")) != EOF) switch (optchar) {

	/* Default case -- command usage error */
	case '?':
	default:
	    usageerr = TRUE;
	    break;
	}

	/* Check the argument count and extract the device group name */
	if (usageerr || (optind != argc-1)) usageerr = TRUE;
	else dgroup = argv[optind];

	/* If there is a usage error, write an appropriate message and exit */
	if (usageerr) {
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, M_USAGE);
	    exit(EX_ERROR);
	}

	/* Open the device-group file (if there's one to be opened) */
	if (!_opendgrptab("r")) {
	    if (dgrptab = _dgrptabpath()) {
		(void) snprintf(msg, sizeof(msg), M_DGRPTAB, dgrptab);
		exitcode = EX_NODGRPTAB;
		sev = MM_ERROR;
	    } else {
		(void) sprintf(msg, M_ERROR, errno);
		exitcode = EX_ERROR;
		sev = MM_HALT;
	    }
	    stdmsg(MM_NRECOV, lbl, sev, msg);
	    exit(exitcode);
	}


	/*
	 * Get the list of devices associated with the device group.
	 * If we get one, write the list to the standard output.
	 * Otherwise, write an appropriate error message
	 */

	exitcode = EX_OK;
	if (devices = listdgrp(dgroup)) {
	    for (pp = devices ; *pp ; pp++) (void) puts(*pp);
	}
	else {
	    if (errno == EINVAL) {
		(void) snprintf(msg, sizeof(msg), M_NODGRP, dgroup);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
		exitcode = EX_NODGROUP;
	    }
	    else {
		(void) sprintf(msg, M_ERROR, errno);
		stdmsg(MM_NRECOV, lbl, MM_HALT, msg);
		exitcode = EX_ERROR;
	    }
	}

	/* Finished (now wasn't that special?) */
	return(exitcode);
}
