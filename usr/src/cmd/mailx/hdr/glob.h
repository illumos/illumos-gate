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


/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * A bunch of global variable declarations lie herein.
 * def.h must be included first.
 */

extern int		Fflag;		/* -F option (followup) */
extern int		Hflag;		/* print headers and exit */
extern char		*Tflag;		/* -T temp file for netnews */
extern int		UnUUCP;		/* -U flag */
extern char		**altnames;	/* List of alternate names for user */
extern int		askme;		/* ???? */
extern int		baud;		/* Output baud rate */
extern char		*bflag;		/* Bcc given from non tty */
extern char		*binmsg;	/* Message: content unprintable */
extern char		*cflag;		/* Cc given from non tty */
extern const struct cmd	cmdtab[];	/* ???? */
extern int		cond;		/* Current state of conditional exc. */
extern NODE		*curptr;	/* ???? */
extern int		debug;		/* Debug flag set */
extern char		domain[];	/* ???? */
extern struct message	*dot;		/* Pointer to current message */
extern int		edit;		/* Indicates editing a file */
extern char		*editfile;	/* Name of file being edited */
extern int		exitflg;	/* -e for mail test */
extern NODE		*fplist;	/* ???? */
extern struct grouphead	*groups[];	/* Pointer to active groups */
extern struct hdr	header[];	/* Known header types */
extern int		hflag;		/* Sequence number for network -h */
extern char		homedir[];	/* Name of home directory */
extern char		host[];		/* ???? */
extern struct ignore	*ignore[];	/* Pointer to ignored fields */
extern int		image;		/* File descriptor for image of msg */
extern FILE		*input;		/* Current command input file */
extern int		intty;		/* True if standard input a tty */
extern int		issysmbox;	/* mailname is a system mailbox */
extern FILE		*itf;		/* Input temp file buffer */
extern int		lexnumber;	/* Number of TNUMBER from scan() */
extern char		lexstring[];	/* String from TSTRING, scan() */
extern int		loading;	/* Loading user definitions */
extern char		*lockname;	/* named used for locking in /var/mail */
extern char		*maildir;	/* directory for mail files */
extern char		mailname[];	/* Name of /var/mail system mailbox */
extern off_t		mailsize;	/* Size of system mailbox */
extern int		maxfiles;	/* Maximum number of open files */
extern struct message	*message;	/* The actual message structure */
extern char		*metanet;	/* ???? */
extern int		msgCount;	/* Count of messages read in */
extern gid_t		myegid;		/* User's effective gid */
extern uid_t		myeuid;		/* User's effective uid */
extern char		myname[];	/* My login id */
extern pid_t		mypid;		/* Current process id */
extern gid_t		myrgid;		/* User's real gid */
extern uid_t		myruid;		/* User's real uid */
extern int		newsflg;	/* -I option for netnews */
extern char		noheader;	/* Suprress initial header listing */
extern int		noreset;	/* String resets suspended */
extern char		nosrc;		/* Don't source /etc/mail/mailx.rc */
extern int		nretained;	/* Number of retained fields */
extern int		numberstack[];	/* Stack of regretted numbers */
extern char		origname[];	/* Original name of mail file */
extern FILE		*otf;		/* Output temp file buffer */
extern int		outtty;		/* True if standard output a tty */
extern FILE		*pipef;		/* Pipe file we have opened */
extern char		*progname;	/* program name (argv[0]) */
extern char		*prompt;	/* prompt string */
extern int		rcvmode;	/* True if receiving mail */
extern int		readonly;	/* Will be unable to rewrite file */
extern int		regretp;	/* Pointer to TOS of regret tokens */
extern int		regretstack[];	/* Stack of regretted tokens */
extern struct ignore	*retain[HSHSIZE];/* Pointer to retained fields */
extern char		*rflag;		/* -r address for network */
extern int		rmail;		/* Being called as rmail */
extern int		sawcom;		/* Set after first command */
extern int		selfsent;	/* User sent self something */
extern int		senderr;	/* An error while checking */
extern int		rpterr;		/* An error msg was sent to stderr */
extern char		*sflag;		/* Subject given from non tty */
extern int		sourcing;	/* Currently reading variant file */
extern int		space;		/* Current maximum number of messages */
extern jmp_buf		srbuf;		/* ???? */
extern struct strings	stringdope[];	/* pointer for the salloc routines */
extern char		*stringstack[];	/* Stack of regretted strings */
extern char		tempEdit[];	/* ???? */
extern char		tempMail[];	/* ???? */
extern char		tempMesg[];	/* ???? */
extern char		tempQuit[];	/* ???? */
extern char		tempResid[];	/* temp file in :saved */
extern char		tempZedit[];	/* ???? */
extern int		tflag;		/* Read headers from text */
extern uid_t		uid;		/* The invoker's user id */
extern struct utimbuf	*utimep;	/* ???? */
extern struct var	*variables[];	/* Pointer to active var list */
extern const char *const version;	/* ???? */
extern int		receipt_flg;	/* Flag for return receipt */

/*
 * Standard external variables from the C library.
 */
extern char		*optarg;
extern int		optind;
