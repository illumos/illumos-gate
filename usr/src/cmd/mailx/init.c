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
 *
 * All global externs are declared in def.h. All variables are initialized
 * here!
 *
 * !!!!!IF YOU CHANGE (OR ADD) IT HERE, DO IT THERE ALSO !!!!!!!!
 *
 */

#include	"def.h"
#include	<grp.h>
#include	<pwd.h>
#include	<sys/utsname.h>

int	Fflag = 0;			/* -F option (followup) */
int	Hflag = 0;			/* print headers and exit */
char	*Tflag;				/* -T temp file for netnews */
int	UnUUCP = 0;			/* -U flag */
char	**altnames;			/* List of alternate names for user */
int	askme;
int	baud;				/* Output baud rate */
char	*bflag;				/* Bcc given from non tty */
char	*binmsg = "*** Message content is not printable: pipe to command or save to a file ***";
char	*cflag;				/* Cc given from non tty */
int	cond;				/* Current state of conditional exc. */
NODE	*curptr = NOFP;
int	debug;				/* Debug flag set */
struct	message	*dot;			/* Pointer to current message */
int	edit;				/* Indicates editing a file */
char	*editfile;			/* Name of file being edited */
int	exitflg = 0;			/* -e for mail test */
NODE	*fplist = NOFP;
struct	grouphead	*groups[HSHSIZE];/* Pointer to active groups */
int	hflag;				/* Sequence number for network -h */
char	homedir[PATHSIZE];		/* Name of home directory */
struct	ignore		*ignore[HSHSIZE];/* Pointer to ignored fields */
int	image;				/* File descriptor for image of msg */
FILE	*input;				/* Current command input file */
int	intty;				/* True if standard input a tty */
int	issysmbox;			/* mailname is a system mailbox */
FILE	*itf;				/* Input temp file buffer */
int	lexnumber;			/* Number of TNUMBER from scan() */
char	lexstring[STRINGLEN];		/* String from TSTRING, scan() */
int	loading;			/* Loading user definitions */
char	*lockname;			/* named used for locking in /var/mail */
#ifdef	USR_SPOOL_MAIL
char	*maildir = "/usr/spool/mail/";	/* directory for mail files */
#else
# ifdef preSVr4
char	*maildir = "/usr/mail/";	/* directory for mail files */
# else
char	*maildir = "/var/mail/";	/* directory for mail files */
# endif
#endif
char	mailname[PATHSIZE];		/* Name of /var/mail system mailbox */
off_t	mailsize;			/* Size of system mailbox */
int	maxfiles;			/* Maximum number of open files */
struct	message	*message;		/* The actual message structure */
int	msgCount;			/* Count of messages read in */
gid_t	myegid;
uid_t	myeuid;
char	myname[PATHSIZE];		/* My login id */
pid_t	mypid;				/* Current process id */
gid_t	myrgid;
uid_t	myruid;
int	newsflg = 0;			/* -I option for netnews */
char	noheader;			/* Suprress initial header listing */
int	noreset;			/* String resets suspended */
char	nosrc;				/* Don't source /etc/mail/mailx.rc */
int	nretained;			/* Number of retained fields */
int	numberstack[REGDEP];		/* Stack of regretted numbers */
char	origname[PATHSIZE];		/* Name of mailfile before expansion */
FILE	*otf;				/* Output temp file buffer */
int	outtty;				/* True if standard output a tty */
FILE	*pipef;				/* Pipe file we have opened */
char	*progname;			/* program name (argv[0]) */
char	*prompt = NOSTR;		/* prompt string */
int	rcvmode;			/* True if receiving mail */
int	readonly;			/* Will be unable to rewrite file */
int	regretp;			/* Pointer to TOS of regret tokens */
int	regretstack[REGDEP];		/* Stack of regretted tokens */
struct	ignore		*retain[HSHSIZE];/* Pointer to retained fields */
char	*rflag;				/* -r address for network */
int	rmail;				/* Being called as rmail */
int	sawcom;				/* Set after first command */
int	selfsent;			/* User sent self something */
int	senderr;			/* An error while checking */
int	rpterr;				/* An error msg was sent to stderr */
char	*sflag;				/* Subject given from non tty */
int	sourcing;			/* Currently reading variant file */
int	space;				/* Current maximum number of messages */
jmp_buf	srbuf;
int	tflag;				/* Read headers from text */
/*
 * The pointers for the string allocation routines,
 * there are NSPACE independent areas.
 * The first holds STRINGSIZE bytes, the next
 * twice as much, and so on.
 */
struct strings stringdope[NSPACE];
char	*stringstack[REGDEP];		/* Stack of regretted strings */
char	tempEdit[TMPSIZ];
char	tempMail[TMPSIZ];
char	tempMesg[TMPSIZ];
char	tempQuit[TMPSIZ];
char	tempResid[PATHSIZE];		/* temp file in :saved */
char	tempZedit[TMPSIZ];
uid_t	uid;				/* The invoker's user id */
static struct utimbuf	utimeb;
struct utimbuf	*utimep = &utimeb;
struct	var	*variables[HSHSIZE];	/* Pointer to active var list */
int	receipt_flg = 0;		/* Flag for return receipt */
