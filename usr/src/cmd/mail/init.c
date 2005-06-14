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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

 /*
  * All global externs defined in mail.h. All variables are initialized
  * here!
  *
  * !!!!!IF YOU CHANGE (OR ADD) IT HERE, DO IT THERE ALSO !!!!!!!!
  *
  */
#include	"mail.h"

int		ac;		/* argument list count */
char		**av;		/* argument list */
int		affbytecnt;     /* Total bytes of Auto-Fwd. info in msg. */
int		affcnt;		/* Number of Auto-Fwd.-From: lines in msg. */
int		Daffbytecnt;    /* Hold affbytecnt when sending Delivery Notification */
int		Daffcnt;	/* Hold affcnt when sending Delivery Notification */
char		binmsg[] = "*** Message content is not printable: delete, write or save it to a file ***";
int		changed;	/* > 0 says mailfile has changed */
char		datestring[60];	/* Today's date and time */
char		dbgfname[20];
FILE		*dbgfp;
char		dead[] = "/dead.letter";	/* name of dead.letter */
int		debug;	/* Controls debugging level. 0 ==> no debugging */
int		delflg = 1;
int		dflag = 0;	/* 1 says returning unsendable mail */
char		*errlist[]= {
		"",
		"Unknown system",
		"Problem with mailfile",
		"Space problem",
		"Unable to forward mail, check permissions and group",
		"Syntax error",
		"Forwarding loop",
		"Invalid sender",
		"Invalid recipient",
		"Too many From lines",
		"Invalid permissions",
		"Cannot open mbox",
		"Temporary file problem",
		"Cannot create dead.letter",
		"Unbounded forwarding",
		"Cannot create lock file",
		"No group id of 'mail'",
		"Problem allocating memory",
		"Could not fork",
		"Cannot pipe",
		"Must be owner to modify mailfile",
		"Permission denied by /etc/mail/mailsurr file",
		"Surrogate command failed"
};
int		error = 0;	/* Local value for error */
char		*failsafe;	/* $FAILSAFE */
int		file_size;
int		flge = 0;	/* 1 ==> 'e' option specified */
int		flgE = 0;	/* 1 ==> 'E' option specified */
int		flgF = 0;	/* 1 ==> Installing/Removing  Forwarding */
int		flgf = 0;	/* 1 ==> 'f' option specified */
int		flgh = 0;	/* 1 ==> 'h' option specified */
int		flgm;
int		flgp = 0;	/* 1 ==> 'p' option specified */
int		flgP = 0;	/* 1 ==> 'P' option specified */
int		flgr = 0;	/* 1 ==> 'r' option -- print in fifo order */
int		flgt = 0;	/* 1 ==> 't' option -- add To: line to letter */
int		flgT = 0;	/* 1 ==> 'T' option specified */
int		flgw = 0;	/* 1 ==> 'w' option specified */
int		fnuhdrtype = 0;	/* type of first non-UNIX header line */
char		forwmsg[] = " forwarded by %s\n";
char		fromS[1024];	/* stored here by sendmail for sendsurg */
char		fromU[1024];	/* stored here by sendmail for sendsurg */
char		frwlmsg[] = "     %s: Forwarding loop detected in %s's mailfile.\n";
char		frwrd[] = "Forward to ";	/* forwarding sentinel */
char		fwdFrom[1024];
int		goerr = 0;	/* counts parsing errors */
struct group	*grpptr;	/* pointer to struct group */
struct hdrlines	hdrlines[H_CONT];
/* Default_display indicates whether to display this header line to the TTY */
/* when in default mode. Can be overridden via 'P' command at ? prompt */
struct hdr	header[] = {
		"",				FALSE,
		"Auto-Forward-Count:",		FALSE,
		"Auto-Forwarded-From:",		FALSE,
		"Content-Length:",		TRUE,
		"Content-Type:",		FALSE,
		"Date:",			TRUE,
		"Default-Options:",		FALSE,
		"End-of-Header:",		FALSE,
		"From ",			TRUE,
		">From ",			TRUE,
		"From:",			TRUE,
		"MIME-Version:",		FALSE,
		"MTS-Message-ID:",		FALSE,
		"Message-Type:",		FALSE,
		"Message-Version:",		FALSE,
		"Message-Service:",		TRUE,
		"Received:",			FALSE,
		"Report-Version:",		FALSE,
		"Subject:",			TRUE,
		"To:",				TRUE,
		">To:",				FALSE,
		"Transport-Options:",		FALSE,
		"UA-Content-ID:",		FALSE,

		/*Dummy place holders for H_DAFWDFROM,*/
		/*H_DTCOPY and H_RECEIVED. Should */
		/* match above first...*/
		"Hold-Auto-Forwarded-From:",	FALSE,
		"Hold->To:",			FALSE,
		"Hold-Received:",		FALSE,
		"Continue:",			FALSE,
		"Name-Value:",			FALSE,
};
char		*help[] = {
		"?\t\tprint this help message\n",
		"#\t\tdisplay message number #\n",
		"-\t\tprint previous\n",
		"+\t\tnext (no delete)\n",
		"! cmd\t\texecute cmd\n",
		"<CR>\t\tnext (no delete)\n",
		"a\t\tposition at and read newly arrived mail\n",
		"d [#]\t\tdelete message # (default current message)\n",
		"dp\t\tdelete current message and print the next\n",
		"dq\t\tdelete current message and exit\n",
		"h a\t\tdisplay all headers\n",
		"h d\t\tdisplay headers of letters scheduled for deletion\n",
		"h [#]\t\tdisplay headers around # (default current message)\n",
		"m user  \tmail (and delete) current message to user\n",
		"n\t\tnext (no delete)\n",
		"p\t\tprint (override any warnings of binary content)\n",
		"P\t\toverride default 'brief' mode and display ALL header lines\n",
		"q, ^D\t\tquit\n",
		"r [args]\treply to (and delete) current letter via mail [args]\n",
		"s [files]\tsave (and delete) current message (default mbox)\n",
		"u [#]\t\tundelete message # (default current message)\n",
		"w [files]\tsave (and delete) current message without header\n",
		"x\t\texit without changing mail\n",
		"y [files]\tsave (and delete) current message (default mbox)\n",
		0
};
char		*hmbox;		/* pointer to $HOME/mbox */
char		*hmdead;	/* pointer to $HOME/dead.letter */
char		*home;		/* pointer to $HOME */
time_t		iop;
int		interactive = 0;	/* 1 says user is interactive */
int		ismail = TRUE;		/* default to program=mail */
int             deliverflag = FALSE;    /* -d flag, skip sendmail 
					 * deliver directly to mailbox
					 */
int             fromflag = FALSE;   /* -f from_user, set a user
					 * when going into a mailbox
					 */
int		keepdbgfile;
struct let	let[MAXLET];
char		*lettmp;		/* pointer to tmp filename */
char		lfil[MAXFILENAME];
char		line[LSIZE];	/* holds a line of a letter in many places */
char		*mailfile;	/* pointer to mailfile */
char		mailcnfg[] = MAILCNFG;	/* configuration file */
char		maildir[] = MAILDIR;	/* directory for mail files */
gid_t		mailgrp;	/* numeric id of group 'mail' */
char		mailsave[] = SAVEDIR;	/* dir for save files */
char		*mailsurr = MAILSURR;	/* surrogate file name */
FILE		*malf;		/* File pointer for mailfile */
int		maxerr = 0;	/* largest value of error */
char		mbox[] = "/mbox";	/* name for mbox */
uid_t		mf_uid;		/* uid of users mailfile */
gid_t		mf_gid;		/* gid of users mailfile */
char		*msgtype;
char		my_name[1024];	/* user's name who invoked this command */
char		from_user[1024];	/* user's name specified w/ -f when sending */
uid_t		my_euid;	/* user's euid */
gid_t		my_egid;	/* user's egid */
uid_t		my_uid;		/* user's uid */
gid_t		my_gid;		/* user's gid */
int		nlet	= 0;	/* current number of letters in mailfile */
int		onlet	= 0;	/* number of letters in mailfile at startup*/
int		optcnt = 0;	/* Number of options specified */
int		orig_aff = 0;	/* orig. msg. contained H_AFWDFROM lines */
int		orig_dbglvl;	/* argument to -x invocation option */
int		orig_rcv = 0;	/* orig. msg. contained H_RECEIVED lines */
int		orig_tcopy = 0;	/* orig. msg. contained H_TCOPY lines */
struct passwd	*pwd;		/* holds passwd entry for this user */
int		pflg = 0;	/* binary message display override flag */
int		Pflg = 0;	/* Selective display flag; 1 ==> display all */
char		*program;	/* program name */
int		rcvbytecnt;     /* Total bytes of Received: info in msg. */
int		Drcvbytecnt;    /* Hold rcvbytecnt when sending Delivery Notification */
char		*recipname;		/* full recipient name/address */
int		replying = 0;	/* 1 says we are replying to a letter */
char		RFC822datestring[60];/* Date in RFC822 date format */
char		Rpath[1024];	/* return path to sender of message */
char		rmtmsg[] =	" remote from %s\n";
char		rtrnmsg[] =	"***** UNDELIVERABLE MAIL sent to %s, being returned by %s *****\n";
int		sav_errno;
char		savefile[MAXFILENAME];	/* holds filename of save file */
void		(*saveint)();
/* Any header line prefixes listed here WILL be displayed in default mode */
/* If it's not here, it won't be shown. Can be overridden via 'P' command */
/* at ? prompt */
char		*seldisp[] = {
		"Cc:",
		"Bcc:",
		"Paper-",
		"Phone:",
		"Message-",
		"Original-",
		"Confirming-",
		"Delivered-",
		"Deliverable-",
		"Not-",
		"En-Route-To:",
		0
};
int		sending;	/* TRUE==>sending mail; FALSE==>printing mail */
char		m_sendto[1024];
jmp_buf		sjbuf;
int		surg_rc = 0;	/* exit code of surrogate command */
int		surr_len = 0;
char		*SURRcmdstr = (char *)NULL; /* save in case of FAILURE */
FILE		*SURRerrfile;	/* stderr from surrogate in case of FAILURE */
char		*thissys;	/* Holds name of the system we are on */
FILE		*tmpf;		/* file pointer for temporary files */
mode_t		umsave;
struct		utsname utsn;
static struct utimbuf	utims;
struct utimbuf	*utimep = &utims;
char		uval[1024];

int init()
{
	utims.actime = utims.modtime = -1;
	return (xsetenv(mailcnfg));
}
