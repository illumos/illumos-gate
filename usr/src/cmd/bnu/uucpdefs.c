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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

/* Configurable parameters */

GLOBAL	char	_ProtoCfg[40]="";	/* protocol string from Config file */

/* Non-configurable parameters */

GLOBAL	int	Ifn, Ofn;
GLOBAL	int 	Sgrades = FALSE;
GLOBAL	int	Debug = 0;
GLOBAL	int	SizeCheck = 0;		/* Ulimit checking supported flag */
GLOBAL	long	RemUlimit = 0;		/* Ulimit of remote if supported */
GLOBAL	int	Restart = 0;		/* checkpoint restart supported flag */
GLOBAL	uid_t	Uid, Euid;		/* user-id and effective-uid */
GLOBAL	long	Ulimit;
GLOBAL	mode_t	Dev_mode;		/* save device mode here */
GLOBAL	char	Progname[NAMESIZE];
GLOBAL	char	Pchar;
GLOBAL	char	Grade = 'Z';
GLOBAL	char	Rmtname[MAXFULLNAME];
GLOBAL	char	JobGrade[MAXBASENAME+1] = { NULLCHAR };
GLOBAL	char	RemSpool[MAXFULLNAME];	/* spool subdirectory for remote system */
GLOBAL	char	User[MAXFULLNAME];
GLOBAL	char	Uucp[NAMESIZE];
GLOBAL	char	Loginuser[NAMESIZE];
GLOBAL	char	Myname[MAXBASENAME+1];
GLOBAL	char	Wrkdir[MAXFULLNAME];
GLOBAL	char	Logfile[MAXFULLNAME];
GLOBAL	char	*Spool = SPOOL;
GLOBAL	char	*Pubdir = PUBDIR;
GLOBAL	char	**Env;
GLOBAL	char	*Shchar = ";&|<>^`\\()'\"{}\t\n ";


GLOBAL	long	Retrytime = 0;		/* default is to use exponential backoff */
GLOBAL	struct	nstat Nstat;
GLOBAL	char	Dc[50];			/* line name				*/
GLOBAL	int	Seqn;			/* sequence #				*/
GLOBAL	int	Role;
GLOBAL	char	*Bnptr;			/* used when BASENAME macro is expanded */
GLOBAL	char	Jobid[NAMESIZE] = "";	/* Jobid of current C. file */
GLOBAL	int	Uerror;			/* global error code */

GLOBAL	void	(*genbrk)();

GLOBAL	int	Verbose = 0;	/* only for cu and ct to change */

/* used for READANY and READSOME macros */
GLOBAL	struct stat __s_;

/* messages */
GLOBAL char	*Ct_OPEN =	"CAN'T OPEN";
GLOBAL char	*Ct_WRITE =	"CAN'T WRITE";
GLOBAL char	*Ct_READ =	"CAN'T READ";
GLOBAL char	*Ct_CREATE =	"CAN'T CREATE";
GLOBAL char	*Ct_ALLOCATE =	"CAN'T ALLOCATE";
GLOBAL char	*Ct_LOCK =	"CAN'T LOCK";
GLOBAL char	*Ct_STAT =	"CAN'T STAT";
GLOBAL char	*Ct_CHOWN =	"CAN'T CHOWN";
GLOBAL char	*Ct_CHMOD =	"CAN'T CHMOD";
GLOBAL char	*Ct_LINK =	"CAN'T LINK";
GLOBAL char	*Ct_CHDIR =	"CAN'T CHDIR";
GLOBAL char	*Ct_UNLINK =	"CAN'T UNLINK";
GLOBAL char	*Wr_ROLE =	"WRONG ROLE";
GLOBAL char	*Ct_CORRUPT =	"CAN'T MOVE TO CORRUPTDIR";
GLOBAL char	*Ct_CLOSE =	"CAN'T CLOSE";
GLOBAL char	*Ct_FORK =	"CAN'T FORK";
GLOBAL char	*Fl_EXISTS =	"FILE EXISTS";
GLOBAL char	*Ct_BADOWN =	"BAD OWNER/PERMS";

GLOBAL	char *UerrorText[] = {
  /* SS_OK			0 */ "SUCCESSFUL",
  /* SS_NO_DEVICE		1 */ "NO DEVICES AVAILABLE",
  /* SS_TIME_WRONG		2 */ "WRONG TIME TO CALL",
  /* SS_INPROGRESS		3 */ "TALKING",
  /* SS_CONVERSATION		4 */ "CONVERSATION FAILED",
  /* SS_SEQBAD			5 */ "BAD SEQUENCE CHECK",
  /* SS_LOGIN_FAILED		6 */ "LOGIN FAILED",
  /* SS_DIAL_FAILED		7 */ "DIAL FAILED",
  /* SS_BAD_LOG_MCH		8 */ "BAD LOGIN/MACHINE COMBINATION",
  /* SS_LOCKED_DEVICE		9 */ "DEVICE LOCKED",
  /* SS_ASSERT_ERROR		10 */ "ASSERT ERROR",
  /* SS_BADSYSTEM		11 */ "SYSTEM NOT IN Systems FILE",
  /* SS_CANT_ACCESS_DEVICE	12 */ "CAN'T ACCESS DEVICE",
  /* SS_DEVICE_FAILED		13 */ "DEVICE FAILED",
  /* SS_WRONG_MCH		14 */ "WRONG MACHINE NAME",
  /* SS_CALLBACK		15 */ "CALLBACK REQUIRED",
  /* SS_RLOCKED			16 */ "REMOTE HAS A LCK FILE FOR ME",
  /* SS_RUNKNOWN		17 */ "REMOTE DOES NOT KNOW ME",
  /* SS_RLOGIN			18 */ "REMOTE REJECT AFTER LOGIN",
  /* SS_UNKNOWN_RESPONSE	19 */ "REMOTE REJECT, UNKNOWN MESSAGE",
  /* SS_STARTUP			20 */ "STARTUP FAILED",
  /* SS_CHAT_FAILED		21 */ "CALLER SCRIPT FAILED",
  /* SS_CALLBACK_LOOP		22 */ "CALLBACK REQUIRED - LOOP",
};
