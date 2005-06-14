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

#include "uucp.h"

/* Configurable parameters */

GLOBAL	char	_ProtoCfg[40];		/* protocol string from Config file */

/* Non-configurable parameters */

GLOBAL	int	Debug;
GLOBAL	uid_t	Uid, Euid;		/* user-id and effective-uid */
GLOBAL	mode_t	Dev_mode;		/* save device mode here */
GLOBAL	char	Progname[NAMESIZE];
GLOBAL	const char	*Spool = SPOOL;
GLOBAL	const char	*Pubdir = PUBDIR;

GLOBAL	long	Retrytime;
GLOBAL	char	Dc[50];			/* line name			*/
GLOBAL	char	*Bnptr;			/* used when BASENAME macro is expanded */
GLOBAL	int	Uerror;			/* global error code */

GLOBAL	void	(*genbrk)();

GLOBAL	int	Verbose;	/* only for cu and ct to change */

/* messages */
GLOBAL const char	Ct_OPEN[] =	"CAN'T OPEN";
GLOBAL const char	Ct_WRITE[] =	"CAN'T WRITE";
GLOBAL const char	Ct_READ[] =	"CAN'T READ";
GLOBAL const char	Ct_CREATE[] =	"CAN'T CREATE";
GLOBAL const char	Ct_ALLOCATE[] =	"CAN'T ALLOCATE";
GLOBAL const char	Ct_LOCK[] =	"CAN'T LOCK";
GLOBAL const char	Ct_STAT[] =	"CAN'T STAT";
GLOBAL const char	Ct_CHOWN[] =	"CAN'T CHOWN";
GLOBAL const char	Ct_CHMOD[] =	"CAN'T CHMOD";
GLOBAL const char	Ct_LINK[] =	"CAN'T LINK";
GLOBAL const char	Ct_CHDIR[] =	"CAN'T CHDIR";
GLOBAL const char	Ct_UNLINK[] =	"CAN'T UNLINK";
GLOBAL const char	Wr_ROLE[] =	"WRONG ROLE";
GLOBAL const char	Ct_CORRUPT[] =	"CAN'T MOVE TO CORRUPTDIR";
GLOBAL const char	Ct_CLOSE[] =	"CAN'T CLOSE";
GLOBAL const char	Ct_FORK[] =	"CAN'T FORK";
GLOBAL const char	Fl_EXISTS[] =	"FILE EXISTS";
GLOBAL const char	Ct_BADOWN[] =	"BAD OWNER/PERMS";

GLOBAL char *UerrorText[] = { 
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
