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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/


#define		FALSE		0
#define		TRUE		1

#define		SUCCESS		0
#define		FAILURE		-1	/* initialize device failed	*/
#define		LOCKED		-2	/* device is locked by others 	*/
#define		SESSION		-3	/* device has active session 	*/
#define		UNACCESS	-4	/* device not accessible	*/


#define		ACTIVE		1
#define		FINISHED	0

/*
 *	flags to indicate the field of /etc/ttydefs
 *	Note: order is important because it corresponds to
 *	      the order of fields in the file
 */
#define		T_TTYLABEL	1
#define		T_IFLAGS	2
#define		T_FFLAGS	3
#define		T_AUTOBAUD	4
#define		T_NEXTLABEL	5

/*
 *	flags to indicate the field of pmtab
 *	Note: order is important because it corresponds to
 *	      the order of fields in the file
 */
#define		P_TAG		1
#define		P_FLAGS		2
#define		P_IDENTITY	3
#define		P_RES1		4
#define		P_RES2		5
#define		P_RES3		6
#define		P_DEVICE	7
#define		P_TTYFLAGS	8
#define		P_COUNT		9
#define		P_SERVER	10
#define		P_TIMEOUT	11
#define		P_TTYLABEL	12
#define		P_MODULES	13
#define		P_PROMPT	14
#define		P_DMSG		15
#define		P_TERMTYPE	16
#define		P_SOFTCAR	17

/*
 *	termio mode
 */
#define		RAW	0x1	/* raw mode		*/
#define		CANON	0x2	/* canonical mode	*/

/*
 *	return value for peeking input data
 */
#define		GOODNAME	1
#define		NONAME		0
#define		BADSPEED	-1

#define	MAXID		15	/* Maximum length the "g_id" and "g_nextid" \
				 * strings can take.  Longer ones will be \
				 * truncated. \
				 */

#define	MAXARGS		64	/* Maximum number of arguments that can be \
				 * passed to "login" \
				 */

#define	SPAWN_LIMIT	15	/* respawn allowed within SPAWN_INTERVAL */
#define	SPAWN_INTERVAL	(2*60)

#define		UUCP		"uucp"	/* owner of bi-directional devices */
#define		TTY		"tty"	/* group name of all devices 	   */
#define		ROOTUID		0		/* root uid		*/

#define	LOGDIR		"/var/saf/"		/* home dir of all saf log */
#define	LOGFILE		"log"			/* log file 		*/
#define	OLOGFILE	"o.log"			/* saved log file	*/
#define	TLOGFILE	"t.log"			/* temp log file	*/
#define	PIDFILE		"_pid"			/* pid file 		*/
#define	PMTABFILE	"_pmtab"		/* pmtab file 		*/
#define	PMPIPE		"_pmpipe"		/* pmpipe 		*/
#define	SACPIPE		"../_sacpipe"		/* sacpipe 		*/
#define	TTYDEFS		"/etc/ttydefs"		/* ttydefs file 	*/
#define	CONSOLE		"/dev/syscon"		/* /dev/console		*/

#ifdef	DEBUG
#define	DBGFILE		"debug"			/* debug file 		*/
#define	EX_DBG		"/var/saf/tm_debug"
					/* debug file for ttymon express*/
#endif

#ifdef	SYS_NAME
#define	ISSUEFILE	"/etc/issue"		/*file to print before prompt */
#endif

#define	PMTAB_VERS	1		/* pmtab version number		*/
#define	TTYDEFS_VERS	1		/* /etc/ttydefs version number	*/

#define	MAXDEFS		100		/* max entries Gdef table can have */

/*
 * - ttymon reserves 7 fd for the following use:
 * - pid, log, pmpipe, sacpipe, pmtab, PCpipe[0], PCpipe[1].
 * - if DEBUG is on, reserve one more for debug file
 * - fd for each file
 *	pid		0
 *	sacpipe		1
 *	pmpipe		2
 *	log		3
 *	PCpipe[0]	4
 *	PCpipe[1]	5
 *	debug		6
 *	pmtab		floating, any fd will do
 */
#ifdef	DEBUG
#define	FILE_RESERVED	8
#else
#define	FILE_RESERVED	7
#endif

#define	TM_MAXCLASS	1	/* maxclass of SAC msg ttymon understands */

/*
 * flag value for strcheck()
 */
#define	NUM		0
#define	ALNUM		1

#define	ALARMTIME	60
