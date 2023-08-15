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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7.1.1	*/

/*
 * lserror.h:	Network listener error exit codes.
 *		The codes in the defines index the table below to
 *		give the actual exit code. (The table is in lsdata.c)
 *
 *		An exit code of 1 means initialization problem
 *			before logging is available
 *
 *		An exit code of 0 means the listener got past
 *		it's initialization and made itself independent
 *		of it's parent.
 *
 *		Not all of the errors listed below will cause error exits.
 */

#ifndef lserror_h	/* avoid multiple inclusions of lserror.h */
#define lserror_h

/*
 * parameters to error/exit routines
 */

#define EXIT		0x80		/* error routines will exit	*/
#define NOCORE		0x40
#define NORMAL		0x20		/* exit is a 'normal' exit	*/
#define NO_MSG		0x10		/* message already logged	*/
#define CONTINUE	0


#define E_CMDLINE	1		/* cmd line arguments		*/
#define E_CDHOME	2		/* can't chdir to home dir	*/
#define E_CREAT		3		/* can't create a file		*/
#define E_ACCESS	4		/* can't access/exec file	*/
#define E_OPEN		5		/* can't open a file		*/
#define E_LSFORK	6		/* can't fork myself		*/
#define E_PIDWRITE	7		/* error writing process id file */

#define	E_FD1OPEN	8		/* fd 1 net device open		*/
#define	E_FD2OPEN	9		/* fd 2 net device open		*/
#define	E_FD3OPEN	10		/* fd 3 net device open		*/
#define E_UNAME		11		/* uname system call		*/
#define	E_SIGTERM	12		/* signal SIGTERM caught	*/
/*
 * E_INCONSISTENT should only be seen by developers/integrators/etc.
 * Cmd line/data base problem. Hopefully only a debug error.
 * In the listener, in check_files(), where cmd line args
 * and the data base file entries are merged, a pathname
 * of a required file (e.g.: pidfile, logfile) was NULL.
 * Make sure the data base/cmd line has all the required entries.
 */

#define E_INCONSISTENT	13


/*
 * TLI errors.
 *	E_T_ALLOC: probably couldn't malloc() (out of memory?)
 *	E_T_BIND:  Couldn't bind nodename or netnodename!!!
 *	E_BIND_REQ: TLI didn't bind the requested name!!!
 *		    (someone else on the machine/net took it?)
 *	E_T_FREE:  t_free failed -- listener/tli bug or reboot
 *	E_IN_TLI:  System call failed in a TLI routine.
 *
 */

#define E_T_ALLOC	14		/* TLI: t_alloc failed		*/
#define	E_T_BIND	15		/* TLI couldn't bind		*/
#define	E_BIND_REQ	16		/* tli bound a different name!	*/
#define E_T_FREE	17		/* tli couldn't free memory?	*/
#define E_IN_TLI	18		/* system call failed in tli	*/
#define E_T_LISTEN	19		/* t_listen error		*/
#define E_T_ACCEPT	20		/* t_accept			*/
#define	E_T_SNDDIS	21		/* t_snddis			*/
#define	E_T_RCV		22		/* t_rcv			*/
#define	E_T_SND		23		/* t_snd			*/

/* miscellaneous errors 						*/

#define E_CANT_HAPPEN	24		/* transport provider bug	*/

#define E_NOINTERMEDIARY 25		/* login service requested, but
					   listener doesn't have an
					   intermediary to 'exec'	*/

#define	E_FORK_SERVICE	26		/* error occurred when the listener
					   tried to fork itself to start
					   a service.			*/

#define E_RCV_MSG	27		/* error in t_rcv		*/
#define E_RCV_TMO	28		/* t_rcv timed out		*/

/*
 * E_OPENBIND: problem during t_open in initialization
 * actually means the driver ran out of minor devices or the
 * system file table is full -- reboot or wait recommended
 */

#define E_OPENBIND	29		/* open/bind err during init	*/

#define E_DBF_IO	30		/* data base file i/o error	*/
#define E_SCAN_DBF	E_DBF_IO
#define E_READ_DBF	E_DBF_IO

#define	E_BAD_VERSION	31		/* attservice: bad version	*/
#define E_BAD_FORMAT	32		/* attservice: bad msg format	*/

#define E_SYS_ERROR	33		/* sys call problem; i.e. in exec */

#define E_DBF_ALLOC	34		/* calloc's for dbf failed	*/
#define E_POLL		35		/* poll call failed		*/
#define E_MALLOC	36		/* generic failed malloc	*/
#define E_T_RCVDIS	37		/* t_rcvdis (should be above but
					   renumbering is bad) */
#define E_T_LOOK	38		/* t_look (should be above but
					   renumbering is bad) */
#define E_DBF_CORRUPT	39		/* data base file corrupt */
#define E_BADVER	40		/* data base file at wrong version */

#define E_FDNOMATCH	41		/* fd the call came in did not match
					   with fd in private_tab */
typedef struct {
	char	*err_msg;
	int	err_code;
} errlist;

#ifndef	GLOBAL_DATA
extern char *Usage;
extern errlist err_list[];
#endif

#endif	/* lserror_h */
