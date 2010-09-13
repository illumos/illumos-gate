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


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3*/


/*
 * REQUIRES: sac.h
 */


struct	admcmd {
	char	ac_mtype;		/* type of message */
	char	ac_tag[PMTAGSIZE + 1];	/* PM tag */
	pid_t	ac_pid;			/* pid for id purposes (seq #) */
};


/*
 * ac_mtype values
 */

# define AC_START	1		/* start PM */
# define AC_KILL	2		/* kill PM */
# define AC_ENABLE	3		/* enable PM */
# define AC_DISABLE	4		/* disable PM */
# define AC_STATUS	5		/* return PM status info - ac_tag
					   is unused with this command */
# define AC_SACREAD	6		/* read _sactab - ac_tag is unused
					   with this command */
# define AC_PMREAD	7		/* tell PM to read _pmtab */


/*
 * the following structure defines the header on messages from
 * the SAC back to sacadm.  The size field (ak_size) defines the
 * size of the data portion of * the message, which follows the header.
 * The form of this optional data portion is defined strictly by the
 * request message type that caused the data to be returned (ac_mtype).
 */

struct	admack {
	char	ak_resp;		/* response code - 0 for ack, non
					   zero indicates reason for failure */
	pid_t	ak_pid;			/* pid for id purposes (seq #) */
	long	ak_size;		/* if true, indicates size of next msg */
};


/*
 * ak_resp values
 */

# define AK_ACK		0		/* requested command succeeded */
# define AK_PMRUN	1		/* PM was already running */
# define AK_PMNOTRUN	2		/* PM was not running */
# define AK_NOPM	3		/* PM does not exist */
# define AK_UNKNOWN	4		/* unknown command */
# define AK_NOCONTACT	5		/* could not contact PM */
# define AK_PMLOCK	6		/* _pid file locked on start */
# define AK_RECOVER	7		/* PM in recovery */
# define AK_REQFAIL	8		/* the request failed for some reason */
