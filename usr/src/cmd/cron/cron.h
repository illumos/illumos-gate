/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CRON_H
#define	_CRON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <dirent.h>
#include <auth_attr.h>
#include <auth_list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	FALSE		0
#define	TRUE		1
#define	MINUTE		60L
#define	HOUR		60L*60L
#define	DAY		24L*60L*60L
#define	NQUEUE		26		/* number of queues available */
#define	ATEVENT		0
#define	BATCHEVENT	1
#define	CRONEVENT	2

#define	ADD		'a'
#define	DELETE		'd'
#define	AT		'a'
#define	CRON		'c'

#define	QUE(x)		('a'+(x))
#define	RCODE(x)	(((x)>>8)&0377)
#define	TSTAT(x)	((x)&0377)

#define	FLEN	15
#define	LLEN	9

/*
 * structure used for passing messages from the at and crontab commands to cron
 */
struct	message {
	char	etype;
	char	action;
	char	fname[FLEN];
	char	logname[LLEN];
} msgbuf;

/* anything below here can be changed */

#define	CRONDIR		"/var/spool/cron/crontabs"
#define	ATDIR		"/var/spool/cron/atjobs"
#define	ACCTFILE	"/var/cron/log"
#define	CRONALLOW	"/etc/cron.d/cron.allow"
#define	CRONDENY	"/etc/cron.d/cron.deny"
#define	ATALLOW		"/etc/cron.d/at.allow"
#define	ATDENY		"/etc/cron.d/at.deny"
#define	PROTO		"/etc/cron.d/.proto"
#define	QUEDEFS		"/etc/cron.d/queuedefs"
#define	FIFO		"/etc/cron.d/FIFO"
#define	DEFFILE		"/etc/default/cron"

#define	SHELL		"/usr/bin/sh"	/* shell to execute */

#define	CTLINESIZE	1000	/* max chars in a crontab line */
#define	UNAMESIZE	20	/* max chars in a user name */

int	allowed(char *, char *, char *);
int	days_in_mon(int, int);
char	*errmsg(int);
char	*getuser(uid_t);
void	cron_sendmsg(char, char *, char *, char);
time_t	 num(char **);
void	*xmalloc(size_t);
void	*xcalloc(size_t, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _CRON_H */
