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

#ifndef	_CFG_LOCKD_H
#define	_CFG_LOCKD_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum	{ LOCK_NOTLOCKED,	/* Unlock message */
		LOCK_READ,		/* ask for read lock */
		LOCK_WRITE,		/* ask for write lock */
		LOCK_LOCKED,		/* lock has been taken */
		LOCK_LOCKEDBY,		/* who has lock? */
		LOCK_STAT,		/* ask daemon to print its state */
		LOCK_ACK		/* acknowledge a notlocked msg */
		} cfglockd_t;

typedef struct	sockaddr_in daemonaddr_t;

struct lock_msg	{
	int32_t	message;
	pid_t pid;
	int32_t order;
	uint8_t seq;
};

#define	CFG_PIDFILE	"/var/tmp/.cfglockd.pid"
#define	CFG_SERVER_PORT	50121u
#define	CFG_LF_EOF		-1
#define	CFG_LF_OKAY		1
#define	CFG_LF_AGAIN		0
void	cfg_lfinit();
int	cfg_filelock(int segment, int flag);
int	cfg_fileunlock(int segment);
void	cfg_readpid(int segment, pid_t *pidp);
void	cfg_writepid(int segment, pid_t pid);
void	cfg_enterpid();
int	cfg_lockd_init();
cfglockd_t	cfg_lockedby(pid_t *);
void	cfg_lockd_rdlock();
void	cfg_lockd_wrlock();
void	cfg_lockd_unlock();

#ifdef	__cplusplus
}
#endif

#endif /* _CFG_LOCKD_H */
