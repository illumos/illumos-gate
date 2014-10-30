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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _LX_SYSV_IPC_H
#define	_LX_SYSV_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * msg-related definitions.
 */
#define	LX_IPC_CREAT	00001000
#define	LX_IPC_EXCL	00002000
#define	LX_IPC_NOWAIT	00004000

#define	LX_IPC_RMID	0
#define	LX_IPC_SET	1
#define	LX_IPC_STAT	2
#define	LX_IPC_INFO	3

#define	LX_IPC_64	0x0100

#define	LX_SEMOP	1
#define	LX_SEMGET	2
#define	LX_SEMCTL	3
#define	LX_MSGSND	11
#define	LX_MSGRCV	12
#define	LX_MSGGET	13
#define	LX_MSGCTL	14
#define	LX_SHMAT	21
#define	LX_SHMDT	22
#define	LX_SHMGET	23
#define	LX_SHMCTL	24

#define	LX_MSG_STAT	11
#define	LX_MSG_INFO	12

#define	LX_MSG_NOERROR	010000

/*
 * Linux hard codes the maximum msgbuf length to be 8192 bytes.  Really.
 */
#define	LX_MSGMAX	8192

struct lx_ipc_perm {
	key_t		key;
	uid_t		uid;
	uid_t		gid;
	uid_t		cuid;
	uid_t		cgid;
	ushort_t	mode;
	ushort_t	_pad1;
	ushort_t	seq;
	ushort_t	_pad2;
	ulong_t		_unused1;
	ulong_t		_unused2;
};

struct lx_msqid_ds {
	struct lx_ipc_perm	msg_perm;
	time_t			msg_stime;
#if defined(_ILP32)
	ulong_t			_unused1;
#endif
	time_t			msg_rtime;
#if defined(_ILP32)
	ulong_t			_unused2;
#endif
	time_t			msg_ctime;
#if defined(_ILP32)
	ulong_t			_unused3;
#endif
	ulong_t			msg_cbytes;
	ulong_t			msg_qnum;
	ulong_t			msg_qbytes;
	pid_t			msg_lspid;
	pid_t			msg_lrpid;
	ulong_t			_unused4;
	ulong_t			_unused5;
};

struct lx_msginfo {
	int		msgpool;
	int		msgmap;
	int		msgmax;
	int		msgmnb;
	int		msgmni;
	int		msgssz;
	int		msgtql;
	ushort_t	msgseg;
};

/*
 * semaphore-related definitions.
 */
#define	LX_GETPID	11
#define	LX_GETVAL	12
#define	LX_GETALL	13
#define	LX_GETNCNT	14
#define	LX_GETZCNT	15
#define	LX_SETVAL	16
#define	LX_SETALL	17
#define	LX_SEM_STAT	18
#define	LX_SEM_INFO	19
#define	LX_SEM_UNDO	0x1000
#define	LX_SEMVMX	32767

struct lx_semid_ds {
	struct lx_ipc_perm	sem_perm;
	time_t			sem_otime;
#if defined(_ILP32)
	ulong_t			_unused1;
#endif
	time_t			sem_ctime;
#if defined(_ILP32)
	ulong_t			_unused2;
#endif
	ulong_t			sem_nsems;
	ulong_t			_unused3;
	ulong_t			_unused4;
};

struct lx_seminfo {
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};

union lx_semun {
	int val;
	struct lx_semid_ds *semds;
	ushort_t *sems;
	struct lx_seminfo *info;
	uintptr_t dummy;
};

/*
 * shm-related definitions
 */
#define	LX_SHM_LOCKED	02000
#define	LX_SHM_RDONLY	010000
#define	LX_SHM_RND	020000
#define	LX_SHM_REMAP	040000

#define	LX_SHM_LOCK	11
#define	LX_SHM_UNLOCK	12
#define	LX_SHM_STAT	13
#define	LX_SHM_INFO	14

struct lx_shmid_ds {
	struct lx_ipc_perm	shm_perm;
	size_t			shm_segsz;
	time_t			shm_atime;
#if defined(_ILP32)
	ulong_t			_unused1;
#endif
	time_t			shm_dtime;
#if defined(_ILP32)
	ulong_t			_unused2;
#endif
	time_t			shm_ctime;
#if defined(_ILP32)
	ulong_t			_unused3;
#endif
	pid_t			shm_cpid;
	pid_t			shm_lpid;
	ushort_t		shm_nattch;
	ulong_t			_unused4;
	ulong_t			_unused5;
};

struct lx_shm_info {
	int	used_ids;
	ulong_t	shm_tot;
	ulong_t	shm_rss;
	ulong_t	shm_swp;
	ulong_t	swap_attempts;
	ulong_t	swap_successes;
};

struct lx_shminfo {
	int	shmmax;
	int	shmmin;
	int	shmmni;
	int	shmseg;
	int	shmall;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_SYSV_IPC_H */
