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

#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <rctl.h>
#include <alloca.h>
#include <values.h>
#include <sys/syscall.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/lx_debug.h>
#include <sys/lx_types.h>
#include <sys/lx_sysv_ipc.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

#define	SLOT_SEM	0
#define	SLOT_SHM	1
#define	SLOT_MSG	2

static int
get_rctlval(rctlblk_t *rblk, char *name)
{
	rctl_qty_t r;

	if (getrctl(name, NULL, rblk, RCTL_FIRST) == -1)
		return (-errno);

	r = rctlblk_get_value(rblk);
	if (r > MAXINT)
		return (-EOVERFLOW);
	return (r);
}

/*
 * Given a slot number and a maximum number of ids to extract from the
 * kernel, return the msgid in the provided slot.
 */
static int
slot_to_id(int type, int slot)
{
	uint_t nids, max;
	int *idbuf = NULL;
	int r = 0;

	nids = 0;
	for (;;) {
		switch (type) {
		case SLOT_SEM:
			r = semids(idbuf, nids, &max);
			break;
		case SLOT_SHM:
			r = shmids(idbuf, nids, &max);
			break;
		case SLOT_MSG:
			r = msgids(idbuf, nids, &max);
			break;
		}

		if (r < 0)
			return (-errno);

		if (max == 0)
			return (-EINVAL);

		if (max <= nids)
			return (idbuf[slot]);

		nids = max;
		if ((idbuf = (int *)SAFE_ALLOCA(sizeof (int) * nids)) == NULL)
			return (-ENOMEM);
	}
}

/*
 * Semaphore operations.
 */
long
lx_semget(key_t key, int nsems, int semflg)
{
	int sol_flag;
	int r;

	lx_debug("\nsemget(%d, %d, %d)\n", key, nsems, semflg);
	sol_flag = semflg & S_IAMB;
	if (semflg & LX_IPC_CREAT)
		sol_flag |= IPC_CREAT;
	if (semflg & LX_IPC_EXCL)
		sol_flag |= IPC_EXCL;

	r = semget(key, nsems, sol_flag);
	return ((r < 0) ? -errno : r);
}

long
lx_semop(int semid, void *p1, size_t nsops)
{
	int r;
	struct sembuf *sops = (struct sembuf *)p1;

	lx_debug("\nsemop(%d, 0x%p, %u)\n", semid, sops, nsops);
	if (nsops == 0)
		return (-EINVAL);

	r = semop(semid, sops, nsops);
	return ((r < 0) ? -errno : r);
}

long
lx_semtimedop(int semid, void *p1, size_t nsops, struct timespec *timeout)
{
	int r;
	struct sembuf *sops = (struct sembuf *)p1;

	lx_debug("\nsemtimedop(%d, 0x%p, %u, 0x%p)\n", semid, sops, nsops,
	    timeout);
	if (nsops == 0)
		return (-EINVAL);

	r = semtimedop(semid, sops, nsops, timeout);
	return ((r < 0) ? -errno : r);
}

static int
lx_semctl_ipcset(int semid, void *buf)
{
	struct lx_semid_ds semds;
	struct semid_ds sol_semds;
	int r;

	if (uucopy(buf, &semds, sizeof (semds)))
		return (-errno);

	bzero(&sol_semds, sizeof (sol_semds));
	sol_semds.sem_perm.uid = semds.sem_perm.uid;
	sol_semds.sem_perm.gid = semds.sem_perm.gid;
	sol_semds.sem_perm.mode = semds.sem_perm.mode;

	r = semctl(semid, 0, IPC_SET, &sol_semds);
	return ((r < 0) ? -errno : r);
}

static int
lx_semctl_ipcstat(int semid, void *buf)
{
	struct lx_semid_ds semds;
	struct semid_ds sol_semds;

	if (semctl(semid, 0, IPC_STAT, &sol_semds) != 0)
		return (-errno);

	bzero(&semds, sizeof (semds));
	semds.sem_perm.key = sol_semds.sem_perm.key;
	semds.sem_perm.seq = sol_semds.sem_perm.seq;
	semds.sem_perm.uid = sol_semds.sem_perm.uid;
	semds.sem_perm.gid = sol_semds.sem_perm.gid;
	semds.sem_perm.cuid = sol_semds.sem_perm.cuid;
	semds.sem_perm.cgid = sol_semds.sem_perm.cgid;

	/* Linux only uses the bottom 9 bits */
	semds.sem_perm.mode = sol_semds.sem_perm.mode & S_IAMB;
	semds.sem_otime = sol_semds.sem_otime;
	semds.sem_ctime = sol_semds.sem_ctime;
	semds.sem_nsems = sol_semds.sem_nsems;

	if (uucopy(&semds, buf, sizeof (semds)))
		return (-errno);

	return (0);
}

static int
lx_semctl_ipcinfo(void *buf)
{
	struct lx_seminfo i;
	rctlblk_t *rblk;
	int rblksz;
	uint_t nids;
	int idbuf;

	rblksz = rctlblk_size();
	if ((rblk = (rctlblk_t *)SAFE_ALLOCA(rblksz)) == NULL)
		return (-ENOMEM);

	bzero(&i, sizeof (i));
	if ((i.semmni = get_rctlval(rblk, "project.max-sem-ids")) < 0)
		return (i.semmni);
	if ((i.semmsl = get_rctlval(rblk, "process.max-sem-nsems")) < 0)
		return (i.semmsl);
	if ((i.semopm = get_rctlval(rblk, "process.max-sem-ops")) < 0)
		return (i.semopm);

	/*
	 * We don't have corresponding rctls for these fields.  The values
	 * are taken from the formulas used to derive the defaults listed
	 * in the Linux header file.  We're lying, but trying to be
	 * coherent about it.
	 */
	i.semmap = i.semmni;
	i.semmns = i.semmni * i.semmsl;
	i.semmnu = INT_MAX;
	i.semume = INT_MAX;
	i.semvmx = LX_SEMVMX;
	if (semids(&idbuf, 0, &nids) < 0)
		return (-errno);
	i.semusz = nids;
	i.semaem = INT_MAX;

	if (uucopy(&i, buf, sizeof (i)) != 0)
		return (-errno);

	return (nids);
}

static int
lx_semctl_semstat(int slot, void *buf)
{
	int r, semid;

	semid = slot_to_id(SLOT_SEM, slot);
	if (semid < 0)
		return (semid);

	r = lx_semctl_ipcstat(semid, buf);
	return (r < 0 ? r : semid);
}

/*
 * For the SETALL operation, we have to examine each of the semaphore
 * values to be sure it is legal.
 */
static int
lx_semctl_setall(int semid, union lx_semun *arg)
{
	struct semid_ds semds;
	ushort_t *vals;
	int i, sz, r;

	/*
	 * Find out how many semaphores are involved, reserve enough
	 * memory for an internal copy of the array, and then copy it in
	 * from the process.
	 */
	if (semctl(semid, 0, IPC_STAT, &semds) != 0)
		return (-errno);
	sz = semds.sem_nsems * sizeof (ushort_t);
	if ((vals = SAFE_ALLOCA(sz)) == NULL)
		return (-ENOMEM);
	if (uucopy(arg->sems, vals, sz))
		return (-errno);

	/* Validate each of the values. */
	for (i = 0; i < semds.sem_nsems; i++)
		if (vals[i] > LX_SEMVMX)
			return (-ERANGE);

	r = semctl(semid, 0, SETALL, arg->sems);

	return ((r < 0) ? -errno : r);
}

long
lx_semctl(int semid, int semnum, int cmd, void *ptr)
{
	union lx_semun arg;
	int rval;
	int opt = cmd & ~LX_IPC_64;
	int use_errno = 0;

	lx_debug("\nsemctl(%d, %d, %d, 0x%p)\n", semid, semnum, cmd, ptr);

	/*
	 * The final arg to semctl() is a pointer to a union.  For some
	 * commands we can hand that pointer directly to the kernel.  For
	 * these commands, we need to extract an argument from the union
	 * before calling into the kernel.
	 */
	if (opt == LX_SETVAL || opt == LX_SETALL || opt == LX_GETALL ||
	    opt == LX_IPC_SET || opt == LX_IPC_STAT || opt == LX_SEM_STAT ||
	    opt == LX_IPC_INFO || opt == LX_SEM_INFO)
		if (uucopy(ptr, &arg, sizeof (arg)))
			return (-errno);

	switch (opt) {
	case LX_GETVAL:
		use_errno = 1;
		rval = semctl(semid, semnum, GETVAL, NULL);
		break;
	case LX_SETVAL:
		if (arg.val > LX_SEMVMX) {
			rval = -ERANGE;
			break;
		}
		use_errno = 1;
		rval = semctl(semid, semnum, SETVAL, arg.val);
		break;
	case LX_GETPID:
		use_errno = 1;
		rval = semctl(semid, semnum, GETPID, NULL);
		break;
	case LX_GETNCNT:
		use_errno = 1;
		rval = semctl(semid, semnum, GETNCNT, NULL);
		break;
	case LX_GETZCNT:
		use_errno = 1;
		rval = semctl(semid, semnum, GETZCNT, NULL);
		break;
	case LX_GETALL:
		use_errno = 1;
		rval = semctl(semid, semnum, GETALL, arg.sems);
		break;
	case LX_SETALL:
		rval = lx_semctl_setall(semid, &arg);
		break;
	case LX_IPC_RMID:
		use_errno = 1;
		rval = semctl(semid, semnum, IPC_RMID, NULL);
		break;
	case LX_SEM_STAT:
		rval = lx_semctl_semstat(semid, arg.semds);
		break;
	case LX_IPC_STAT:
		rval = lx_semctl_ipcstat(semid, arg.semds);
		break;

	case LX_IPC_SET:
		rval = lx_semctl_ipcset(semid, arg.semds);
		break;

	case LX_IPC_INFO:
	case LX_SEM_INFO:
		rval = lx_semctl_ipcinfo(arg.semds);
		break;

	default:
		rval = -EINVAL;
	}

	if (use_errno == 1 && rval < 0)
		return (-errno);
	return (rval);
}

/*
 * msg operations.
 */
long
lx_msgget(key_t key, int flag)
{
	int sol_flag;
	int r;

	lx_debug("\tlx_msgget(%d, %d)\n", key, flag);

	sol_flag = flag & S_IAMB;
	if (flag & LX_IPC_CREAT)
		sol_flag |= IPC_CREAT;
	if (flag & LX_IPC_EXCL)
		sol_flag |= IPC_EXCL;

	r = msgget(key, sol_flag);
	return (r < 0 ? -errno : r);
}

long
lx_msgsnd(int id, void *p1, size_t sz, int flag)
{
	int sol_flag = 0;
	int r;
	struct msgbuf *buf = (struct msgbuf *)p1;

	lx_debug("\tlx_msgsnd(%d, 0x%p, %d, %d)\n", id, buf, sz, flag);

	if (flag & LX_IPC_NOWAIT)
		sol_flag |= IPC_NOWAIT;

	if (((ssize_t)sz < 0) || (sz > LX_MSGMAX))
		return (-EINVAL);

	r = msgsnd(id, buf, sz, sol_flag);
	return (r < 0 ? -errno : r);
}

long
lx_msgrcv(int id, void *msgp, size_t sz, long msgtype, int flag)
{
	int sol_flag = 0;
	ssize_t r;

	lx_debug("\tlx_msgrcv(%d, 0x%p, %d, %d, %ld, %d)\n",
	    id, msgp, sz, msgtype, flag);

	/*
	 * Check for a negative sz parameter.
	 *
	 * Unlike msgsnd(2), the Linux man page does not specify that
	 * msgrcv(2) should return EINVAL if (sz > MSGMAX), only if (sz < 0).
	 */
	if ((ssize_t)sz < 0)
		return (-EINVAL);

	if (flag & LX_MSG_NOERROR)
		sol_flag |= MSG_NOERROR;
	if (flag & LX_IPC_NOWAIT)
		sol_flag |= IPC_NOWAIT;

	r = msgrcv(id, msgp, sz, msgtype, sol_flag);
	return (r < 0 ? -errno : r);
}

static int
lx_msgctl_ipcstat(int msgid, void *buf)
{
	struct lx_msqid_ds msgids;
	struct msqid_ds sol_msgids;
	int r;

	r = msgctl(msgid, IPC_STAT, &sol_msgids);
	if (r < 0)
		return (-errno);

	bzero(&msgids, sizeof (msgids));
	msgids.msg_perm.key = sol_msgids.msg_perm.key;
	msgids.msg_perm.seq = sol_msgids.msg_perm.seq;
	msgids.msg_perm.uid = sol_msgids.msg_perm.uid;
	msgids.msg_perm.gid = sol_msgids.msg_perm.gid;
	msgids.msg_perm.cuid = sol_msgids.msg_perm.cuid;
	msgids.msg_perm.cgid = sol_msgids.msg_perm.cgid;

	/* Linux only uses the bottom 9 bits */
	msgids.msg_perm.mode = sol_msgids.msg_perm.mode & S_IAMB;

	msgids.msg_stime = sol_msgids.msg_stime;
	msgids.msg_rtime = sol_msgids.msg_rtime;
	msgids.msg_ctime = sol_msgids.msg_ctime;
	msgids.msg_qbytes = sol_msgids.msg_qbytes;
	msgids.msg_cbytes = sol_msgids.msg_cbytes;
	msgids.msg_qnum = sol_msgids.msg_qnum;
	msgids.msg_lspid = sol_msgids.msg_lspid;
	msgids.msg_lrpid = sol_msgids.msg_lrpid;

	if (uucopy(&msgids, buf, sizeof (msgids)))
		return (-errno);

	return (0);
}

static int
lx_msgctl_ipcinfo(int cmd, void *buf)
{
	struct lx_msginfo m;
	rctlblk_t *rblk;
	int idbuf, rblksz, msgseg, maxmsgs;
	uint_t nids;
	int rval;

	rblksz = rctlblk_size();
	if ((rblk = (rctlblk_t *)SAFE_ALLOCA(rblksz)) == NULL)
		return (-ENOMEM);

	bzero(&m, sizeof (m));
	if ((m.msgmni = get_rctlval(rblk, "project.max-msg-ids")) < 0)
		return (m.msgmni);
	if ((m.msgmnb = get_rctlval(rblk, "process.max-msg-qbytes")) < 0)
		return (m.msgmnb);

	if (cmd == LX_IPC_INFO) {
		if ((maxmsgs = get_rctlval(rblk,
		    "process.max-msg-messages")) < 0)
			return (maxmsgs);
		m.msgtql = maxmsgs * m.msgmni;
		m.msgmap = m.msgmnb;
		m.msgpool = m.msgmax * m.msgmnb;
		rval = 0;
	} else {
		if (msgids(&idbuf, 0, &nids) < 0)
			return (-errno);
		m.msgpool = nids;

		/*
		 * For these fields, we can't even come up with a good fake
		 * approximation.  These are listed as 'obsolete' or
		 * 'unused' in the header files, so hopefully nobody is
		 * relying on them anyway.
		 */
		m.msgtql = INT_MAX;
		m.msgmap = INT_MAX;
		rval = nids;
	}

	/*
	 * We don't have corresponding rctls for these fields.  The values
	 * are taken from the formulas used to derive the defaults listed
	 * in the Linux header file.  We're lying, but trying to be
	 * coherent about it.
	 */
	m.msgmax = m.msgmnb;
	m.msgssz = 16;
	msgseg = (m.msgpool * 1024) / m.msgssz;
	m.msgseg = (msgseg > 0xffff) ? 0xffff : msgseg;

	if (uucopy(&m, buf, sizeof (m)))
		return (-errno);
	return (rval);
}

static int
lx_msgctl_ipcset(int msgid, void *buf)
{
	struct lx_msqid_ds msgids;
	struct msqid_ds sol_msgids;
	int r;

	if (uucopy(buf, &msgids, sizeof (msgids)))
		return (-errno);

	bzero(&sol_msgids, sizeof (sol_msgids));
	sol_msgids.msg_perm.uid = LX_UID16_TO_UID32(msgids.msg_perm.uid);
	sol_msgids.msg_perm.gid = LX_UID16_TO_UID32(msgids.msg_perm.gid);

	/* Linux only uses the bottom 9 bits */
	sol_msgids.msg_perm.mode = msgids.msg_perm.mode & S_IAMB;
	sol_msgids.msg_qbytes = msgids.msg_qbytes;

	r = msgctl(msgid, IPC_SET, &sol_msgids);
	return (r < 0 ? -errno : r);
}

static int
lx_msgctl_msgstat(int slot, void *buf)
{
	int r, msgid;

	lx_debug("msgstat(%d, 0x%p)\n", slot, buf);

	msgid = slot_to_id(SLOT_MSG, slot);

	if (msgid < 0)
		return (msgid);

	r = lx_msgctl_ipcstat(msgid, buf);
	return (r < 0 ? r : msgid);
}

/*
 * Split off the various msgctl's here
 */
long
lx_msgctl(int msgid, int cmd, void *buf)
{
	int r;

	lx_debug("\tlx_msgctl(%d, %d, 0x%p)\n", msgid, cmd, buf);
	switch (cmd & ~LX_IPC_64) {
	case LX_IPC_RMID:
		r = msgctl(msgid, IPC_RMID, NULL);
		if (r < 0)
			r = -errno;
		break;
	case LX_IPC_SET:
		r = lx_msgctl_ipcset(msgid, buf);
		break;
	case LX_IPC_STAT:
		r = lx_msgctl_ipcstat(msgid, buf);
		break;
	case LX_MSG_STAT:
		r = lx_msgctl_msgstat(msgid, buf);
		break;

	case LX_IPC_INFO:
	case LX_MSG_INFO:
		r = lx_msgctl_ipcinfo(cmd, buf);
		break;

	default:
		r = -EINVAL;
		break;
	}

	return (r);
}

/*
 * shm-related operations.
 */
long
lx_shmget(key_t key, size_t size, int flag)
{
	int sol_flag;
	int r;

	lx_debug("\tlx_shmget(%d, %d, %d)\n", key, size, flag);

	sol_flag = flag & S_IAMB;
	if (flag & LX_IPC_CREAT)
		sol_flag |= IPC_CREAT;
	if (flag & LX_IPC_EXCL)
		sol_flag |= IPC_EXCL;

	r = shmget(key, size, sol_flag);
	return (r < 0 ? -errno : r);
}

long
lx_shmat(int shmid, void *addr, int flags)
{
	int sol_flags;
	void *ptr;

	lx_debug("\tlx_shmat(%d, 0x%p, %d)\n", shmid, addr, flags);

	sol_flags = 0;
	if (flags & LX_SHM_RDONLY)
		sol_flags |= SHM_RDONLY;
	if (flags & LX_SHM_RND)
		sol_flags |= SHM_RND;
	if ((flags & LX_SHM_REMAP) && (addr == NULL))
		return (-EINVAL);

	ptr = shmat(shmid, addr, sol_flags);
	if (ptr == (void *)-1)
		return (-errno);

	return ((ssize_t)ptr);
}

static int
lx_shmctl_ipcinfo(void *buf)
{
	struct lx_shminfo s;
	rctlblk_t *rblk;
	int rblksz;

	rblksz = rctlblk_size();
	if ((rblk = (rctlblk_t *)SAFE_ALLOCA(rblksz)) == NULL)
		return (-ENOMEM);

	bzero(&s, sizeof (s));
	if ((s.shmmni = get_rctlval(rblk, "project.max-shm-ids")) < 0)
		return (s.shmmni);
	if ((s.shmmax = get_rctlval(rblk, "project.max-shm-memory")) < 0)
		return (s.shmmax);

	/*
	 * We don't have corresponding rctls for these fields.  The values
	 * are taken from the formulas used to derive the defaults listed
	 * in the Linux header file.  We're lying, but trying to be
	 * coherent about it.
	 */
	s.shmmin = 1;
	s.shmseg = INT_MAX;
	s.shmall = s.shmmax / getpagesize();

	if (uucopy(&s, buf, sizeof (s)))
		return (-errno);

	return (0);
}

static int
lx_shmctl_ipcstat(int shmid, void *buf)
{
	struct lx_shmid_ds shmds;
	struct shmid_ds sol_shmds;

	if (shmctl(shmid, IPC_STAT, &sol_shmds) != 0)
		return (-errno);

	bzero(&shmds, sizeof (shmds));
	shmds.shm_perm.key = sol_shmds.shm_perm.key;
	shmds.shm_perm.seq = sol_shmds.shm_perm.seq;
	shmds.shm_perm.uid = sol_shmds.shm_perm.uid;
	shmds.shm_perm.gid = sol_shmds.shm_perm.gid;
	shmds.shm_perm.cuid = sol_shmds.shm_perm.cuid;
	shmds.shm_perm.cgid = sol_shmds.shm_perm.cgid;
	shmds.shm_perm.mode = sol_shmds.shm_perm.mode & S_IAMB;
	if (sol_shmds.shm_lkcnt > 0)
		shmds.shm_perm.mode |= LX_SHM_LOCKED;
	shmds.shm_segsz = sol_shmds.shm_segsz;
	shmds.shm_atime	 = sol_shmds.shm_atime;
	shmds.shm_dtime = sol_shmds.shm_dtime;
	shmds.shm_ctime = sol_shmds.shm_ctime;
	shmds.shm_cpid = sol_shmds.shm_cpid;
	shmds.shm_lpid = sol_shmds.shm_lpid;
	shmds.shm_nattch = (ushort_t)sol_shmds.shm_nattch;

	if (uucopy(&shmds, buf, sizeof (shmds)))
		return (-errno);

	return (0);
}

static int
lx_shmctl_ipcset(int shmid, void *buf)
{
	struct lx_shmid_ds shmds;
	struct shmid_ds sol_shmds;
	int r;

	if (uucopy(buf, &shmds, sizeof (shmds)))
		return (-errno);

	bzero(&sol_shmds, sizeof (sol_shmds));
	sol_shmds.shm_perm.uid = shmds.shm_perm.uid;
	sol_shmds.shm_perm.gid = shmds.shm_perm.gid;
	sol_shmds.shm_perm.mode = shmds.shm_perm.mode & S_IAMB;

	r = shmctl(shmid, IPC_SET, &sol_shmds);
	return (r < 0 ? -errno : r);
}

/*
 * Build and return a shm_info structure. We only return the bare
 * essentials required by ipcs. The rest of the info is not readily
 * available.
 */
static int
lx_shmctl_shminfo(void *buf)
{
	struct lx_shm_info shminfo;
	uint_t nids;
	int idbuf;

	bzero(&shminfo, sizeof (shminfo));

	if (shmids(&idbuf, 0, &nids) < 0)
		return (-errno);

	shminfo.used_ids = nids;
	if (uucopy(&shminfo, buf, sizeof (shminfo)) != 0)
		return (-errno);

	return (nids);
}

static int
lx_shmctl_shmstat(int slot, void *buf)
{
	int r, shmid;

	lx_debug("shmctl_shmstat(%d, 0x%p)\n", slot, buf);
	shmid = slot_to_id(SLOT_SHM, slot);
	if (shmid < 0)
		return (shmid);

	r = lx_shmctl_ipcstat(shmid, buf);
	return (r < 0 ? r : shmid);
}

long
lx_shmctl(int shmid, int cmd, void *buf)
{
	int r;
	int use_errno = 0;

	lx_debug("\tlx_shmctl(%d, %d, 0x%p)\n", shmid, cmd, buf);
	switch (cmd & ~LX_IPC_64) {
	case LX_IPC_RMID:
		use_errno = 1;
		r = shmctl(shmid, IPC_RMID, NULL);
		break;

	case LX_IPC_SET:
		r = lx_shmctl_ipcset(shmid, buf);
		break;

	case LX_IPC_STAT:
		r = lx_shmctl_ipcstat(shmid, buf);
		break;

	case LX_IPC_INFO:
		r = lx_shmctl_ipcinfo(buf);
		break;

	case LX_SHM_LOCK:
		use_errno = 1;
		r = shmctl(shmid, SHM_LOCK, NULL);
		break;

	case LX_SHM_UNLOCK:
		use_errno = 1;
		r = shmctl(shmid, SHM_UNLOCK, NULL);
		break;

	case LX_SHM_INFO:
		r = lx_shmctl_shminfo(buf);
		break;

	case LX_SHM_STAT:
		r = lx_shmctl_shmstat(shmid, buf);
		break;
	default:
		r = -EINVAL;
		break;
	}

	if (use_errno == 1 && r < 0)
		return (-errno);

	return (r);
}

/*
 * Under 32-bit Linux, glibc funnels all of the sysv IPC operations into this
 * single ipc(2) system call.  We need to blow that up and filter the
 * remnants into the proper Solaris system calls.
 */
long
lx_ipc(uintptr_t cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4)
{
	int r;
	void *bufptr = (void *)arg4;

	lx_debug("lx_ipc(%d, %d, %d, %d, 0x%p, %d)\n",
	    cmd, arg1, arg2, arg3, bufptr, arg4);

	switch (cmd) {
	case LX_MSGGET:
		r = lx_msgget((key_t)arg1, (int)arg2);
		break;
	case LX_MSGSND:
		r = lx_msgsnd((int)arg1, bufptr, (size_t)arg2, (int)arg3);
		break;
	case LX_MSGRCV:
		{
			struct {
				void *msgp;
				long msgtype;
			} args;

			/*
			 * Rather than passing 5 args into ipc(2) directly,
			 * glibc passes 4 args and uses the buf argument to
			 * point to a structure containing two args: a pointer
			 * to the message and the message type.
			 */
			if (uucopy(bufptr, &args, sizeof (args)))
				return (-errno);
			r = lx_msgrcv((int)arg1, args.msgp, (size_t)arg2,
			    args.msgtype, (int)arg3);
		}
		break;
	case LX_MSGCTL:
		r = lx_msgctl((int)arg1, (int)arg2, bufptr);
		break;
	case LX_SEMCTL:
		r = lx_semctl((int)arg1, (size_t)arg2, (int)arg3, bufptr);
		break;
	case LX_SEMOP:
		/*
		 * 'struct sembuf' is the same on Linux and Solaris, so we
		 * pass bufptr straight through.
		 */
		r = lx_semop((int)arg1, bufptr, (size_t)arg2);
		break;
	case LX_SEMGET:
		r = lx_semget((int)arg1, (size_t)arg2, (int)arg3);
		break;
	case LX_SHMAT:
		r = lx_shmat((int)arg1, bufptr, (size_t)arg2);
		if (r >= 0 || r <= -4096) {
			if (uucopy(&r, (void *)arg3, sizeof (r)) != 0)
				r = -errno;
		}
		break;
	case LX_SHMDT:
		r = shmdt(bufptr);
		if (r < 0)
			r = -errno;
		break;
	case LX_SHMGET:
		r = lx_shmget((int)arg1, (size_t)arg2, (int)arg3);
		break;
	case LX_SHMCTL:
		r = lx_shmctl((int)arg1, (int)arg2, bufptr);
		break;

	default:
		r = -EINVAL;
	}

	return (r);
}
