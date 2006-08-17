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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Inter-Process Communication Message Facility.
 *
 * See os/ipc.c for a description of common IPC functionality.
 *
 * Resource controls
 * -----------------
 *
 * Control:      project.max-msg-ids (rc_project_msgmni)
 * Description:  Maximum number of message queue ids allowed a project.
 *
 *   When msgget() is used to allocate a message queue, one id is
 *   allocated.  If the id allocation doesn't succeed, msgget() fails
 *   and errno is set to ENOSPC.  Upon successful msgctl(, IPC_RMID)
 *   the id is deallocated.
 *
 * Control:      process.max-msg-qbytes (rc_process_msgmnb)
 * Description:  Maximum number of bytes of messages on a message queue.
 *
 *   When msgget() successfully allocates a message queue, the minimum
 *   enforced value of this limit is used to initialize msg_qbytes.
 *
 * Control:      process.max-msg-messages (rc_process_msgtql)
 * Description:  Maximum number of messages on a message queue.
 *
 *   When msgget() successfully allocates a message queue, the minimum
 *   enforced value of this limit is used to initialize a per-queue
 *   limit on the number of messages.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/msg.h>
#include <sys/msg_impl.h>
#include <sys/list.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/project.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/policy.h>
#include <sys/zone.h>

#include <c2/audit.h>

/*
 * The following tunables are obsolete.  Though for compatibility we
 * still read and interpret msginfo_msgmnb, msginfo_msgmni, and
 * msginfo_msgtql (see os/project.c and os/rctl_proc.c), the preferred
 * mechanism for administrating the IPC Message facility is through the
 * resource controls described at the top of this file.
 */
size_t	msginfo_msgmax = 2048;	/* (obsolete) */
size_t	msginfo_msgmnb = 4096;	/* (obsolete) */
int	msginfo_msgmni = 50;	/* (obsolete) */
int	msginfo_msgtql = 40;	/* (obsolete) */
int	msginfo_msgssz = 8;	/* (obsolete) */
int	msginfo_msgmap = 0;	/* (obsolete) */
ushort_t msginfo_msgseg = 1024;	/* (obsolete) */

extern rctl_hndl_t rc_project_msgmni;
extern rctl_hndl_t rc_process_msgmnb;
extern rctl_hndl_t rc_process_msgtql;
static ipc_service_t *msq_svc;
static zone_key_t msg_zone_key;

static void msg_dtor(kipc_perm_t *);
static void msg_rmid(kipc_perm_t *);
static void msg_remove_zone(zoneid_t, void *);

/*
 * Module linkage information for the kernel.
 */
static ssize_t msgsys(int opcode, uintptr_t a0, uintptr_t a1, uintptr_t a2,
	uintptr_t a4, uintptr_t a5);

static struct sysent ipcmsg_sysent = {
	6,
#ifdef	_LP64
	SE_ARGC | SE_NOUNLOAD | SE_64RVAL,
#else
	SE_ARGC | SE_NOUNLOAD | SE_32RVAL1,
#endif
	(int (*)())msgsys
};

#ifdef	_SYSCALL32_IMPL
static ssize32_t msgsys32(int opcode, uint32_t a0, uint32_t a1, uint32_t a2,
	uint32_t a4, uint32_t a5);

static struct sysent ipcmsg_sysent32 = {
	6,
	SE_ARGC | SE_NOUNLOAD | SE_32RVAL1,
	(int (*)())msgsys32
};
#endif	/* _SYSCALL32_IMPL */

static struct modlsys modlsys = {
	&mod_syscallops, "System V message facility", &ipcmsg_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit System V message facility", &ipcmsg_sysent32
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};


int
_init(void)
{
	int result;

	msq_svc = ipcs_create("msqids", rc_project_msgmni, sizeof (kmsqid_t),
	    msg_dtor, msg_rmid, AT_IPC_MSG,
	    offsetof(kproject_data_t, kpd_msgmni));
	zone_key_create(&msg_zone_key, NULL, msg_remove_zone, NULL);

	if ((result = mod_install(&modlinkage)) == 0)
		return (0);

	(void) zone_key_delete(msg_zone_key);
	ipcs_destroy(msq_svc);

	return (result);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
msg_dtor(kipc_perm_t *perm)
{
	kmsqid_t *qp = (kmsqid_t *)perm;
	int		ii;

	for (ii = 0; ii < MAX_QNUM_CV; ii++)
		ASSERT(qp->msg_rcv_cnt[ii] == 0);
	ASSERT(qp->msg_snd_cnt == 0);
	ASSERT(qp->msg_cbytes == 0);
	list_destroy(&qp->msg_list);
}


#define	msg_hold(mp)	(mp)->msg_copycnt++

/*
 * msg_rele - decrement the reference count on the message.  When count
 * reaches zero, free message header and contents.
 */
static void
msg_rele(struct msg *mp)
{
	ASSERT(mp->msg_copycnt > 0);
	if (mp->msg_copycnt-- == 1) {
		if (mp->msg_addr)
			kmem_free(mp->msg_addr, mp->msg_size);
		kmem_free(mp, sizeof (struct msg));
	}
}

/*
 * msgunlink - Unlink msg from queue, decrement byte count and wake up anyone
 * waiting for free bytes on queue.
 *
 * Called with queue locked.
 */
static void
msgunlink(kmsqid_t *qp, struct msg *mp)
{
	list_remove(&qp->msg_list, mp);
	qp->msg_qnum--;
	qp->msg_cbytes -= mp->msg_size;
	msg_rele(mp);

	/* Wake up waiting writers */
	if (qp->msg_snd_cnt)
		cv_broadcast(&qp->msg_snd_cv);
}

static void
msg_rmid(kipc_perm_t *perm)
{
	kmsqid_t *qp = (kmsqid_t *)perm;
	struct msg *mp;
	int		ii;


	while ((mp = list_head(&qp->msg_list)) != NULL)
		msgunlink(qp, mp);
	ASSERT(qp->msg_cbytes == 0);

	for (ii = 0; ii < MAX_QNUM_CV; ii++) {
		if (qp->msg_rcv_cnt[ii])
			cv_broadcast(&qp->msg_rcv_cv[ii]);
	}
	if (qp->msg_snd_cnt)
		cv_broadcast(&qp->msg_snd_cv);
}

/*
 * msgctl system call.
 *
 * gets q lock (via ipc_lookup), releases before return.
 * may call users of msg_lock
 */
static int
msgctl(int msgid, int cmd, void *arg)
{
	STRUCT_DECL(msqid_ds, ds);		/* SVR4 queue work area */
	kmsqid_t		*qp;		/* ptr to associated q */
	int			error, ii;
	struct	cred		*cr;
	model_t	mdl = get_udatamodel();
	struct msqid_ds64	ds64;
	kmutex_t		*lock;
	proc_t			*pp = curproc;

	STRUCT_INIT(ds, mdl);
	cr = CRED();

	/*
	 * Perform pre- or non-lookup actions (e.g. copyins, RMID).
	 */
	switch (cmd) {
	case IPC_SET:
		if (copyin(arg, STRUCT_BUF(ds), STRUCT_SIZE(ds)))
			return (set_errno(EFAULT));
		break;

	case IPC_SET64:
		if (copyin(arg, &ds64, sizeof (struct msqid_ds64)))
			return (set_errno(EFAULT));
		break;

	case IPC_RMID:
		if (error = ipc_rmid(msq_svc, msgid, cr))
			return (set_errno(error));
		return (0);
	}

	/*
	 * get msqid_ds for this msgid
	 */
	if ((lock = ipc_lookup(msq_svc, msgid, (kipc_perm_t **)&qp)) == NULL)
		return (set_errno(EINVAL));

	switch (cmd) {
	case IPC_SET:
		if (STRUCT_FGET(ds, msg_qbytes) > qp->msg_qbytes &&
		    secpolicy_ipc_config(cr) != 0) {
			mutex_exit(lock);
			return (set_errno(EPERM));
		}
		if (error = ipcperm_set(msq_svc, cr, &qp->msg_perm,
		    &STRUCT_BUF(ds)->msg_perm, mdl)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		qp->msg_qbytes = STRUCT_FGET(ds, msg_qbytes);
		qp->msg_ctime = gethrestime_sec();
		break;

	case IPC_STAT:
		if (error = ipcperm_access(&qp->msg_perm, MSG_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}

		for (ii = 0; ii < MAX_QNUM_CV; ii++) {
			if (qp->msg_rcv_cnt[ii]) {
				qp->msg_perm.ipc_mode |= MSG_RWAIT;
				break;
			}
		}
		if (qp->msg_snd_cnt)
			qp->msg_perm.ipc_mode |= MSG_WWAIT;
		ipcperm_stat(&STRUCT_BUF(ds)->msg_perm, &qp->msg_perm, mdl);
		qp->msg_perm.ipc_mode &= ~(MSG_RWAIT|MSG_WWAIT);
		STRUCT_FSETP(ds, msg_first, NULL); 	/* kernel addr */
		STRUCT_FSETP(ds, msg_last, NULL);
		STRUCT_FSET(ds, msg_cbytes, qp->msg_cbytes);
		STRUCT_FSET(ds, msg_qnum, qp->msg_qnum);
		STRUCT_FSET(ds, msg_qbytes, qp->msg_qbytes);
		STRUCT_FSET(ds, msg_lspid, qp->msg_lspid);
		STRUCT_FSET(ds, msg_lrpid, qp->msg_lrpid);
		STRUCT_FSET(ds, msg_stime, qp->msg_stime);
		STRUCT_FSET(ds, msg_rtime, qp->msg_rtime);
		STRUCT_FSET(ds, msg_ctime, qp->msg_ctime);
		break;

	case IPC_SET64:
		mutex_enter(&pp->p_lock);
		if ((ds64.msgx_qbytes > qp->msg_qbytes) &&
		    secpolicy_ipc_config(cr) != 0 &&
		    rctl_test(rc_process_msgmnb, pp->p_rctls, pp,
		    ds64.msgx_qbytes, RCA_SAFE) & RCT_DENY) {
			mutex_exit(&pp->p_lock);
			mutex_exit(lock);
			return (set_errno(EPERM));
		}
		mutex_exit(&pp->p_lock);
		if (error = ipcperm_set64(msq_svc, cr, &qp->msg_perm,
		    &ds64.msgx_perm)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		qp->msg_qbytes = ds64.msgx_qbytes;
		qp->msg_ctime = gethrestime_sec();
		break;

	case IPC_STAT64:
		for (ii = 0; ii < MAX_QNUM_CV; ii++) {
			if (qp->msg_rcv_cnt[ii]) {
				qp->msg_perm.ipc_mode |= MSG_RWAIT;
				break;
			}
		}
		if (qp->msg_snd_cnt)
			qp->msg_perm.ipc_mode |= MSG_WWAIT;
		ipcperm_stat64(&ds64.msgx_perm, &qp->msg_perm);
		qp->msg_perm.ipc_mode &= ~(MSG_RWAIT|MSG_WWAIT);
		ds64.msgx_cbytes = qp->msg_cbytes;
		ds64.msgx_qnum = qp->msg_qnum;
		ds64.msgx_qbytes = qp->msg_qbytes;
		ds64.msgx_lspid = qp->msg_lspid;
		ds64.msgx_lrpid = qp->msg_lrpid;
		ds64.msgx_stime = qp->msg_stime;
		ds64.msgx_rtime = qp->msg_rtime;
		ds64.msgx_ctime = qp->msg_ctime;
		break;

	default:
		mutex_exit(lock);
		return (set_errno(EINVAL));
	}

	mutex_exit(lock);

	/*
	 * Do copyout last (after releasing mutex).
	 */
	switch (cmd) {
	case IPC_STAT:
		if (copyout(STRUCT_BUF(ds), arg, STRUCT_SIZE(ds)))
			return (set_errno(EFAULT));
		break;

	case IPC_STAT64:
		if (copyout(&ds64, arg, sizeof (struct msqid_ds64)))
			return (set_errno(EFAULT));
		break;
	}

	return (0);
}

/*
 * Remove all message queues associated with a given zone.  Called by
 * zone_shutdown when the zone is halted.
 */
/*ARGSUSED1*/
static void
msg_remove_zone(zoneid_t zoneid, void *arg)
{
	ipc_remove_zone(msq_svc, zoneid);
}

/*
 * msgget system call.
 */
static int
msgget(key_t key, int msgflg)
{
	kmsqid_t	*qp;
	kmutex_t	*lock;
	int		id, error;
	int		ii;
	proc_t		*pp = curproc;

top:
	if (error = ipc_get(msq_svc, key, msgflg, (kipc_perm_t **)&qp, &lock))
		return (set_errno(error));

	if (IPC_FREE(&qp->msg_perm)) {
		mutex_exit(lock);
		mutex_exit(&pp->p_lock);

		list_create(&qp->msg_list, sizeof (struct msg),
		    offsetof(struct msg, msg_node));
		qp->msg_qnum = 0;
		qp->msg_lspid = qp->msg_lrpid = 0;
		qp->msg_stime = qp->msg_rtime = 0;
		qp->msg_ctime = gethrestime_sec();
		for (ii = 0; ii < MAX_QNUM_CV; ii++)
			qp->msg_rcv_cnt[ii] = 0;
		qp->msg_snd_cnt = 0;

		if (error = ipc_commit_begin(msq_svc, key, msgflg,
		    (kipc_perm_t *)qp)) {
			if (error == EAGAIN)
				goto top;
			return (set_errno(error));
		}
		qp->msg_qbytes = rctl_enforced_value(rc_process_msgmnb,
		    pp->p_rctls, pp);
		qp->msg_qmax = rctl_enforced_value(rc_process_msgtql,
		    pp->p_rctls, pp);
		lock = ipc_commit_end(msq_svc, &qp->msg_perm);
	}
#ifdef C2_AUDIT
	if (audit_active)
		audit_ipcget(AT_IPC_MSG, (void *)qp);
#endif
	id = qp->msg_perm.ipc_id;
	mutex_exit(lock);
	return (id);
}

/*
 * msgrcv system call.
 */
static ssize_t
msgrcv(int msqid, struct ipcmsgbuf *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	struct msg	*mp;	/* ptr to msg on q */
	struct msg	*smp;	/* ptr to best msg on q */
	kmsqid_t	*qp;	/* ptr to associated q */
	kmutex_t	*lock;
	size_t		xtsz;	/* transfer byte count */
	int		error = 0, copyerror = 0;
	int		cvres;
	STRUCT_HANDLE(ipcmsgbuf, umsgp);
	model_t		mdl = get_udatamodel();

	CPU_STATS_ADDQ(CPU, sys, msg, 1);	/* bump msg send/rcv count */
	STRUCT_SET_HANDLE(umsgp, mdl, msgp);

	if ((lock = ipc_lookup(msq_svc, msqid, (kipc_perm_t **)&qp)) == NULL)
		return ((ssize_t)set_errno(EINVAL));
	ipc_hold(msq_svc, (kipc_perm_t *)qp);

	if (error = ipcperm_access(&qp->msg_perm, MSG_R, CRED()))
		goto msgrcv_out;

findmsg:
	smp = NULL;
	mp = list_head(&qp->msg_list);
	if (msgtyp == 0) {
		smp = mp;
	} else {
		for (; mp; mp = list_next(&qp->msg_list, mp)) {
			if (msgtyp > 0) {
				if (msgtyp != mp->msg_type)
					continue;
				smp = mp;
				break;
			}
			if (mp->msg_type <= -msgtyp) {
				if (smp && smp->msg_type <= mp->msg_type)
					continue;
				smp = mp;
			}
		}
	}

	if (smp) {
		/*
		 * Message found.
		 */
		if ((smp->msg_flags & MSG_RCVCOPY) == 0) {
			/*
			 * No one else is copying this message. Copy it.
			 */
			if (msgsz < smp->msg_size) {
				if ((msgflg & MSG_NOERROR) == 0) {
					error = E2BIG;
					goto msgrcv_out;
				} else {
					xtsz = msgsz;
				}
			} else {
				xtsz = smp->msg_size;
			}

			/*
			 * Mark message as being copied out. Release mutex
			 * while copying out.
			 */
			ASSERT((smp->msg_flags & MSG_RCVCOPY) == 0);
			smp->msg_flags |= MSG_RCVCOPY;
			msg_hold(smp);
			mutex_exit(lock);

			if (mdl == DATAMODEL_NATIVE) {
				copyerror = copyout(&smp->msg_type, msgp,
				    sizeof (smp->msg_type));
			} else {
				/*
				 * 32-bit callers need an imploded msg type.
				 */
				int32_t	msg_type32 = smp->msg_type;

				copyerror = copyout(&msg_type32, msgp,
				    sizeof (msg_type32));
			}

			if (copyerror == 0 && xtsz)
				copyerror = copyout(smp->msg_addr,
				    STRUCT_FADDR(umsgp, mtext), xtsz);

			/*
			 * Reclaim mutex, make sure queue still exists,
			 * and remove message.
			 */
			lock = ipc_lock(msq_svc, qp->msg_perm.ipc_id);
			ASSERT(smp->msg_flags & MSG_RCVCOPY);
			smp->msg_flags &= ~MSG_RCVCOPY;
			msg_rele(smp);

			if (IPC_FREE(&qp->msg_perm)) {
				error = EIDRM;
				goto msgrcv_out;
			}
			/*
			 * MSG_RCVCOPY was set while we dropped and reaquired
			 * the lock. A thread looking for same message type
			 * might have entered during that interval and seeing
			 * MSG_RCVCOPY set, would have landed up in the sleepq.
			 */
			cv_broadcast(&qp->msg_rcv_cv[MSG_QNUM(smp->msg_type)]);
			cv_broadcast(&qp->msg_rcv_cv[0]);

			if (copyerror) {
				error = EFAULT;
				goto msgrcv_out;
			}
			qp->msg_lrpid = ttoproc(curthread)->p_pid;
			qp->msg_rtime = gethrestime_sec();
			msgunlink(qp, smp);
			goto msgrcv_out;
		}

	} else {
		/*
		 * No message found.
		 */
		if (msgflg & IPC_NOWAIT) {
			error = ENOMSG;
			goto msgrcv_out;
		}
	}

	/* Wait for new message */
	qp->msg_rcv_cnt[MSG_QNUM(msgtyp)]++;
	cvres = cv_wait_sig(&qp->msg_rcv_cv[MSG_QNUM(msgtyp)], lock);
	lock = ipc_relock(msq_svc, qp->msg_perm.ipc_id, lock);
	qp->msg_rcv_cnt[MSG_QNUM(msgtyp)]--;

	if (IPC_FREE(&qp->msg_perm)) {
		error = EIDRM;
		goto msgrcv_out;
	}
	if (cvres == 0) {
		error = EINTR;
		goto msgrcv_out;
	}

	goto findmsg;

msgrcv_out:
	ipc_rele(msq_svc, (kipc_perm_t *)qp);
	if (error)
		return ((ssize_t)set_errno(error));
	return ((ssize_t)xtsz);
}

/*
 * msgids system call.
 */
static int
msgids(int *buf, uint_t nids, uint_t *pnids)
{
	int error;

	if (error = ipc_ids(msq_svc, buf, nids, pnids))
		return (set_errno(error));

	return (0);
}

#define	RND(x)		roundup((x), sizeof (size_t))
#define	RND32(x)	roundup((x), sizeof (size32_t))

/*
 * msgsnap system call.
 */
static int
msgsnap(int msqid, caddr_t buf, size_t bufsz, long msgtyp)
{
	struct msg	*mp;	/* ptr to msg on q */
	kmsqid_t	*qp;	/* ptr to associated q */
	kmutex_t	*lock;
	size_t		size;
	size_t		nmsg;
	struct msg	**snaplist;
	int		error, i;
	model_t		mdl = get_udatamodel();
	STRUCT_DECL(msgsnap_head, head);
	STRUCT_DECL(msgsnap_mhead, mhead);

	STRUCT_INIT(head, mdl);
	STRUCT_INIT(mhead, mdl);

	if (bufsz < STRUCT_SIZE(head))
		return (set_errno(EINVAL));

	if ((lock = ipc_lookup(msq_svc, msqid, (kipc_perm_t **)&qp)) == NULL)
		return (set_errno(EINVAL));

	if (error = ipcperm_access(&qp->msg_perm, MSG_R, CRED())) {
		mutex_exit(lock);
		return (set_errno(error));
	}
	ipc_hold(msq_svc, (kipc_perm_t *)qp);

	/*
	 * First compute the required buffer size and
	 * the number of messages on the queue.
	 */
	size = nmsg = 0;
	for (mp = list_head(&qp->msg_list); mp;
	    mp = list_next(&qp->msg_list, mp)) {
		if (msgtyp == 0 ||
		    (msgtyp > 0 && msgtyp == mp->msg_type) ||
		    (msgtyp < 0 && mp->msg_type <= -msgtyp)) {
			nmsg++;
			if (mdl == DATAMODEL_NATIVE)
				size += RND(mp->msg_size);
			else
				size += RND32(mp->msg_size);
		}
	}

	size += STRUCT_SIZE(head) + nmsg * STRUCT_SIZE(mhead);
	if (size > bufsz)
		nmsg = 0;

	if (nmsg > 0) {
		/*
		 * Mark the messages as being copied.
		 */
		snaplist = (struct msg **)kmem_alloc(nmsg *
		    sizeof (struct msg *), KM_SLEEP);
		i = 0;
		for (mp = list_head(&qp->msg_list); mp;
		    mp = list_next(&qp->msg_list, mp)) {
			if (msgtyp == 0 ||
			    (msgtyp > 0 && msgtyp == mp->msg_type) ||
			    (msgtyp < 0 && mp->msg_type <= -msgtyp)) {
				msg_hold(mp);
				snaplist[i] = mp;
				i++;
			}
		}
	}
	mutex_exit(lock);

	/*
	 * Copy out the buffer header.
	 */
	STRUCT_FSET(head, msgsnap_size, size);
	STRUCT_FSET(head, msgsnap_nmsg, nmsg);
	if (copyout(STRUCT_BUF(head), buf, STRUCT_SIZE(head)))
		error = EFAULT;

	buf += STRUCT_SIZE(head);

	/*
	 * Now copy out the messages one by one.
	 */
	for (i = 0; i < nmsg; i++) {
		mp = snaplist[i];
		if (error == 0) {
			STRUCT_FSET(mhead, msgsnap_mlen, mp->msg_size);
			STRUCT_FSET(mhead, msgsnap_mtype, mp->msg_type);
			if (copyout(STRUCT_BUF(mhead), buf, STRUCT_SIZE(mhead)))
				error = EFAULT;
			buf += STRUCT_SIZE(mhead);

			if (error == 0 &&
			    mp->msg_size != 0 &&
			    copyout(mp->msg_addr, buf, mp->msg_size))
				error = EFAULT;
			if (mdl == DATAMODEL_NATIVE)
				buf += RND(mp->msg_size);
			else
				buf += RND32(mp->msg_size);
		}
		lock = ipc_lock(msq_svc, qp->msg_perm.ipc_id);
		msg_rele(mp);
		/* Check for msg q deleted or reallocated */
		if (IPC_FREE(&qp->msg_perm))
			error = EIDRM;
		mutex_exit(lock);
	}

	(void) ipc_lock(msq_svc, qp->msg_perm.ipc_id);
	ipc_rele(msq_svc, (kipc_perm_t *)qp);

	if (nmsg > 0)
		kmem_free(snaplist, nmsg * sizeof (struct msg *));

	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * msgsnd system call.
 */
static int
msgsnd(int msqid, struct ipcmsgbuf *msgp, size_t msgsz, int msgflg)
{
	kmsqid_t	*qp;
	kmutex_t	*lock;
	struct msg	*mp = NULL;
	long		type;
	int		error = 0;
	model_t		mdl = get_udatamodel();
	STRUCT_HANDLE(ipcmsgbuf, umsgp);

	CPU_STATS_ADDQ(CPU, sys, msg, 1);	/* bump msg send/rcv count */
	STRUCT_SET_HANDLE(umsgp, mdl, msgp);

	if (mdl == DATAMODEL_NATIVE) {
		if (copyin(msgp, &type, sizeof (type)))
			return (set_errno(EFAULT));
	} else {
		int32_t	type32;
		if (copyin(msgp, &type32, sizeof (type32)))
			return (set_errno(EFAULT));
		type = type32;
	}

	if (type < 1)
		return (set_errno(EINVAL));

	if ((lock = ipc_lookup(msq_svc, msqid, (kipc_perm_t **)&qp)) == NULL)
		return (set_errno(EINVAL));
	ipc_hold(msq_svc, (kipc_perm_t *)qp);

	if (msgsz > qp->msg_qbytes) {
		error = EINVAL;
		goto msgsnd_out;
	}

	if (error = ipcperm_access(&qp->msg_perm, MSG_W, CRED()))
		goto msgsnd_out;

top:
	/*
	 * Allocate space on q, message header, & buffer space.
	 */
	ASSERT(qp->msg_qnum <= qp->msg_qmax);
	while ((msgsz > qp->msg_qbytes - qp->msg_cbytes) ||
	    (qp->msg_qnum == qp->msg_qmax)) {
		int cvres;

		if (msgflg & IPC_NOWAIT) {
			error = EAGAIN;
			goto msgsnd_out;
		}

		qp->msg_snd_cnt++;
		cvres = cv_wait_sig(&qp->msg_snd_cv, lock);
		lock = ipc_relock(msq_svc, qp->msg_perm.ipc_id, lock);
		qp->msg_snd_cnt--;

		if (IPC_FREE(&qp->msg_perm)) {
			error = EIDRM;
			goto msgsnd_out;
		}

		if (cvres == 0) {
			error = EINTR;
			goto msgsnd_out;
		}
	}

	if (mp == NULL) {
		int failure;

		mutex_exit(lock);
		mp = kmem_zalloc(sizeof (struct msg), KM_SLEEP);
		mp->msg_addr = kmem_zalloc(msgsz, KM_SLEEP);
		mp->msg_size = msgsz;
		mp->msg_copycnt = 1;

		failure = msgsz && (copyin(STRUCT_FADDR(umsgp, mtext),
		    mp->msg_addr, msgsz) == -1);
		lock = ipc_lock(msq_svc, qp->msg_perm.ipc_id);
		if (IPC_FREE(&qp->msg_perm)) {
			error = EIDRM;
			goto msgsnd_out;
		}
		if (failure) {
			error = EFAULT;
			goto msgsnd_out;
		}
		goto top;
	}

	/*
	 * Everything is available, put msg on q.
	 */
	qp->msg_qnum++;
	qp->msg_cbytes += msgsz;
	qp->msg_lspid = curproc->p_pid;
	qp->msg_stime = gethrestime_sec();
	mp->msg_type = type;
	mp->msg_flags = 0;
	list_insert_tail(&qp->msg_list, mp);
	/*
	 * For all message type >= 1.
	 */
	if (qp->msg_rcv_cnt[MSG_QNUM(type)])
		cv_broadcast(&qp->msg_rcv_cv[MSG_QNUM(type)]);
	/*
	 * For all message type < 1.
	 */
	if (qp->msg_rcv_cnt[0])
		cv_broadcast(&qp->msg_rcv_cv[0]);

msgsnd_out:
	ipc_rele(msq_svc, (kipc_perm_t *)qp);	/* drops lock */

	if (error) {
		if (mp)
			msg_rele(mp);
		return (set_errno(error));
	}

	return (0);
}

/*
 * msgsys - System entry point for msgctl, msgget, msgrcv, and msgsnd
 * system calls.
 */
static ssize_t
msgsys(int opcode, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	ssize_t error;

	switch (opcode) {
	case MSGGET:
		error = msgget((key_t)a1, (int)a2);
		break;
	case MSGCTL:
		error = msgctl((int)a1, (int)a2, (void *)a3);
		break;
	case MSGRCV:
		error = msgrcv((int)a1, (struct ipcmsgbuf *)a2,
		    (size_t)a3, (long)a4, (int)a5);
		break;
	case MSGSND:
		error = msgsnd((int)a1, (struct ipcmsgbuf *)a2,
		    (size_t)a3, (int)a4);
		break;
	case MSGIDS:
		error = msgids((int *)a1, (uint_t)a2, (uint_t *)a3);
		break;
	case MSGSNAP:
		error = msgsnap((int)a1, (caddr_t)a2, (size_t)a3, (long)a4);
		break;
	default:
		error = set_errno(EINVAL);
		break;
	}

	return (error);
}

#ifdef	_SYSCALL32_IMPL
/*
 * msgsys32 - System entry point for msgctl, msgget, msgrcv, and msgsnd
 * system calls for 32-bit callers on LP64 kernel.
 */
static ssize32_t
msgsys32(int opcode, uint32_t a1, uint32_t a2, uint32_t a3,
	uint32_t a4, uint32_t a5)
{
	ssize_t error;

	switch (opcode) {
	case MSGGET:
		error = msgget((key_t)a1, (int)a2);
		break;
	case MSGCTL:
		error = msgctl((int)a1, (int)a2, (void *)(uintptr_t)a3);
		break;
	case MSGRCV:
		error = msgrcv((int)a1, (struct ipcmsgbuf *)(uintptr_t)a2,
		    (size_t)a3, (long)(int32_t)a4, (int)a5);
		break;
	case MSGSND:
		error = msgsnd((int)a1, (struct ipcmsgbuf *)(uintptr_t)a2,
		    (size_t)(int32_t)a3, (int)a4);
		break;
	case MSGIDS:
		error = msgids((int *)(uintptr_t)a1, (uint_t)a2,
		    (uint_t *)(uintptr_t)a3);
		break;
	case MSGSNAP:
		error = msgsnap((int)a1, (caddr_t)(uintptr_t)a2, (size_t)a3,
		    (long)(int32_t)a4);
		break;
	default:
		error = set_errno(EINVAL);
		break;
	}

	return (error);
}
#endif	/* SYSCALL32_IMPL */
