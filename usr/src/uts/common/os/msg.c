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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Inter-Process Communication Message Facility.
 *
 * See os/ipc.c for a description of common IPC functionality.
 *
 * Resource controls
 * -----------------
 *
 * Control:      zone.max-msg-ids (rc_zone_msgmni)
 * Description:  Maximum number of message queue ids allowed a zone.
 *
 *   When msgget() is used to allocate a message queue, one id is
 *   allocated.  If the id allocation doesn't succeed, msgget() fails
 *   and errno is set to ENOSPC.  Upon successful msgctl(, IPC_RMID)
 *   the id is deallocated.
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

extern rctl_hndl_t rc_zone_msgmni;
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

/*
 *      Big Theory statement for message queue correctness
 *
 * The msgrcv and msgsnd functions no longer uses cv_broadcast to wake up
 * receivers who are waiting for an event.  Using the cv_broadcast method
 * resulted in negative scaling when the number of waiting receivers are large
 * (the thundering herd problem).  Instead, the receivers waiting to receive a
 * message are now linked in a queue-like fashion and awaken one at a time in
 * a controlled manner.
 *
 * Receivers can block on two different classes of waiting list:
 *    1) "sendwait" list, which is the more complex list of the two.  The
 *	  receiver will be awakened by a sender posting a new message.  There
 *	  are two types of "sendwait" list used:
 *		a) msg_wait_snd: handles all receivers who are looking for
 *		   a message type >= 0, but was unable to locate a match.
 *
 *		   slot 0: reserved for receivers that have designated they
 *			   will take any message type.
 *		   rest:   consist of receivers requesting a specific type
 *			   but the type was not present.  The entries are
 *			   hashed into a bucket in an attempt to keep
 *			   any list search relatively short.
 * 		b) msg_wait_snd_ngt: handles all receivers that have designated
 *		   a negative message type. Unlike msg_wait_snd, the hash bucket
 *		   serves a range of negative message types (-1 to -5, -6 to -10
 *		   and so forth), where the last bucket is reserved for all the
 *		   negative message types that hash outside of MSG_MAX_QNUM - 1.
 *		   This is done this way to simplify the operation of locating a
 *		   negative message type.
 *
 *    2) "copyout" list, where the receiver is awakened by another
 *	 receiver after a message is copied out.  This is a linked list
 *	 of waiters that are awakened one at a time.  Although the solution is
 *	 not optimal, the complexity that would be added in for waking
 *	 up the right entry far exceeds any potential pay back (too many
 *	 correctness and corner case issues).
 *
 * The lists are doubly linked.  In the case of the "sendwait"
 * list, this allows the thread to remove itself from the list without having
 * to traverse the list.  In the case of the "copyout" list it simply allows
 * us to use common functions with the "sendwait" list.
 *
 * To make sure receivers are not hung out to dry, we must guarantee:
 *    1. If any queued message matches any receiver, then at least one
 *       matching receiver must be processing the request.
 *    2. Blocking on the copyout queue is only temporary while messages
 *	 are being copied out.  The process is guaranted to wakeup
 *	 when it gets to front of the queue (copyout is a FIFO).
 *
 * Rules for blocking and waking up:
 *   1. A receiver entering msgrcv must examine all messages for a match
 *      before blocking on a sendwait queue.
 *   2. If the receiver blocks because the message it chose is already
 *	being copied out, then when it wakes up needs to start start
 *	checking the messages from the beginning.
 *   3) When ever a process returns from msgrcv for any reason, if it
 *	had attempted to copy a message or blocked waiting for a copy
 *	to complete it needs to wakeup the next receiver blocked on
 *	a copy out.
 *   4) When a message is sent, the sender selects a process waiting
 *	for that type of message.  This selection process rotates between
 *	receivers types of 0, negative and positive to prevent starvation of
 *	any one particular receiver type.
 *   5) The following are the scenarios for processes that are awakened
 *	by a msgsnd:
 *		a) The process finds the message and is able to copy
 *		   it out.  Once complete, the process returns.
 *		b) The message that was sent that triggered the wakeup is no
 *		   longer available (another process found the message first).
 *		   We issue a wakeup on copy queue and then go back to
 *		   sleep waiting for another matching message to be sent.
 *		c) The message that was supposed to be processed was
 *		   already serviced by another process.  However a different
 *		   message is present which we can service.  The message
 *		   is copied and the process returns.
 *		d) The message is found, but some sort of error occurs that
 *		   prevents the message from being copied.  The receiver
 *		   wakes up the next sender that can service this message
 *		   type and returns an error to the caller.
 *		e) The message is found, but it is marked as being copied
 *		   out.  The receiver then goes to sleep on the copyout
 *		   queue where it will be awakened again sometime in the future.
 *
 *
 *   6) Whenever a message is found that matches the message type designated,
 * 	but is being copied out we have to block on the copyout queue.
 *	After process copying finishes the copy out, it  must wakeup (either
 *	directly or indirectly) all receivers who blocked on its copyout,
 *	so they are guaranteed a chance to examine the remaining messages.
 *	This is implemented via a chain of wakeups: Y wakes X, who wakes Z,
 *	and so on.  The chain cannot be broken.  This leads to the following
 *	cases:
 *		a) A receiver is finished copying the message (or encountered)
 *		   an error), the first entry on the copyout queue is woken
 *		   up.
 *		b) When the receiver is woken up, it attempts to locate
 *		   a message type match.
 *		c) If a message type is found and
 *			-- MSG_RCVCOPY flag is not set, the message is
 *			   marked for copying out.  Regardless of the copyout
 *			   success the next entry on the copyout queue is
 *			   awakened and the operation is completed.
 *			-- MSG_RCVCOPY is set, we simply go back to sleep again
 *			   on the copyout queue.
 *		d) If the message type is not found then we wakeup the next
 *		   process on the copyout queue.
 *   7) If a msgsnd is unable to complete for of any of the following reasons
 *	  a) the msgq has no space for the message
 *	  b) the maximum number of messages allowed has been reached
 *      then one of two things happen:
 *	  1) If the passed in msg_flag has IPC_NOWAIT set, then
 *	     an error is returned.
 *	  2) The IPC_NOWAIT bit is not set in msg_flag, then the
 *	     the thread is placed to sleep until the request can be
 *	     serviced.
 *   8) When waking a thread waiting to send a message, a check is done to
 *      verify that the operation being asked for by the thread will complete.
 *      This decision making process is done in a loop where the oldest request
 *      is checked first. The search will continue until there is no more
 *	room on the msgq or we have checked all the waiters.
 */

static uint_t msg_type_hash(long);
static int msgq_check_err(kmsqid_t *qp, int cvres);
static int msg_rcvq_sleep(list_t *, msgq_wakeup_t *, kmutex_t **,
    kmsqid_t *);
static int msg_copyout(kmsqid_t *, long, kmutex_t **, size_t *, size_t,
    struct msg *, struct ipcmsgbuf *, int);
static void msg_rcvq_wakeup_all(list_t *);
static void msg_wakeup_senders(kmsqid_t *);
static void msg_wakeup_rdr(kmsqid_t *, msg_select_t **, long);
static msgq_wakeup_t *msg_fnd_any_snd(kmsqid_t *, int, long);
static msgq_wakeup_t *msg_fnd_any_rdr(kmsqid_t *, int, long);
static msgq_wakeup_t *msg_fnd_neg_snd(kmsqid_t *, int, long);
static msgq_wakeup_t *msg_fnd_spc_snd(kmsqid_t *, int, long);
static struct msg *msgrcv_lookup(kmsqid_t *, long);

msg_select_t msg_fnd_sndr[] = {
	{ msg_fnd_any_snd, &msg_fnd_sndr[1] },
	{ msg_fnd_spc_snd, &msg_fnd_sndr[2] },
	{ msg_fnd_neg_snd, &msg_fnd_sndr[0] }
};

msg_select_t msg_fnd_rdr[1] = {
	{ msg_fnd_any_rdr, &msg_fnd_rdr[0] },
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

#define	MSG_SMALL_INIT (size_t)-1
int
_init(void)
{
	int result;

	msq_svc = ipcs_create("msqids", rc_project_msgmni, rc_zone_msgmni,
	    sizeof (kmsqid_t), msg_dtor, msg_rmid, AT_IPC_MSG,
	    offsetof(ipc_rqty_t, ipcq_msgmni));
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

	for (ii = 0; ii <= MSG_MAX_QNUM; ii++) {
		ASSERT(list_is_empty(&qp->msg_wait_snd[ii]));
		ASSERT(list_is_empty(&qp->msg_wait_snd_ngt[ii]));
		list_destroy(&qp->msg_wait_snd[ii]);
		list_destroy(&qp->msg_wait_snd_ngt[ii]);
	}
	ASSERT(list_is_empty(&qp->msg_cpy_block));
	ASSERT(list_is_empty(&qp->msg_wait_rcv));
	list_destroy(&qp->msg_cpy_block);
	ASSERT(qp->msg_snd_cnt == 0);
	ASSERT(qp->msg_cbytes == 0);
	list_destroy(&qp->msg_list);
	list_destroy(&qp->msg_wait_rcv);
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
	msg_wakeup_senders(qp);
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

	/*
	 * Wake up everyone who is in a wait state of some sort
	 * for this message queue.
	 */
	for (ii = 0; ii <= MSG_MAX_QNUM; ii++) {
		msg_rcvq_wakeup_all(&qp->msg_wait_snd[ii]);
		msg_rcvq_wakeup_all(&qp->msg_wait_snd_ngt[ii]);
	}
	msg_rcvq_wakeup_all(&qp->msg_cpy_block);
	msg_rcvq_wakeup_all(&qp->msg_wait_rcv);
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
	int			error;
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

		if (qp->msg_rcv_cnt)
			qp->msg_perm.ipc_mode |= MSG_RWAIT;
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
		if (qp->msg_rcv_cnt)
			qp->msg_perm.ipc_mode |= MSG_RWAIT;
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
		qp->msg_ngt_cnt = 0;
		qp->msg_neg_copy = 0;
		for (ii = 0; ii <= MSG_MAX_QNUM; ii++) {
			list_create(&qp->msg_wait_snd[ii],
			    sizeof (msgq_wakeup_t),
			    offsetof(msgq_wakeup_t, msgw_list));
			list_create(&qp->msg_wait_snd_ngt[ii],
			    sizeof (msgq_wakeup_t),
			    offsetof(msgq_wakeup_t, msgw_list));
		}
		/*
		 * The proper initialization of msg_lowest_type is to the
		 * highest possible value.  By doing this we guarantee that
		 * when the first send happens, the lowest type will be set
		 * properly.
		 */
		qp->msg_lowest_type = MSG_SMALL_INIT;
		list_create(&qp->msg_cpy_block,
		    sizeof (msgq_wakeup_t),
		    offsetof(msgq_wakeup_t, msgw_list));
		list_create(&qp->msg_wait_rcv,
		    sizeof (msgq_wakeup_t),
		    offsetof(msgq_wakeup_t, msgw_list));
		qp->msg_fnd_sndr = &msg_fnd_sndr[0];
		qp->msg_fnd_rdr = &msg_fnd_rdr[0];
		qp->msg_rcv_cnt = 0;
		qp->msg_snd_cnt = 0;
		qp->msg_snd_smallest = MSG_SMALL_INIT;

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

	if (AU_AUDITING())
		audit_ipcget(AT_IPC_MSG, (void *)qp);

	id = qp->msg_perm.ipc_id;
	mutex_exit(lock);
	return (id);
}

static ssize_t
msgrcv(int msqid, struct ipcmsgbuf *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	struct msg	*smp;	/* ptr to best msg on q */
	kmsqid_t	*qp;	/* ptr to associated q */
	kmutex_t	*lock;
	size_t		xtsz;	/* transfer byte count */
	int		error = 0;
	int		cvres;
	uint_t		msg_hash;
	msgq_wakeup_t	msg_entry;

	CPU_STATS_ADDQ(CPU, sys, msg, 1);	/* bump msg send/rcv count */

	msg_hash = msg_type_hash(msgtyp);
	if ((lock = ipc_lookup(msq_svc, msqid, (kipc_perm_t **)&qp)) == NULL) {
		return ((ssize_t)set_errno(EINVAL));
	}
	ipc_hold(msq_svc, (kipc_perm_t *)qp);

	if (error = ipcperm_access(&qp->msg_perm, MSG_R, CRED())) {
		goto msgrcv_out;
	}

	/*
	 * Various information (including the condvar_t) required for the
	 * process to sleep is provided by it's stack.
	 */
	msg_entry.msgw_thrd = curthread;
	msg_entry.msgw_snd_wake = 0;
	msg_entry.msgw_type = msgtyp;
findmsg:
	smp = msgrcv_lookup(qp, msgtyp);

	if (smp) {
		/*
		 * We found a possible message to copy out.
		 */
		if ((smp->msg_flags & MSG_RCVCOPY) == 0) {
			long t = msg_entry.msgw_snd_wake;
			long copy_type = smp->msg_type;

			/*
			 * It is available, attempt to copy it.
			 */
			error = msg_copyout(qp, msgtyp, &lock, &xtsz, msgsz,
			    smp, msgp, msgflg);

			/*
			 * It is possible to consume a different message
			 * type then what originally awakened for (negative
			 * types).  If this happens a check must be done to
			 * to determine if another receiver is available
			 * for the waking message type,  Failure to do this
			 * can result in a message on the queue that can be
			 * serviced by a sleeping receiver.
			 */
			if (!error && t && (copy_type != t))
				msg_wakeup_rdr(qp, &qp->msg_fnd_sndr, t);

			/*
			 * Don't forget to wakeup a sleeper that blocked because
			 * we were copying things out.
			 */
			msg_wakeup_rdr(qp, &qp->msg_fnd_rdr, 0);
			goto msgrcv_out;
		}
		/*
		 * The selected message is being copied out, so block.  We do
		 * not need to wake the next person up on the msg_cpy_block list
		 * due to the fact some one is copying out and they will get
		 * things moving again once the copy is completed.
		 */
		cvres = msg_rcvq_sleep(&qp->msg_cpy_block,
		    &msg_entry, &lock, qp);
		error = msgq_check_err(qp, cvres);
		if (error) {
			goto msgrcv_out;
		}
		goto findmsg;
	}
	/*
	 * There isn't a message to copy out that matches the designated
	 * criteria.
	 */
	if (msgflg & IPC_NOWAIT) {
		error = ENOMSG;
		goto msgrcv_out;
	}
	msg_wakeup_rdr(qp,  &qp->msg_fnd_rdr, 0);

	/*
	 * Wait for new message.  We keep the negative and positive types
	 * separate for performance reasons.
	 */
	msg_entry.msgw_snd_wake = 0;
	if (msgtyp >= 0) {
		cvres = msg_rcvq_sleep(&qp->msg_wait_snd[msg_hash],
		    &msg_entry, &lock, qp);
	} else {
		qp->msg_ngt_cnt++;
		cvres = msg_rcvq_sleep(&qp->msg_wait_snd_ngt[msg_hash],
		    &msg_entry, &lock, qp);
		qp->msg_ngt_cnt--;
	}

	if (!(error = msgq_check_err(qp, cvres))) {
		goto findmsg;
	}

msgrcv_out:
	if (error) {
		msg_wakeup_rdr(qp,  &qp->msg_fnd_rdr, 0);
		if (msg_entry.msgw_snd_wake) {
			msg_wakeup_rdr(qp, &qp->msg_fnd_sndr,
			    msg_entry.msgw_snd_wake);
		}
		ipc_rele(msq_svc, (kipc_perm_t *)qp);
		return ((ssize_t)set_errno(error));
	}
	ipc_rele(msq_svc, (kipc_perm_t *)qp);
	return ((ssize_t)xtsz);
}

static int
msgq_check_err(kmsqid_t *qp, int cvres)
{
	if (IPC_FREE(&qp->msg_perm)) {
		return (EIDRM);
	}

	if (cvres == 0) {
		return (EINTR);
	}

	return (0);
}

static int
msg_copyout(kmsqid_t *qp, long msgtyp, kmutex_t **lock, size_t *xtsz_ret,
    size_t msgsz, struct msg *smp, struct ipcmsgbuf *msgp, int msgflg)
{
	size_t		xtsz;
	STRUCT_HANDLE(ipcmsgbuf, umsgp);
	model_t		mdl = get_udatamodel();
	int		copyerror = 0;

	STRUCT_SET_HANDLE(umsgp, mdl, msgp);
	if (msgsz < smp->msg_size) {
		if ((msgflg & MSG_NOERROR) == 0) {
			return (E2BIG);
		} else {
			xtsz = msgsz;
		}
	} else {
		xtsz = smp->msg_size;
	}
	*xtsz_ret = xtsz;

	/*
	 * To prevent a DOS attack we mark the message as being
	 * copied out and release mutex.  When the copy is completed
	 * we need to acquire the mutex and make the appropriate updates.
	 */
	ASSERT((smp->msg_flags & MSG_RCVCOPY) == 0);
	smp->msg_flags |= MSG_RCVCOPY;
	msg_hold(smp);
	if (msgtyp < 0) {
		ASSERT(qp->msg_neg_copy == 0);
		qp->msg_neg_copy = 1;
	}
	mutex_exit(*lock);

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

	if (copyerror == 0 && xtsz) {
		copyerror = copyout(smp->msg_addr,
		    STRUCT_FADDR(umsgp, mtext), xtsz);
	}

	/*
	 * Reclaim the mutex and make sure the message queue still exists.
	 */

	*lock = ipc_lock(msq_svc, qp->msg_perm.ipc_id);
	if (msgtyp < 0) {
		qp->msg_neg_copy = 0;
	}
	ASSERT(smp->msg_flags & MSG_RCVCOPY);
	smp->msg_flags &= ~MSG_RCVCOPY;
	msg_rele(smp);
	if (IPC_FREE(&qp->msg_perm)) {
		return (EIDRM);
	}
	if (copyerror) {
		return (EFAULT);
	}
	qp->msg_lrpid = ttoproc(curthread)->p_pid;
	qp->msg_rtime = gethrestime_sec();
	msgunlink(qp, smp);
	return (0);
}

static struct msg *
msgrcv_lookup(kmsqid_t *qp, long msgtyp)
{
	struct msg 		*smp = NULL;
	long			qp_low;
	struct msg		*mp;	/* ptr to msg on q */
	long			low_msgtype;
	static struct msg	neg_copy_smp;

	mp = list_head(&qp->msg_list);
	if (msgtyp == 0) {
		smp = mp;
	} else {
		qp_low = qp->msg_lowest_type;
		if (msgtyp > 0) {
			/*
			 * If our lowest possible message type is larger than
			 * the message type desired, then we know there is
			 * no entry present.
			 */
			if (qp_low > msgtyp) {
				return (NULL);
			}

			for (; mp; mp = list_next(&qp->msg_list, mp)) {
				if (msgtyp == mp->msg_type) {
					smp = mp;
					break;
				}
			}
		} else {
			/*
			 * We have kept track of the lowest possible message
			 * type on the send queue.  This allows us to terminate
			 * the search early if we find a message type of that
			 * type.  Note, the lowest type may not be the actual
			 * lowest value in the system, it is only guaranteed
			 * that there isn't a value lower than that.
			 */
			low_msgtype = -msgtyp;
			if (low_msgtype < qp_low) {
				return (NULL);
			}
			if (qp->msg_neg_copy) {
				neg_copy_smp.msg_flags = MSG_RCVCOPY;
				return (&neg_copy_smp);
			}
			for (; mp; mp = list_next(&qp->msg_list, mp)) {
				if (mp->msg_type <= low_msgtype &&
				    !(smp && smp->msg_type <= mp->msg_type)) {
					smp = mp;
					low_msgtype = mp->msg_type;
					if (low_msgtype == qp_low) {
						break;
					}
				}
			}
			if (smp) {
				/*
				 * Update the lowest message type.
				 */
				qp->msg_lowest_type = smp->msg_type;
			}
		}
	}
	return (smp);
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

#define	MSG_PREALLOC_LIMIT 8192

/*
 * msgsnd system call.
 */
static int
msgsnd(int msqid, struct ipcmsgbuf *msgp, size_t msgsz, int msgflg)
{
	kmsqid_t	*qp;
	kmutex_t	*lock = NULL;
	struct msg	*mp = NULL;
	long		type;
	int		error = 0, wait_wakeup = 0;
	msgq_wakeup_t   msg_entry;
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

	/*
	 * We want the value here large enough that most of the
	 * the message operations will use the "lockless" path,
	 * but small enough that a user can not reserve large
	 * chunks of kernel memory unless they have a valid
	 * reason to.
	 */
	if (msgsz <= MSG_PREALLOC_LIMIT) {
		/*
		 * We are small enough that we can afford to do the
		 * allocation now.  This saves dropping the lock
		 * and then reacquiring the lock.
		 */
		mp = kmem_zalloc(sizeof (struct msg), KM_SLEEP);
		mp->msg_copycnt = 1;
		mp->msg_size = msgsz;
		if (msgsz) {
			mp->msg_addr = kmem_alloc(msgsz, KM_SLEEP);
			if (copyin(STRUCT_FADDR(umsgp, mtext),
			    mp->msg_addr, msgsz) == -1) {
				error = EFAULT;
				goto msgsnd_out;
			}
		}
	}

	if ((lock = ipc_lookup(msq_svc, msqid, (kipc_perm_t **)&qp)) == NULL) {
		error = EINVAL;
		goto msgsnd_out;
	}

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

		wait_wakeup = 0;
		qp->msg_snd_cnt++;
		msg_entry.msgw_snd_size = msgsz;
		msg_entry.msgw_thrd = curthread;
		msg_entry.msgw_type = type;
		cv_init(&msg_entry.msgw_wake_cv, NULL, 0, NULL);
		list_insert_tail(&qp->msg_wait_rcv, &msg_entry);
		if (qp->msg_snd_smallest > msgsz)
			qp->msg_snd_smallest = msgsz;
		cvres = cv_wait_sig(&msg_entry.msgw_wake_cv, lock);
		lock = ipc_relock(msq_svc, qp->msg_perm.ipc_id, lock);
		qp->msg_snd_cnt--;
		if (list_link_active(&msg_entry.msgw_list))
			list_remove(&qp->msg_wait_rcv, &msg_entry);
		if (error = msgq_check_err(qp, cvres)) {
			goto msgsnd_out;
		}
		wait_wakeup = 1;
	}

	if (mp == NULL) {
		int failure;

		mutex_exit(lock);
		ASSERT(msgsz > 0);
		mp = kmem_zalloc(sizeof (struct msg), KM_SLEEP);
		mp->msg_addr = kmem_alloc(msgsz, KM_SLEEP);
		mp->msg_size = msgsz;
		mp->msg_copycnt = 1;

		failure = (copyin(STRUCT_FADDR(umsgp, mtext),
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
	if (qp->msg_lowest_type > type)
		qp->msg_lowest_type = type;
	list_insert_tail(&qp->msg_list, mp);
	/*
	 * Get the proper receiver going.
	 */
	msg_wakeup_rdr(qp, &qp->msg_fnd_sndr, type);

msgsnd_out:
	/*
	 * We were woken up from the send wait list, but an
	 * an error occured on placing the message onto the
	 * msg queue.  Given that, we need to do the wakeup
	 * dance again.
	 */

	if (wait_wakeup && error) {
		msg_wakeup_senders(qp);
	}
	if (lock)
		ipc_rele(msq_svc, (kipc_perm_t *)qp);	/* drops lock */

	if (error) {
		if (mp)
			msg_rele(mp);
		return (set_errno(error));
	}

	return (0);
}

static void
msg_wakeup_rdr(kmsqid_t *qp, msg_select_t **flist, long type)
{
	msg_select_t	*walker = *flist;
	msgq_wakeup_t	*wakeup;
	uint_t		msg_hash;

	msg_hash = msg_type_hash(type);

	do {
		wakeup = walker->selection(qp, msg_hash, type);
		walker = walker->next_selection;
	} while (!wakeup && walker != *flist);

	*flist = (*flist)->next_selection;
	if (wakeup) {
		if (type) {
			wakeup->msgw_snd_wake = type;
		}
		cv_signal(&wakeup->msgw_wake_cv);
	}
}

static uint_t
msg_type_hash(long msg_type)
{
	if (msg_type < 0) {
		long	hash = -msg_type / MSG_NEG_INTERVAL;
		/*
		 * Negative message types are hashed over an
		 * interval.  Any message type that hashes
		 * beyond MSG_MAX_QNUM is automatically placed
		 * in the last bucket.
		 */
		if (hash > MSG_MAX_QNUM)
			hash = MSG_MAX_QNUM;
		return (hash);
	}

	/*
	 * 0 or positive message type.  The first bucket is reserved for
	 * message receivers of type 0, the other buckets we hash into.
	 */
	if (msg_type)
		return (1 + (msg_type % MSG_MAX_QNUM));
	return (0);
}

/*
 * Routines to see if we have a receiver of type 0 either blocked waiting
 * for a message.  Simply return the first guy on the list.
 */

static msgq_wakeup_t *
/* ARGSUSED */
msg_fnd_any_snd(kmsqid_t *qp, int msg_hash, long type)
{
	msgq_wakeup_t	*walker;

	walker = list_head(&qp->msg_wait_snd[0]);

	if (walker)
		list_remove(&qp->msg_wait_snd[0], walker);
	return (walker);
}

static msgq_wakeup_t *
/* ARGSUSED */
msg_fnd_any_rdr(kmsqid_t *qp, int msg_hash, long type)
{
	msgq_wakeup_t	*walker;

	walker = list_head(&qp->msg_cpy_block);
	if (walker)
		list_remove(&qp->msg_cpy_block, walker);
	return (walker);
}

static msgq_wakeup_t *
msg_fnd_spc_snd(kmsqid_t *qp, int msg_hash, long type)
{
	msgq_wakeup_t	*walker;

	walker = list_head(&qp->msg_wait_snd[msg_hash]);

	while (walker && walker->msgw_type != type)
		walker = list_next(&qp->msg_wait_snd[msg_hash], walker);
	if (walker)
		list_remove(&qp->msg_wait_snd[msg_hash], walker);
	return (walker);
}

/* ARGSUSED */
static msgq_wakeup_t *
msg_fnd_neg_snd(kmsqid_t *qp, int msg_hash, long type)
{
	msgq_wakeup_t	*qptr;
	int		count;
	int		check_index;
	int		neg_index;
	int		nbuckets;

	if (!qp->msg_ngt_cnt) {
		return (NULL);
	}
	neg_index = msg_type_hash(-type);

	/*
	 * Check for a match among the negative type queues.  Any buckets
	 * at neg_index or larger can match the type.  Use the last send
	 * time to randomize the starting bucket to prevent starvation.
	 * Search all buckets from neg_index to MSG_MAX_QNUM, starting
	 * from the random starting point, and wrapping around after
	 * MSG_MAX_QNUM.
	 */

	nbuckets = MSG_MAX_QNUM - neg_index + 1;
	check_index = neg_index + (qp->msg_stime % nbuckets);

	for (count = nbuckets; count > 0; count--) {
		qptr = list_head(&qp->msg_wait_snd_ngt[check_index]);
		while (qptr) {
			/*
			 * The lowest hash bucket may actually contain
			 * message types that are not valid for this
			 * request.  This can happen due to the fact that
			 * the message buckets actually contain a consecutive
			 * range of types.
			 */
			if (-qptr->msgw_type >= type) {
				list_remove(&qp->msg_wait_snd_ngt[check_index],
				    qptr);
				return (qptr);
			}
			qptr = list_next(&qp->msg_wait_snd_ngt[check_index],
			    qptr);
		}
		if (++check_index > MSG_MAX_QNUM) {
			check_index = neg_index;
		}
	}
	return (NULL);
}

static int
msg_rcvq_sleep(list_t *queue, msgq_wakeup_t *entry, kmutex_t **lock,
    kmsqid_t *qp)
{
	int		cvres;

	cv_init(&entry->msgw_wake_cv, NULL, 0, NULL);

	list_insert_tail(queue, entry);

	qp->msg_rcv_cnt++;
	cvres = cv_wait_sig(&entry->msgw_wake_cv, *lock);
	*lock = ipc_relock(msq_svc, qp->msg_perm.ipc_id, *lock);
	qp->msg_rcv_cnt--;

	if (list_link_active(&entry->msgw_list)) {
		/*
		 * We woke up unexpectedly, remove ourself.
		 */
		list_remove(queue, entry);
	}

	return (cvres);
}

static void
msg_rcvq_wakeup_all(list_t *q_ptr)
{
	msgq_wakeup_t	*q_walk;

	while (q_walk = list_head(q_ptr)) {
		list_remove(q_ptr, q_walk);
		cv_signal(&q_walk->msgw_wake_cv);
	}
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

/*
 * Determine if a writer who is waiting can process its message.  If so
 * wake it up.
 */
static void
msg_wakeup_senders(kmsqid_t *qp)

{
	struct msgq_wakeup *ptr, *optr;
	size_t avail, smallest;
	int msgs_out;

	/*
	 * Is there a writer waiting, and if so, can it be serviced? If
	 * not return back to the caller.
	 */
	if (IPC_FREE(&qp->msg_perm) || qp->msg_qnum >= qp->msg_qmax)
		return;

	avail = qp->msg_qbytes - qp->msg_cbytes;
	if (avail < qp->msg_snd_smallest)
		return;

	ptr = list_head(&qp->msg_wait_rcv);
	if (ptr == NULL) {
		qp->msg_snd_smallest = MSG_SMALL_INIT;
		return;
	}
	optr = ptr;

	/*
	 * smallest:	minimum message size of all queued writers
	 *
	 * avail:	amount of space left on the msgq
	 *		if all the writers we have woken up are successful.
	 *
	 * msgs_out:	is the number of messages on the message queue if
	 *		all the writers we have woken up are successful.
	 */

	smallest = MSG_SMALL_INIT;
	msgs_out = qp->msg_qnum;
	while (ptr) {
		ptr = list_next(&qp->msg_wait_rcv, ptr);
		if (optr->msgw_snd_size <= avail) {
			list_remove(&qp->msg_wait_rcv, optr);
			avail -= optr->msgw_snd_size;
			cv_signal(&optr->msgw_wake_cv);
			msgs_out++;
			if (msgs_out == qp->msg_qmax ||
			    avail < qp->msg_snd_smallest)
				break;
		} else {
			if (smallest > optr->msgw_snd_size)
				smallest = optr->msgw_snd_size;
		}
		optr = ptr;
	}

	/*
	 * Reset the smallest message size if the entire list has been visited
	 */
	if (ptr == NULL && smallest != MSG_SMALL_INIT)
		qp->msg_snd_smallest = smallest;
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
