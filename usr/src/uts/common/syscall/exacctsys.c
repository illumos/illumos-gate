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
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acctctl.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/exacct.h>
#include <sys/modctl.h>
#include <sys/procset.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/task.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/policy.h>

/*
 * getacct(2), putacct(2), and wracct(2) system calls
 *
 *   The extended accounting subsystem provides three root-privileged system
 *   calls for interacting with the actual resource data associated with each
 *   task or process.  getacct() copies a packed exacct record reflecting the
 *   resource usage out to the buffer provided by the user.  wracct() writes a
 *   record to the appropriate extended accounting file.  putacct() takes the
 *   buffer provided by the user, and appends a "tag" record associated with the
 *   specified task or project that encapsulates the user data.  All three of
 *   these functions exit early if extended accounting is not active for the
 *   requested entity type.
 *
 * Locking
 *   Under the terminology introduced in os/task.c, all three of these system
 *   calls are task observers, when executing on an existing task.
 */

/*
 * getacct_callback() is used to copyout the buffer with accounting records
 * from the kernel back to the user. It also sets actual to the size of the
 * kernel buffer--the required minimum size for a successful outbound copy.
 */
/* ARGSUSED */
static int
getacct_callback(ac_info_t *unused, void *ubuf, size_t usize, void *kbuf,
    size_t ksize, size_t *actual)
{
	size_t size = MIN(usize, ksize);

	if (ubuf != NULL && copyout(kbuf, ubuf, size) != 0)
		return (EFAULT);
	*actual = ksize;
	return (0);
}

static int
getacct_task(ac_info_t *ac_task, taskid_t tkid, void *buf, size_t bufsize,
    size_t *sizep)
{
	task_t *tk;
	int error;

	mutex_enter(&ac_task->ac_lock);
	if (ac_task->ac_state == AC_OFF) {
		mutex_exit(&ac_task->ac_lock);
		return (ENOTACTIVE);
	}
	mutex_exit(&ac_task->ac_lock);

	if ((tk = task_hold_by_id(tkid)) == NULL)
		return (ESRCH);
	error = exacct_assemble_task_usage(ac_task, tk,
	    getacct_callback, buf, bufsize, sizep, EW_PARTIAL);
	task_rele(tk);

	return (error);
}

static int
getacct_proc(ac_info_t *ac_proc, pid_t pid, void *buf, size_t bufsize,
    size_t *sizep)
{
	proc_t *p;
	proc_usage_t *pu;
	ulong_t mask[AC_MASK_SZ];
	ulong_t *ac_mask = &mask[0];
	int error;

	mutex_enter(&ac_proc->ac_lock);
	if (ac_proc->ac_state == AC_OFF) {
		mutex_exit(&ac_proc->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_proc->ac_mask[0], ac_mask, AC_MASK_SZ);
	mutex_exit(&ac_proc->ac_lock);

	pu = kmem_zalloc(sizeof (proc_usage_t), KM_SLEEP);
	pu->pu_command = kmem_zalloc(MAXCOMLEN + 1, KM_SLEEP);

	mutex_enter(&pidlock);
	if ((p = prfind(pid)) == NULL) {
		mutex_exit(&pidlock);
		kmem_free(pu->pu_command, MAXCOMLEN + 1);
		kmem_free(pu, sizeof (proc_usage_t));
		return (ESRCH);
	}
	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);

	exacct_calculate_proc_usage(p, pu, ac_mask, EW_PARTIAL, 0);
	mutex_exit(&p->p_lock);

	error = exacct_assemble_proc_usage(ac_proc, pu,
	    getacct_callback, buf, bufsize, sizep, EW_PARTIAL);

	kmem_free(pu->pu_command, MAXCOMLEN + 1);
	kmem_free(pu, sizeof (proc_usage_t));

	return (error);
}

static ssize_t
getacct(idtype_t idtype, id_t id, void *buf, size_t bufsize)
{
	size_t size = 0;
	int error;
	struct exacct_globals *acg;

	if (bufsize > EXACCT_MAX_BUFSIZE)
		bufsize = EXACCT_MAX_BUFSIZE;

	acg = zone_getspecific(exacct_zone_key, curproc->p_zone);
	switch (idtype) {
	case P_PID:
		error = getacct_proc(&acg->ac_proc, id, buf, bufsize, &size);
		break;
	case P_TASKID:
		error = getacct_task(&acg->ac_task, id, buf, bufsize, &size);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error == 0 ? (ssize_t)size : set_errno(error));
}

static int
putacct(idtype_t idtype, id_t id, void *buf, size_t bufsize, int flags)
{
	int error;
	taskid_t tkid;
	proc_t *p;
	task_t *tk;
	void *kbuf;
	struct exacct_globals *acg;

	if (bufsize == 0 || bufsize > EXACCT_MAX_BUFSIZE)
		return (set_errno(EINVAL));

	kbuf = kmem_alloc(bufsize, KM_SLEEP);
	if (copyin(buf, kbuf, bufsize) != 0) {
		error = EFAULT;
		goto out;
	}

	acg = zone_getspecific(exacct_zone_key, curproc->p_zone);
	switch (idtype) {
	case P_PID:
		mutex_enter(&pidlock);
		if ((p = prfind(id)) == NULL) {
			mutex_exit(&pidlock);
			error = ESRCH;
		} else {
			zone_t *zone = p->p_zone;

			tkid = p->p_task->tk_tkid;
			zone_hold(zone);
			mutex_exit(&pidlock);

			error = exacct_tag_proc(&acg->ac_proc, id, tkid, kbuf,
			    bufsize, flags, zone->zone_nodename);
			zone_rele(zone);
		}
		break;
	case P_TASKID:
		if ((tk = task_hold_by_id(id)) != NULL) {
			error = exacct_tag_task(&acg->ac_task, tk, kbuf,
			    bufsize, flags);
			task_rele(tk);
		} else {
			error = ESRCH;
		}
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	kmem_free(kbuf, bufsize);
	return (error == 0 ? error : set_errno(error));
}

static int
wracct_task(ac_info_t *ac_task, taskid_t tkid, int flag, size_t *sizep)
{
	task_t *tk;
	int error;

	mutex_enter(&ac_task->ac_lock);
	if (ac_task->ac_state == AC_OFF || ac_task->ac_vnode == NULL) {
		mutex_exit(&ac_task->ac_lock);
		return (ENOTACTIVE);
	}
	mutex_exit(&ac_task->ac_lock);

	if ((tk = task_hold_by_id(tkid)) == NULL)
		return (ESRCH);
	error = exacct_assemble_task_usage(ac_task, tk, exacct_commit_callback,
	    NULL, 0, sizep, flag);
	task_rele(tk);

	return (error);
}

static int
wracct_proc(ac_info_t *ac_proc, pid_t pid, int flag, size_t *sizep)
{
	proc_t *p;
	proc_usage_t *pu;
	ulong_t mask[AC_MASK_SZ];
	ulong_t *ac_mask = &mask[0];
	int error;

	mutex_enter(&ac_proc->ac_lock);
	if (ac_proc->ac_state == AC_OFF || ac_proc->ac_vnode == NULL) {
		mutex_exit(&ac_proc->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_proc->ac_mask[0], ac_mask, AC_MASK_SZ);
	mutex_exit(&ac_proc->ac_lock);

	pu = kmem_zalloc(sizeof (proc_usage_t), KM_SLEEP);
	pu->pu_command = kmem_zalloc(MAXCOMLEN + 1, KM_SLEEP);

	mutex_enter(&pidlock);
	if ((p = prfind(pid)) == NULL) {
		mutex_exit(&pidlock);
		kmem_free(pu->pu_command, MAXCOMLEN + 1);
		kmem_free(pu, sizeof (proc_usage_t));
		return (ESRCH);
	}
	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);
	exacct_calculate_proc_usage(p, pu, ac_mask, flag, 0);
	mutex_exit(&p->p_lock);

	error = exacct_assemble_proc_usage(ac_proc, pu,
	    exacct_commit_callback, NULL, 0, sizep, flag);

	kmem_free(pu->pu_command, MAXCOMLEN + 1);
	kmem_free(pu, sizeof (proc_usage_t));

	return (error);
}

static int
wracct(idtype_t idtype, id_t id, int flags)
{
	int error;
	size_t size = 0;
	struct exacct_globals *acg;

	/*
	 * Validate flags.
	 */
	switch (flags) {
	case EW_PARTIAL:
	case EW_INTERVAL:
		break;
	default:
		return (set_errno(EINVAL));
	}

	acg = zone_getspecific(exacct_zone_key, curproc->p_zone);
	switch (idtype) {
	case P_PID:
		if (flags == EW_INTERVAL)
			return (set_errno(ENOTSUP));
		error = wracct_proc(&acg->ac_proc, id, flags, &size);
		break;
	case P_TASKID:
		error = wracct_task(&acg->ac_task, id, flags, &size);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error == 0 ? error : set_errno(error));
}

static long
exacct(int code, idtype_t idtype, id_t id, void *buf, size_t bufsize,
    int flags)
{
	if (secpolicy_acct(CRED()) != 0)
		return (set_errno(EPERM));

	if (exacct_zone_key == ZONE_KEY_UNINITIALIZED)
		return (set_errno(ENOTACTIVE));

	switch (code) {
	case 0:
		return (getacct(idtype, id, buf, bufsize));
	case 1:
		return (putacct(idtype, id, buf, bufsize, flags));
	case 2:
		return (wracct(idtype, id, flags));
	default:
		return (set_errno(EINVAL));
	}
}

#if defined(_LP64)
#define	SE_LRVAL	SE_64RVAL
#else
#define	SE_LRVAL	SE_32RVAL1
#endif

static struct sysent exacctsys_sysent = {
	6,
	SE_NOUNLOAD | SE_ARGC | SE_LRVAL,
	(int (*)())exacct
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"extended accounting facility",
	&exacctsys_sysent
};

#ifdef _SYSCALL32_IMPL

static struct sysent exacctsys_sysent32 = {
	6,
	SE_NOUNLOAD | SE_ARGC | SE_32RVAL1,
	(int (*)())exacct
};

static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit extended accounting facility",
	&exacctsys_sysent32
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
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&modlinkage, mip));
}
