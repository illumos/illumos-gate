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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/exacct.h>
#include <sys/exacct_catalog.h>
#include <sys/disp.h>
#include <sys/task.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/project.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/acctctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/session.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/msacct.h>

/*
 * exacct usage and recording routines
 *
 * wracct(2), getacct(2), and the records written at process or task
 * termination are constructed using the exacct_assemble_[task,proc]_usage()
 * functions, which take a callback that takes the appropriate action on
 * the packed exacct record for the task or process.  For the process-related
 * actions, we partition the routines such that the data collecting component
 * can be performed while holding p_lock, and all sleeping or blocking
 * operations can be performed without acquiring p_lock.
 *
 * putacct(2), which allows an application to construct a customized record
 * associated with an existing process or task, has its own entry points:
 * exacct_tag_task() and exacct_tag_proc().
 */

taskq_t *exacct_queue;
kmem_cache_t *exacct_object_cache;

zone_key_t exacct_zone_key = ZONE_KEY_UNINITIALIZED;

static const uint32_t exacct_version = EXACCT_VERSION;
static const char exacct_header[] = "exacct";
static const char exacct_creator[] = "SunOS";

ea_object_t *
ea_alloc_item(ea_catalog_t catalog, void *buf, size_t bufsz)
{
	ea_object_t *item;

	item = kmem_cache_alloc(exacct_object_cache, KM_SLEEP);
	bzero(item, sizeof (ea_object_t));
	(void) ea_set_item(item, catalog, buf, bufsz);
	return (item);
}

ea_object_t *
ea_alloc_group(ea_catalog_t catalog)
{
	ea_object_t *group;

	group = kmem_cache_alloc(exacct_object_cache, KM_SLEEP);
	bzero(group, sizeof (ea_object_t));
	(void) ea_set_group(group, catalog);
	return (group);
}

ea_object_t *
ea_attach_item(ea_object_t *grp, void *buf, size_t bufsz, ea_catalog_t catalog)
{
	ea_object_t *item;

	item = ea_alloc_item(catalog, buf, bufsz);
	(void) ea_attach_to_group(grp, item);
	return (item);
}

/*
 * exacct_add_task_mstate() and exacct_sub_task_mstate() add and subtract
 * microstate accounting data and resource usage counters from one task_usage_t
 * from those supplied in another. These functions do not operate on *all*
 * members of a task_usage_t: for some (e.g. tu_anctaskid) it would not make
 * sense.
 */
static void
exacct_add_task_mstate(task_usage_t *tu, task_usage_t *delta)
{
	tu->tu_utime  += delta->tu_utime;
	tu->tu_stime  += delta->tu_stime;
	tu->tu_minflt += delta->tu_minflt;
	tu->tu_majflt += delta->tu_majflt;
	tu->tu_sndmsg += delta->tu_sndmsg;
	tu->tu_rcvmsg += delta->tu_rcvmsg;
	tu->tu_ioch   += delta->tu_ioch;
	tu->tu_iblk   += delta->tu_iblk;
	tu->tu_oblk   += delta->tu_oblk;
	tu->tu_vcsw   += delta->tu_vcsw;
	tu->tu_icsw   += delta->tu_icsw;
	tu->tu_nsig   += delta->tu_nsig;
	tu->tu_nswp   += delta->tu_nswp;
	tu->tu_nscl   += delta->tu_nscl;
}

/*
 * See the comments for exacct_add_task_mstate(), above.
 */
static void
exacct_sub_task_mstate(task_usage_t *tu, task_usage_t *delta)
{
	tu->tu_utime  -= delta->tu_utime;
	tu->tu_stime  -= delta->tu_stime;
	tu->tu_minflt -= delta->tu_minflt;
	tu->tu_majflt -= delta->tu_majflt;
	tu->tu_sndmsg -= delta->tu_sndmsg;
	tu->tu_rcvmsg -= delta->tu_rcvmsg;
	tu->tu_ioch   -= delta->tu_ioch;
	tu->tu_iblk   -= delta->tu_iblk;
	tu->tu_oblk   -= delta->tu_oblk;
	tu->tu_vcsw   -= delta->tu_vcsw;
	tu->tu_icsw   -= delta->tu_icsw;
	tu->tu_nsig   -= delta->tu_nsig;
	tu->tu_nswp   -= delta->tu_nswp;
	tu->tu_nscl   -= delta->tu_nscl;
}

/*
 * Wrapper for vn_rdwr() used by exacct_vn_write() and exacct_write_header()
 * to write to the accounting file without corrupting it in case of an I/O or
 * filesystem error.
 */
static int
exacct_vn_write_impl(ac_info_t *info, void *buf, ssize_t bufsize)
{
	int error;
	ssize_t resid;
	struct vattr va;

	ASSERT(info != NULL);
	ASSERT(info->ac_vnode != NULL);
	ASSERT(MUTEX_HELD(&info->ac_lock));

	/*
	 * Save the size. If vn_rdwr fails, reset the size to avoid corrupting
	 * the present accounting file.
	 */
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(info->ac_vnode, &va, 0, kcred, NULL);
	if (error == 0) {
		error = vn_rdwr(UIO_WRITE, info->ac_vnode, (caddr_t)buf,
		    bufsize, 0LL, UIO_SYSSPACE, FAPPEND, (rlim64_t)MAXOFFSET_T,
		    kcred, &resid);
		if (error) {
			(void) VOP_SETATTR(info->ac_vnode, &va, 0, kcred, NULL);
		} else if (resid != 0) {
			(void) VOP_SETATTR(info->ac_vnode, &va, 0, kcred, NULL);
			error = ENOSPC;
		}
	}
	return (error);
}

/*
 * exacct_vn_write() safely writes to an accounting file.  acctctl() prevents
 * the two accounting vnodes from being equal, and the appropriate ac_lock is
 * held across the call, so we're single threaded through this code for each
 * file.
 */
static int
exacct_vn_write(ac_info_t *info, void *buf, ssize_t bufsize)
{
	int error;

	if (info == NULL)
		return (0);

	mutex_enter(&info->ac_lock);

	/*
	 * Don't do anything unless accounting file is set.
	 */
	if (info->ac_vnode == NULL) {
		mutex_exit(&info->ac_lock);
		return (0);
	}
	error = exacct_vn_write_impl(info, buf, bufsize);
	mutex_exit(&info->ac_lock);

	return (error);
}

/*
 * void *exacct_create_header(size_t *)
 *
 * Overview
 *   exacct_create_header() constructs an exacct file header identifying the
 *   accounting file as the output of the kernel.  exacct_create_header() and
 *   the static write_header() and verify_header() routines in libexacct must
 *   remain synchronized.
 *
 * Return values
 *   A pointer to a packed exacct buffer containing the appropriate header is
 *   returned; the size of the buffer is placed in the location indicated by
 *   sizep.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
void *
exacct_create_header(size_t *sizep)
{
	ea_object_t *hdr_grp;
	uint32_t bskip;
	void *buf;
	size_t bufsize;

	hdr_grp = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | EXD_GROUP_HEADER);
	(void) ea_attach_item(hdr_grp, (void *)&exacct_version, 0,
	    EXT_UINT32 | EXC_DEFAULT | EXD_VERSION);
	(void) ea_attach_item(hdr_grp, (void *)exacct_header, 0,
	    EXT_STRING | EXC_DEFAULT | EXD_FILETYPE);
	(void) ea_attach_item(hdr_grp, (void *)exacct_creator, 0,
	    EXT_STRING | EXC_DEFAULT | EXD_CREATOR);
	(void) ea_attach_item(hdr_grp, uts_nodename(), 0,
	    EXT_STRING | EXC_DEFAULT | EXD_HOSTNAME);

	bufsize = ea_pack_object(hdr_grp, NULL, 0);
	buf = kmem_alloc(bufsize, KM_SLEEP);
	(void) ea_pack_object(hdr_grp, buf, bufsize);
	ea_free_object(hdr_grp, EUP_ALLOC);

	/*
	 * To prevent reading the header when reading the file backwards,
	 * set the large backskip of the header group to 0 (last 4 bytes).
	 */
	bskip = 0;
	exacct_order32(&bskip);
	bcopy(&bskip, (char *)buf + bufsize - sizeof (bskip),
	    sizeof (bskip));

	*sizep = bufsize;
	return (buf);
}

/*
 * int exacct_write_header(ac_info_t *, void *, size_t)
 *
 * Overview
 *   exacct_write_header() writes the given header buffer to the indicated
 *   vnode.
 *
 * Return values
 *   The result of the write operation is returned.
 *
 * Caller's context
 *   Caller must hold the ac_lock of the appropriate accounting file
 *   information block (ac_info_t).
 */
int
exacct_write_header(ac_info_t *info, void *hdr, size_t hdrsize)
{
	if (info != NULL && info->ac_vnode != NULL)
		return (exacct_vn_write_impl(info, hdr, hdrsize));

	return (0);
}

static void
exacct_get_interval_task_usage(task_t *tk, task_usage_t *tu,
    task_usage_t **tu_buf)
{
	task_usage_t *oldtu, *newtu;
	task_usage_t **prevusage;

	ASSERT(MUTEX_HELD(&tk->tk_usage_lock));
	if (getzoneid() != GLOBAL_ZONEID) {
		prevusage = &tk->tk_zoneusage;
	} else {
		prevusage = &tk->tk_prevusage;
	}
	if ((oldtu = *prevusage) != NULL) {
		/*
		 * In case we have any accounting information
		 * saved from the previous interval record.
		 */
		newtu = *tu_buf;
		bcopy(tu, newtu, sizeof (task_usage_t));
		tu->tu_minflt	-= oldtu->tu_minflt;
		tu->tu_majflt	-= oldtu->tu_majflt;
		tu->tu_sndmsg	-= oldtu->tu_sndmsg;
		tu->tu_rcvmsg	-= oldtu->tu_rcvmsg;
		tu->tu_ioch	-= oldtu->tu_ioch;
		tu->tu_iblk	-= oldtu->tu_iblk;
		tu->tu_oblk	-= oldtu->tu_oblk;
		tu->tu_vcsw	-= oldtu->tu_vcsw;
		tu->tu_icsw	-= oldtu->tu_icsw;
		tu->tu_nsig	-= oldtu->tu_nsig;
		tu->tu_nswp	-= oldtu->tu_nswp;
		tu->tu_nscl	-= oldtu->tu_nscl;
		tu->tu_utime	-= oldtu->tu_utime;
		tu->tu_stime	-= oldtu->tu_stime;

		tu->tu_startsec = oldtu->tu_finishsec;
		tu->tu_startnsec = oldtu->tu_finishnsec;
		/*
		 * Copy the data from our temporary storage to the task's
		 * previous interval usage structure for future reference.
		 */
		bcopy(newtu, oldtu, sizeof (task_usage_t));
	} else {
		/*
		 * Store current statistics in the task's previous interval
		 * usage structure for future references.
		 */
		*prevusage = *tu_buf;
		bcopy(tu, *prevusage, sizeof (task_usage_t));
		*tu_buf = NULL;
	}
}

static void
exacct_snapshot_task_usage(task_t *tk, task_usage_t *tu)
{
	timestruc_t ts;
	proc_t *p;

	ASSERT(MUTEX_HELD(&pidlock));

	if ((p = tk->tk_memb_list) == NULL)
		return;

	/*
	 * exacct_snapshot_task_usage() provides an approximate snapshot of the
	 * usage of the potentially many members of the task.  Since we don't
	 * guarantee exactness, we don't acquire the p_lock of any of the member
	 * processes.
	 */
	do {
		mutex_enter(&p->p_lock);
		tu->tu_utime	+= mstate_aggr_state(p, LMS_USER);
		tu->tu_stime	+= mstate_aggr_state(p, LMS_SYSTEM);
		mutex_exit(&p->p_lock);
		tu->tu_minflt	+= p->p_ru.minflt;
		tu->tu_majflt	+= p->p_ru.majflt;
		tu->tu_sndmsg	+= p->p_ru.msgsnd;
		tu->tu_rcvmsg	+= p->p_ru.msgrcv;
		tu->tu_ioch	+= p->p_ru.ioch;
		tu->tu_iblk	+= p->p_ru.inblock;
		tu->tu_oblk	+= p->p_ru.oublock;
		tu->tu_vcsw	+= p->p_ru.nvcsw;
		tu->tu_icsw	+= p->p_ru.nivcsw;
		tu->tu_nsig	+= p->p_ru.nsignals;
		tu->tu_nswp	+= p->p_ru.nswap;
		tu->tu_nscl	+= p->p_ru.sysc;
	} while ((p = p->p_tasknext) != tk->tk_memb_list);

	/*
	 * The resource usage accounted for so far will include that
	 * contributed by the task's first process. If this process
	 * came from another task, then its accumulated resource usage
	 * will include a contribution from work performed there.
	 * We must therefore subtract any resource usage that was
	 * inherited with the first process.
	 */
	exacct_sub_task_mstate(tu, tk->tk_inherited);

	gethrestime(&ts);
	tu->tu_finishsec = (uint64_t)(ulong_t)ts.tv_sec;
	tu->tu_finishnsec = (uint64_t)(ulong_t)ts.tv_nsec;
}

/*
 * void exacct_update_task_mstate(proc_t *)
 *
 * Overview
 *   exacct_update_task_mstate() updates the task usage; it is intended
 *   to be called from proc_exit().
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   p_lock must be held at entry.
 */
void
exacct_update_task_mstate(proc_t *p)
{
	task_usage_t *tu;

	mutex_enter(&p->p_task->tk_usage_lock);
	tu = p->p_task->tk_usage;
	tu->tu_utime	+= mstate_aggr_state(p, LMS_USER);
	tu->tu_stime	+= mstate_aggr_state(p, LMS_SYSTEM);
	tu->tu_minflt	+= p->p_ru.minflt;
	tu->tu_majflt	+= p->p_ru.majflt;
	tu->tu_sndmsg	+= p->p_ru.msgsnd;
	tu->tu_rcvmsg	+= p->p_ru.msgrcv;
	tu->tu_ioch	+= p->p_ru.ioch;
	tu->tu_iblk	+= p->p_ru.inblock;
	tu->tu_oblk	+= p->p_ru.oublock;
	tu->tu_vcsw	+= p->p_ru.nvcsw;
	tu->tu_icsw	+= p->p_ru.nivcsw;
	tu->tu_nsig	+= p->p_ru.nsignals;
	tu->tu_nswp	+= p->p_ru.nswap;
	tu->tu_nscl	+= p->p_ru.sysc;
	mutex_exit(&p->p_task->tk_usage_lock);
}

static void
exacct_calculate_task_usage(task_t *tk, task_usage_t *tu, int flag)
{
	timestruc_t ts;
	task_usage_t *tu_buf;

	switch (flag) {
	case EW_PARTIAL:
		/*
		 * For partial records we must report the sum of current
		 * accounting statistics with previously accumulated
		 * statistics.
		 */
		mutex_enter(&pidlock);
		mutex_enter(&tk->tk_usage_lock);

		(void) bcopy(tk->tk_usage, tu, sizeof (task_usage_t));
		exacct_snapshot_task_usage(tk, tu);

		mutex_exit(&tk->tk_usage_lock);
		mutex_exit(&pidlock);
		break;
	case EW_INTERVAL:
		/*
		 * We need to allocate spare task_usage_t buffer before
		 * grabbing pidlock because we might need it later in
		 * exacct_get_interval_task_usage().
		 */
		tu_buf = kmem_zalloc(sizeof (task_usage_t), KM_SLEEP);
		mutex_enter(&pidlock);
		mutex_enter(&tk->tk_usage_lock);

		/*
		 * For interval records, we deduct the previous microstate
		 * accounting data and cpu usage times from previously saved
		 * results and update the previous task usage structure.
		 */
		(void) bcopy(tk->tk_usage, tu, sizeof (task_usage_t));
		exacct_snapshot_task_usage(tk, tu);
		exacct_get_interval_task_usage(tk, tu, &tu_buf);

		mutex_exit(&tk->tk_usage_lock);
		mutex_exit(&pidlock);

		if (tu_buf != NULL)
			kmem_free(tu_buf, sizeof (task_usage_t));
		break;
	case EW_FINAL:
		/*
		 * For final records, we deduct, from the task's current
		 * usage, any usage that was inherited with the arrival
		 * of a process from a previous task. We then record
		 * the task's finish time.
		 */
		mutex_enter(&tk->tk_usage_lock);
		(void) bcopy(tk->tk_usage, tu, sizeof (task_usage_t));
		exacct_sub_task_mstate(tu, tk->tk_inherited);
		mutex_exit(&tk->tk_usage_lock);

		gethrestime(&ts);
		tu->tu_finishsec = (uint64_t)(ulong_t)ts.tv_sec;
		tu->tu_finishnsec = (uint64_t)(ulong_t)ts.tv_nsec;

		break;
	}
}

static int
exacct_attach_task_item(task_t *tk, task_usage_t *tu, ea_object_t *record,
    int res)
{
	int attached = 1;

	switch (res) {
	case AC_TASK_TASKID:
		(void) ea_attach_item(record, &tk->tk_tkid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_TASK_TASKID);
		break;
	case AC_TASK_PROJID:
		(void) ea_attach_item(record, &tk->tk_proj->kpj_id,
		    sizeof (uint32_t), EXT_UINT32 | EXD_TASK_PROJID);
		break;
	case AC_TASK_CPU: {
			timestruc_t ts;
			uint64_t ui;

			hrt2ts(tu->tu_stime, &ts);
			ui = ts.tv_sec;
			(void) ea_attach_item(record, &ui, sizeof (uint64_t),
			    EXT_UINT64 | EXD_TASK_CPU_SYS_SEC);
			ui = ts.tv_nsec;
			(void) ea_attach_item(record, &ui, sizeof (uint64_t),
			    EXT_UINT64 | EXD_TASK_CPU_SYS_NSEC);

			hrt2ts(tu->tu_utime, &ts);
			ui = ts.tv_sec;
			(void) ea_attach_item(record, &ui, sizeof (uint64_t),
			    EXT_UINT64 | EXD_TASK_CPU_USER_SEC);
			ui = ts.tv_nsec;
			(void) ea_attach_item(record, &ui, sizeof (uint64_t),
			    EXT_UINT64 | EXD_TASK_CPU_USER_NSEC);
		}
		break;
	case AC_TASK_TIME:
		(void) ea_attach_item(record, &tu->tu_startsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_START_SEC);
		(void) ea_attach_item(record, &tu->tu_startnsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_START_NSEC);
		(void) ea_attach_item(record, &tu->tu_finishsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_FINISH_SEC);
		(void) ea_attach_item(record, &tu->tu_finishnsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_FINISH_NSEC);
		break;
	case AC_TASK_HOSTNAME:
		(void) ea_attach_item(record, tk->tk_zone->zone_nodename,
		    strlen(tk->tk_zone->zone_nodename) + 1,
		    EXT_STRING | EXD_TASK_HOSTNAME);
			break;
	case AC_TASK_MICROSTATE:
		(void) ea_attach_item(record, &tu->tu_majflt,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_FAULTS_MAJOR);
		(void) ea_attach_item(record, &tu->tu_minflt,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_FAULTS_MINOR);
		(void) ea_attach_item(record, &tu->tu_sndmsg,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_MESSAGES_SND);
		(void) ea_attach_item(record, &tu->tu_rcvmsg,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_MESSAGES_RCV);
		(void) ea_attach_item(record, &tu->tu_iblk,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_BLOCKS_IN);
		(void) ea_attach_item(record, &tu->tu_oblk,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_BLOCKS_OUT);
		(void) ea_attach_item(record, &tu->tu_ioch,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_CHARS_RDWR);
		(void) ea_attach_item(record, &tu->tu_vcsw,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_CONTEXT_VOL);
		(void) ea_attach_item(record, &tu->tu_icsw,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_CONTEXT_INV);
		(void) ea_attach_item(record, &tu->tu_nsig,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_SIGNALS);
		(void) ea_attach_item(record, &tu->tu_nswp,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_SWAPS);
		(void) ea_attach_item(record, &tu->tu_nscl,
		    sizeof (uint64_t), EXT_UINT64 | EXD_TASK_SYSCALLS);
		break;
	case AC_TASK_ANCTASKID:
		(void) ea_attach_item(record, &tu->tu_anctaskid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_TASK_ANCTASKID);
		break;
	case AC_TASK_ZONENAME:
		(void) ea_attach_item(record, tk->tk_zone->zone_name,
		    strlen(tk->tk_zone->zone_name) + 1,
		    EXT_STRING | EXD_TASK_ZONENAME);
		break;
	default:
		attached = 0;
	}
	return (attached);
}

static ea_object_t *
exacct_assemble_task_record(task_t *tk, task_usage_t *tu, ulong_t *mask,
    ea_catalog_t record_type)
{
	int res, count;
	ea_object_t *record;

	/*
	 * Assemble usage values into group.
	 */
	record = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | record_type);
	for (res = 1, count = 0; res <= AC_TASK_MAX_RES; res++)
		if (BT_TEST(mask, res))
			count += exacct_attach_task_item(tk, tu, record, res);
	if (count == 0) {
		ea_free_object(record, EUP_ALLOC);
		record = NULL;
	}
	return (record);
}

/*
 * int exacct_assemble_task_usage(task_t *, int (*)(void *, size_t, void *,
 *	size_t, size_t *), void *, size_t, size_t *, int)
 *
 * Overview
 *   exacct_assemble_task_usage() builds the packed exacct buffer for the
 *   indicated task, executes the given callback function, and free the packed
 *   buffer.
 *
 * Return values
 *   Returns 0 on success; otherwise the appropriate error code is returned.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
int
exacct_assemble_task_usage(ac_info_t *ac_task, task_t *tk,
    int (*callback)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *ubuf, size_t ubufsize, size_t *actual, int flag)
{
	ulong_t mask[AC_MASK_SZ];
	ea_object_t *task_record;
	ea_catalog_t record_type;
	task_usage_t *tu;
	void *buf;
	size_t bufsize;
	int ret;

	ASSERT(flag == EW_FINAL || flag == EW_PARTIAL || flag == EW_INTERVAL);

	mutex_enter(&ac_task->ac_lock);
	if (ac_task->ac_state == AC_OFF) {
		mutex_exit(&ac_task->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(ac_task->ac_mask, mask, AC_MASK_SZ);
	mutex_exit(&ac_task->ac_lock);

	switch (flag) {
	case EW_FINAL:
		record_type = EXD_GROUP_TASK;
		break;
	case EW_PARTIAL:
		record_type = EXD_GROUP_TASK_PARTIAL;
		break;
	case EW_INTERVAL:
		record_type = EXD_GROUP_TASK_INTERVAL;
		break;
	}

	/*
	 * Calculate task usage and assemble it into the task record.
	 */
	tu = kmem_zalloc(sizeof (task_usage_t), KM_SLEEP);
	exacct_calculate_task_usage(tk, tu, flag);
	task_record = exacct_assemble_task_record(tk, tu, mask, record_type);
	if (task_record == NULL) {
		/*
		 * The current configuration of the accounting system has
		 * resulted in records with no data; accordingly, we don't write
		 * these, but we return success.
		 */
		kmem_free(tu, sizeof (task_usage_t));
		return (0);
	}

	/*
	 * Pack object into buffer and run callback on it.
	 */
	bufsize = ea_pack_object(task_record, NULL, 0);
	buf = kmem_alloc(bufsize, KM_SLEEP);
	(void) ea_pack_object(task_record, buf, bufsize);
	ret = callback(ac_task, ubuf, ubufsize, buf, bufsize, actual);

	/*
	 * Free all previously allocated structures.
	 */
	kmem_free(buf, bufsize);
	ea_free_object(task_record, EUP_ALLOC);
	kmem_free(tu, sizeof (task_usage_t));
	return (ret);
}

/*
 * void exacct_commit_task(void *)
 *
 * Overview
 *   exacct_commit_task() calculates the final usage for a task, updating the
 *   task usage if task accounting is active, and writing a task record if task
 *   accounting is active.  exacct_commit_task() is intended for being called
 *   from a task queue (taskq_t).
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */

void
exacct_commit_task(void *arg)
{
	task_t *tk = (task_t *)arg;
	size_t size;
	zone_t *zone = tk->tk_zone;
	struct exacct_globals *acg;

	ASSERT(tk != task0p);
	ASSERT(tk->tk_memb_list == NULL);

	/*
	 * Don't do any extra work if the acctctl module isn't loaded.
	 * If acctctl module is loaded when zone is in down state then
	 * zone_getspecific can return NULL for that zone.
	 */
	if (exacct_zone_key != ZONE_KEY_UNINITIALIZED) {
		acg = zone_getspecific(exacct_zone_key, zone);
		if (acg == NULL)
			goto err;
		(void) exacct_assemble_task_usage(&acg->ac_task, tk,
		    exacct_commit_callback, NULL, 0, &size, EW_FINAL);
		if (tk->tk_zone != global_zone) {
			acg = zone_getspecific(exacct_zone_key, global_zone);
			(void) exacct_assemble_task_usage(&acg->ac_task, tk,
			    exacct_commit_callback, NULL, 0, &size, EW_FINAL);
		}
	}
	/*
	 * Release associated project and finalize task.
	 */
err:
	task_end(tk);
}

static int
exacct_attach_proc_item(proc_usage_t *pu, ea_object_t *record, int res)
{
	int attached = 1;

	switch (res) {
	case AC_PROC_PID:
		(void) ea_attach_item(record, &pu->pu_pid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_PID);
		break;
	case AC_PROC_UID:
		(void) ea_attach_item(record, &pu->pu_ruid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_UID);
		break;
	case AC_PROC_FLAG:
		(void) ea_attach_item(record, &pu->pu_acflag,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_ACCT_FLAGS);
		break;
	case AC_PROC_GID:
		(void) ea_attach_item(record, &pu->pu_rgid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_GID);
		break;
	case AC_PROC_PROJID:
		(void) ea_attach_item(record, &pu->pu_projid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_PROJID);
		break;
	case AC_PROC_TASKID:
		(void) ea_attach_item(record, &pu->pu_taskid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_TASKID);
		break;
	case AC_PROC_CPU:
		(void) ea_attach_item(record, &pu->pu_utimesec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CPU_USER_SEC);
		(void) ea_attach_item(record, &pu->pu_utimensec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CPU_USER_NSEC);
		(void) ea_attach_item(record, &pu->pu_stimesec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CPU_SYS_SEC);
		(void) ea_attach_item(record, &pu->pu_stimensec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CPU_SYS_NSEC);
		break;
	case AC_PROC_TIME:
		(void) ea_attach_item(record, &pu->pu_startsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_START_SEC);
		(void) ea_attach_item(record, &pu->pu_startnsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_START_NSEC);
		(void) ea_attach_item(record, &pu->pu_finishsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_FINISH_SEC);
		(void) ea_attach_item(record, &pu->pu_finishnsec,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_FINISH_NSEC);
		break;
	case AC_PROC_COMMAND:
		(void) ea_attach_item(record, pu->pu_command,
		    strlen(pu->pu_command) + 1, EXT_STRING | EXD_PROC_COMMAND);
		break;
	case AC_PROC_HOSTNAME:
		(void) ea_attach_item(record, pu->pu_nodename,
		    strlen(pu->pu_nodename) + 1,
		    EXT_STRING | EXD_PROC_HOSTNAME);
		break;
	case AC_PROC_TTY:
		(void) ea_attach_item(record, &pu->pu_major,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_TTY_MAJOR);
		(void) ea_attach_item(record, &pu->pu_minor,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_TTY_MINOR);
		break;
	case AC_PROC_MICROSTATE:
		(void) ea_attach_item(record, &pu->pu_majflt,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_FAULTS_MAJOR);
		(void) ea_attach_item(record, &pu->pu_minflt,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_FAULTS_MINOR);
		(void) ea_attach_item(record, &pu->pu_sndmsg,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_MESSAGES_SND);
		(void) ea_attach_item(record, &pu->pu_rcvmsg,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_MESSAGES_RCV);
		(void) ea_attach_item(record, &pu->pu_iblk,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_BLOCKS_IN);
		(void) ea_attach_item(record, &pu->pu_oblk,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_BLOCKS_OUT);
		(void) ea_attach_item(record, &pu->pu_ioch,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CHARS_RDWR);
		(void) ea_attach_item(record, &pu->pu_vcsw,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CONTEXT_VOL);
		(void) ea_attach_item(record, &pu->pu_icsw,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_CONTEXT_INV);
		(void) ea_attach_item(record, &pu->pu_nsig,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_SIGNALS);
		(void) ea_attach_item(record, &pu->pu_nswp,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_SWAPS);
		(void) ea_attach_item(record, &pu->pu_nscl,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_SYSCALLS);
		break;
	case AC_PROC_ANCPID:
		(void) ea_attach_item(record, &pu->pu_ancpid,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_ANCPID);
		break;
	case AC_PROC_WAIT_STATUS:
		(void) ea_attach_item(record, &pu->pu_wstat,
		    sizeof (uint32_t), EXT_UINT32 | EXD_PROC_WAIT_STATUS);
		break;
	case AC_PROC_ZONENAME:
		(void) ea_attach_item(record, pu->pu_zonename,
		    strlen(pu->pu_zonename) + 1,
		    EXT_STRING | EXD_PROC_ZONENAME);
		break;
	case AC_PROC_MEM:
		(void) ea_attach_item(record, &pu->pu_mem_rss_avg,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_MEM_RSS_AVG_K);
		(void) ea_attach_item(record, &pu->pu_mem_rss_max,
		    sizeof (uint64_t), EXT_UINT64 | EXD_PROC_MEM_RSS_MAX_K);
		break;
	default:
		attached = 0;
	}
	return (attached);
}

static ea_object_t *
exacct_assemble_proc_record(proc_usage_t *pu, ulong_t *mask,
    ea_catalog_t record_type)
{
	int res, count;
	ea_object_t *record;

	/*
	 * Assemble usage values into group.
	 */
	record = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | record_type);
	for (res = 1, count = 0; res <= AC_PROC_MAX_RES; res++)
		if (BT_TEST(mask, res))
			count += exacct_attach_proc_item(pu, record, res);
	if (count == 0) {
		ea_free_object(record, EUP_ALLOC);
		record = NULL;
	}
	return (record);
}

/*
 * The following two routines assume that process's p_lock is held or
 * exacct_commit_proc has been called from exit() when all lwps are stopped.
 */
static void
exacct_calculate_proc_mstate(proc_t *p, proc_usage_t *pu)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));
	if ((t = p->p_tlist) == NULL)
		return;

	do {
		pu->pu_minflt	+= t->t_lwp->lwp_ru.minflt;
		pu->pu_majflt	+= t->t_lwp->lwp_ru.majflt;
		pu->pu_sndmsg	+= t->t_lwp->lwp_ru.msgsnd;
		pu->pu_rcvmsg	+= t->t_lwp->lwp_ru.msgrcv;
		pu->pu_ioch	+= t->t_lwp->lwp_ru.ioch;
		pu->pu_iblk	+= t->t_lwp->lwp_ru.inblock;
		pu->pu_oblk	+= t->t_lwp->lwp_ru.oublock;
		pu->pu_vcsw	+= t->t_lwp->lwp_ru.nvcsw;
		pu->pu_icsw	+= t->t_lwp->lwp_ru.nivcsw;
		pu->pu_nsig	+= t->t_lwp->lwp_ru.nsignals;
		pu->pu_nswp	+= t->t_lwp->lwp_ru.nswap;
		pu->pu_nscl	+= t->t_lwp->lwp_ru.sysc;
	} while ((t = t->t_forw) != p->p_tlist);
}

static void
exacct_copy_proc_mstate(proc_t *p, proc_usage_t *pu)
{
	pu->pu_minflt	= p->p_ru.minflt;
	pu->pu_majflt	= p->p_ru.majflt;
	pu->pu_sndmsg	= p->p_ru.msgsnd;
	pu->pu_rcvmsg	= p->p_ru.msgrcv;
	pu->pu_ioch	= p->p_ru.ioch;
	pu->pu_iblk	= p->p_ru.inblock;
	pu->pu_oblk	= p->p_ru.oublock;
	pu->pu_vcsw	= p->p_ru.nvcsw;
	pu->pu_icsw	= p->p_ru.nivcsw;
	pu->pu_nsig	= p->p_ru.nsignals;
	pu->pu_nswp	= p->p_ru.nswap;
	pu->pu_nscl	= p->p_ru.sysc;
}

void
exacct_calculate_proc_usage(proc_t *p, proc_usage_t *pu, ulong_t *mask,
    int flag, int wstat)
{
	timestruc_t ts, ts_run;

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * Convert CPU and execution times to sec/nsec format.
	 */
	if (BT_TEST(mask, AC_PROC_CPU)) {
		hrt2ts(mstate_aggr_state(p, LMS_USER), &ts);
		pu->pu_utimesec = (uint64_t)(ulong_t)ts.tv_sec;
		pu->pu_utimensec = (uint64_t)(ulong_t)ts.tv_nsec;
		hrt2ts(mstate_aggr_state(p, LMS_SYSTEM), &ts);
		pu->pu_stimesec = (uint64_t)(ulong_t)ts.tv_sec;
		pu->pu_stimensec = (uint64_t)(ulong_t)ts.tv_nsec;
	}
	if (BT_TEST(mask, AC_PROC_TIME)) {
		gethrestime(&ts);
		pu->pu_finishsec = (uint64_t)(ulong_t)ts.tv_sec;
		pu->pu_finishnsec = (uint64_t)(ulong_t)ts.tv_nsec;
		hrt2ts(gethrtime() - p->p_mstart, &ts_run);
		ts.tv_sec -= ts_run.tv_sec;
		ts.tv_nsec -= ts_run.tv_nsec;
		if (ts.tv_nsec < 0) {
			ts.tv_sec--;
			if ((ts.tv_nsec = ts.tv_nsec + NANOSEC) >= NANOSEC) {
				ts.tv_sec++;
				ts.tv_nsec -= NANOSEC;
			}
		}
		pu->pu_startsec = (uint64_t)(ulong_t)ts.tv_sec;
		pu->pu_startnsec = (uint64_t)(ulong_t)ts.tv_nsec;
	}

	pu->pu_pid = p->p_pidp->pid_id;
	pu->pu_acflag = p->p_user.u_acflag;
	pu->pu_projid = p->p_task->tk_proj->kpj_id;
	pu->pu_taskid = p->p_task->tk_tkid;
	pu->pu_major = getmajor(p->p_sessp->s_dev);
	pu->pu_minor = getminor(p->p_sessp->s_dev);
	pu->pu_ancpid = p->p_ancpid;
	pu->pu_wstat = wstat;
	/*
	 * Compute average RSS in K.  The denominator is the number of
	 * samples:  the number of clock ticks plus the initial value.
	 */
	pu->pu_mem_rss_avg = (PTOU(p)->u_mem / (p->p_stime + p->p_utime + 1)) *
	    (PAGESIZE / 1024);
	pu->pu_mem_rss_max = PTOU(p)->u_mem_max * (PAGESIZE / 1024);

	mutex_enter(&p->p_crlock);
	pu->pu_ruid = crgetruid(p->p_cred);
	pu->pu_rgid = crgetrgid(p->p_cred);
	mutex_exit(&p->p_crlock);

	bcopy(p->p_user.u_comm, pu->pu_command, strlen(p->p_user.u_comm) + 1);
	bcopy(p->p_zone->zone_name, pu->pu_zonename,
	    strlen(p->p_zone->zone_name) + 1);
	bcopy(p->p_zone->zone_nodename, pu->pu_nodename,
	    strlen(p->p_zone->zone_nodename) + 1);

	/*
	 * Calculate microstate accounting data for a process that is still
	 * running.  Presently, we explicitly collect all of the LWP usage into
	 * the proc usage structure here.
	 */
	if (flag & EW_PARTIAL)
		exacct_calculate_proc_mstate(p, pu);
	if (flag & EW_FINAL)
		exacct_copy_proc_mstate(p, pu);
}

/*
 * int exacct_assemble_proc_usage(proc_usage_t *, int (*)(void *, size_t, void
 *	*, size_t, size_t *), void *, size_t, size_t *)
 *
 * Overview
 *   Assemble record with miscellaneous accounting information about the process
 *   and execute the callback on it. It is the callback's job to set "actual" to
 *   the size of record.
 *
 * Return values
 *   The result of the callback function, unless the extended process accounting
 *   feature is not active, in which case ENOTACTIVE is returned.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
int
exacct_assemble_proc_usage(ac_info_t *ac_proc, proc_usage_t *pu,
    int (*callback)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *ubuf, size_t ubufsize, size_t *actual, int flag)
{
	ulong_t mask[AC_MASK_SZ];
	ea_object_t *proc_record;
	ea_catalog_t record_type;
	void *buf;
	size_t bufsize;
	int ret;

	ASSERT(flag == EW_FINAL || flag == EW_PARTIAL);

	mutex_enter(&ac_proc->ac_lock);
	if (ac_proc->ac_state == AC_OFF) {
		mutex_exit(&ac_proc->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_proc->ac_mask[0], mask, AC_MASK_SZ);
	mutex_exit(&ac_proc->ac_lock);

	switch (flag) {
	case EW_FINAL:
		record_type = EXD_GROUP_PROC;
		break;
	case EW_PARTIAL:
		record_type = EXD_GROUP_PROC_PARTIAL;
		break;
	}

	proc_record = exacct_assemble_proc_record(pu, mask, record_type);
	if (proc_record == NULL)
		return (0);

	/*
	 * Pack object into buffer and pass to callback.
	 */
	bufsize = ea_pack_object(proc_record, NULL, 0);
	buf = kmem_alloc(bufsize, KM_SLEEP);
	(void) ea_pack_object(proc_record, buf, bufsize);

	ret = callback(ac_proc, ubuf, ubufsize, buf, bufsize, actual);

	/*
	 * Free all previously allocations.
	 */
	kmem_free(buf, bufsize);
	ea_free_object(proc_record, EUP_ALLOC);
	return (ret);
}

/*
 * int exacct_commit_callback(ac_info_t *, void *, size_t, void *, size_t,
 * 	size_t *)
 *
 * Overview
 *   exacct_commit_callback() writes the indicated buffer to the indicated
 *   extended accounting file.
 *
 * Return values
 *   The result of the write operation is returned.  "actual" is updated to
 *   contain the number of bytes actually written.
 *
 * Caller's context
 *   Suitable for a vn_rdwr() operation.
 */
/*ARGSUSED*/
int
exacct_commit_callback(ac_info_t *info, void *ubuf, size_t ubufsize,
    void *buf, size_t bufsize, size_t *actual)
{
	int error = 0;

	*actual = 0;
	if ((error = exacct_vn_write(info, buf, bufsize)) == 0)
		*actual = bufsize;
	return (error);
}

static void
exacct_do_commit_proc(ac_info_t *ac_proc, proc_t *p, int wstat)
{
	size_t size;
	proc_usage_t *pu;
	ulong_t mask[AC_MASK_SZ];

	mutex_enter(&ac_proc->ac_lock);
	if (ac_proc->ac_state == AC_ON) {
		bt_copy(&ac_proc->ac_mask[0], mask, AC_MASK_SZ);
		mutex_exit(&ac_proc->ac_lock);
	} else {
		mutex_exit(&ac_proc->ac_lock);
		return;
	}

	mutex_enter(&p->p_lock);
	size = strlen(p->p_user.u_comm) + 1;
	mutex_exit(&p->p_lock);

	pu = kmem_alloc(sizeof (proc_usage_t), KM_SLEEP);
	pu->pu_command = kmem_alloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	exacct_calculate_proc_usage(p, pu, mask, EW_FINAL, wstat);
	mutex_exit(&p->p_lock);

	(void) exacct_assemble_proc_usage(ac_proc, pu,
	    exacct_commit_callback, NULL, 0, &size, EW_FINAL);

	kmem_free(pu->pu_command, strlen(pu->pu_command) + 1);
	kmem_free(pu, sizeof (proc_usage_t));
}

/*
 * void exacct_commit_proc(proc_t *, int)
 *
 * Overview
 *   exacct_commit_proc() calculates the final usage for a process, updating the
 *   task usage if task accounting is active, and writing a process record if
 *   process accounting is active.  exacct_commit_proc() is intended for being
 *   called from proc_exit().
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.  p_lock must not be held at entry.
 */
void
exacct_commit_proc(proc_t *p, int wstat)
{
	zone_t *zone = p->p_zone;
	struct exacct_globals *acg, *gacg = NULL;

	if (exacct_zone_key == ZONE_KEY_UNINITIALIZED) {
		/*
		 * acctctl module not loaded.  Nothing to do.
		 */
		return;
	}

	/*
	 * If acctctl module is loaded when zone is in down state then
	 * zone_getspecific can return NULL for that zone.
	 */
	acg = zone_getspecific(exacct_zone_key, zone);
	if (acg == NULL)
		return;
	exacct_do_commit_proc(&acg->ac_proc, p, wstat);
	if (zone != global_zone) {
		gacg = zone_getspecific(exacct_zone_key, global_zone);
		exacct_do_commit_proc(&gacg->ac_proc, p, wstat);
	}
}

static int
exacct_attach_netstat_item(net_stat_t *ns, ea_object_t *record, int res)
{
	int		attached = 1;

	switch (res) {
	case AC_NET_NAME:
		(void) ea_attach_item(record, ns->ns_name,
		    strlen(ns->ns_name) + 1, EXT_STRING | EXD_NET_STATS_NAME);
		break;
	case AC_NET_CURTIME:
		{
			uint64_t	now;
			timestruc_t	ts;

			gethrestime(&ts);
			now = (uint64_t)(ulong_t)ts.tv_sec;
			(void) ea_attach_item(record,  &now, sizeof (uint64_t),
			    EXT_UINT64 | EXD_NET_STATS_CURTIME);
		}
		break;
	case AC_NET_IBYTES:
		(void) ea_attach_item(record, &ns->ns_ibytes,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_IBYTES);
		break;
	case AC_NET_OBYTES:
		(void) ea_attach_item(record, &ns->ns_obytes,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_OBYTES);
		break;
	case AC_NET_IPKTS:
		(void) ea_attach_item(record, &ns->ns_ipackets,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_IPKTS);
		break;
	case AC_NET_OPKTS:
		(void) ea_attach_item(record, &ns->ns_opackets,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_OPKTS);
		break;
	case AC_NET_IERRPKTS:
		(void) ea_attach_item(record, &ns->ns_ierrors,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_IERRPKTS);
		break;
	case AC_NET_OERRPKTS:
		(void) ea_attach_item(record, &ns->ns_oerrors,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_STATS_OERRPKTS);
		break;
	default:
		attached = 0;
	}
	return (attached);
}

static int
exacct_attach_netdesc_item(net_desc_t *nd, ea_object_t *record, int res)
{
	int attached = 1;

	switch (res) {
	case AC_NET_NAME:
		(void) ea_attach_item(record, nd->nd_name,
		    strlen(nd->nd_name) + 1, EXT_STRING | EXD_NET_DESC_NAME);
		break;
	case AC_NET_DEVNAME:
		(void) ea_attach_item(record, nd->nd_devname,
		    strlen(nd->nd_devname) + 1, EXT_STRING |
		    EXD_NET_DESC_DEVNAME);
		break;
	case AC_NET_EHOST:
		(void) ea_attach_item(record, &nd->nd_ehost,
		    sizeof (nd->nd_ehost), EXT_RAW | EXD_NET_DESC_EHOST);
		break;
	case AC_NET_EDEST:
		(void) ea_attach_item(record, &nd->nd_edest,
		    sizeof (nd->nd_edest), EXT_RAW | EXD_NET_DESC_EDEST);
		break;
	case AC_NET_VLAN_TPID:
		(void) ea_attach_item(record, &nd->nd_vlan_tpid,
		    sizeof (ushort_t), EXT_UINT16 | EXD_NET_DESC_VLAN_TPID);
		break;
	case AC_NET_VLAN_TCI:
		(void) ea_attach_item(record, &nd->nd_vlan_tci,
		    sizeof (ushort_t), EXT_UINT16 | EXD_NET_DESC_VLAN_TCI);
		break;
	case AC_NET_SAP:
		(void) ea_attach_item(record, &nd->nd_sap,
		    sizeof (ushort_t), EXT_UINT16 | EXD_NET_DESC_SAP);
		break;
	case AC_NET_PRIORITY:
		(void) ea_attach_item(record, &nd->nd_priority,
		    sizeof (ushort_t), EXT_UINT16 | EXD_NET_DESC_PRIORITY);
		break;
	case AC_NET_BWLIMIT:
		(void) ea_attach_item(record, &nd->nd_bw_limit,
		    sizeof (uint64_t), EXT_UINT64 | EXD_NET_DESC_BWLIMIT);
		break;
	case AC_NET_SADDR:
		if (nd->nd_isv4) {
			(void) ea_attach_item(record, &nd->nd_saddr[3],
			    sizeof (uint32_t), EXT_UINT32 |
			    EXD_NET_DESC_V4SADDR);
		} else {
			(void) ea_attach_item(record, &nd->nd_saddr,
			    sizeof (nd->nd_saddr), EXT_RAW |
			    EXD_NET_DESC_V6SADDR);
		}
		break;
	case AC_NET_DADDR:
		if (nd->nd_isv4) {
			(void) ea_attach_item(record, &nd->nd_daddr[3],
			    sizeof (uint32_t), EXT_UINT32 |
			    EXD_NET_DESC_V4DADDR);
		} else {
			(void) ea_attach_item(record, &nd->nd_daddr,
			    sizeof (nd->nd_daddr), EXT_RAW |
			    EXD_NET_DESC_V6DADDR);
		}
		break;
	case AC_NET_SPORT:
		(void) ea_attach_item(record, &nd->nd_sport,
		    sizeof (uint16_t), EXT_UINT16 | EXD_NET_DESC_SPORT);
		break;
	case AC_NET_DPORT:
		(void) ea_attach_item(record, &nd->nd_dport,
		    sizeof (uint16_t), EXT_UINT16 | EXD_NET_DESC_DPORT);
		break;
	case AC_NET_PROTOCOL:
		(void) ea_attach_item(record, &nd->nd_protocol,
		    sizeof (uint8_t), EXT_UINT8 | EXD_NET_DESC_PROTOCOL);
		break;
	case AC_NET_DSFIELD:
		(void) ea_attach_item(record, &nd->nd_dsfield,
		    sizeof (uint8_t), EXT_UINT8 | EXD_NET_DESC_DSFIELD);
		break;
	default:
		attached = 0;
	}
	return (attached);
}

static ea_object_t *
exacct_assemble_net_record(void *ninfo, ulong_t *mask, ea_catalog_t record_type,
    int what)
{
	int		res;
	int		count;
	ea_object_t	*record;

	/*
	 * Assemble usage values into group.
	 */
	record = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | record_type);
	for (res = 1, count = 0; res <= AC_NET_MAX_RES; res++)
		if (BT_TEST(mask, res)) {
			if (what == EX_NET_LNDESC_REC ||
			    what == EX_NET_FLDESC_REC) {
				count += exacct_attach_netdesc_item(
				    (net_desc_t *)ninfo, record, res);
			} else {
				count += exacct_attach_netstat_item(
				    (net_stat_t *)ninfo, record, res);
			}
		}
	if (count == 0) {
		ea_free_object(record, EUP_ALLOC);
		record = NULL;
	}
	return (record);
}

int
exacct_assemble_net_usage(ac_info_t *ac_net, void *ninfo,
    int (*callback)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *ubuf, size_t ubufsize, size_t *actual, int what)
{
	ulong_t		mask[AC_MASK_SZ];
	ea_object_t	*net_desc;
	ea_catalog_t	record_type;
	void		*buf;
	size_t		bufsize;
	int		ret;

	mutex_enter(&ac_net->ac_lock);
	if (ac_net->ac_state == AC_OFF) {
		mutex_exit(&ac_net->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_net->ac_mask[0], mask, AC_MASK_SZ);
	mutex_exit(&ac_net->ac_lock);

	switch (what) {
	case EX_NET_LNDESC_REC:
		record_type = EXD_GROUP_NET_LINK_DESC;
		break;
	case EX_NET_LNSTAT_REC:
		record_type = EXD_GROUP_NET_LINK_STATS;
		break;
	case EX_NET_FLDESC_REC:
		record_type = EXD_GROUP_NET_FLOW_DESC;
		break;
	case EX_NET_FLSTAT_REC:
		record_type = EXD_GROUP_NET_FLOW_STATS;
		break;
	}

	net_desc = exacct_assemble_net_record(ninfo, mask, record_type, what);
	if (net_desc == NULL)
		return (0);

	/*
	 * Pack object into buffer and pass to callback.
	 */
	bufsize = ea_pack_object(net_desc, NULL, 0);
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL)
		return (ENOMEM);

	(void) ea_pack_object(net_desc, buf, bufsize);

	ret = callback(ac_net, ubuf, ubufsize, buf, bufsize, actual);

	/*
	 * Free all previously allocations.
	 */
	kmem_free(buf, bufsize);
	ea_free_object(net_desc, EUP_ALLOC);
	return (ret);
}

int
exacct_commit_netinfo(void *arg, int what)
{
	size_t			size;
	ulong_t			mask[AC_MASK_SZ];
	struct exacct_globals	*acg;
	ac_info_t		*ac_net;

	if (exacct_zone_key == ZONE_KEY_UNINITIALIZED) {
		/*
		 * acctctl module not loaded. Nothing to do.
		 */
		return (ENOTACTIVE);
	}

	/*
	 * Even though each zone nominally has its own flow accounting settings
	 * (ac_flow), these are only maintained by and for the global zone.
	 *
	 * If this were to change in the future, this function should grow a
	 * second zoneid (or zone) argument, and use the corresponding zone's
	 * settings rather than always using those of the global zone.
	 */
	acg = zone_getspecific(exacct_zone_key, global_zone);
	ac_net = &acg->ac_net;

	mutex_enter(&ac_net->ac_lock);
	if (ac_net->ac_state == AC_OFF) {
		mutex_exit(&ac_net->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_net->ac_mask[0], mask, AC_MASK_SZ);
	mutex_exit(&ac_net->ac_lock);

	return (exacct_assemble_net_usage(ac_net, arg, exacct_commit_callback,
	    NULL, 0, &size, what));
}

static int
exacct_attach_flow_item(flow_usage_t *fu, ea_object_t *record, int res)
{
	int attached = 1;

	switch (res) {
	case AC_FLOW_SADDR:
		if (fu->fu_isv4) {
			(void) ea_attach_item(record, &fu->fu_saddr[3],
			    sizeof (uint32_t), EXT_UINT32 | EXD_FLOW_V4SADDR);
		} else {
			(void) ea_attach_item(record, &fu->fu_saddr,
			    sizeof (fu->fu_saddr), EXT_RAW |
			    EXD_FLOW_V6SADDR);
		}
		break;
	case AC_FLOW_DADDR:
		if (fu->fu_isv4) {
			(void) ea_attach_item(record, &fu->fu_daddr[3],
			    sizeof (uint32_t), EXT_UINT32 | EXD_FLOW_V4DADDR);
		} else {
			(void) ea_attach_item(record, &fu->fu_daddr,
			    sizeof (fu->fu_daddr), EXT_RAW |
			    EXD_FLOW_V6DADDR);
		}
		break;
	case AC_FLOW_SPORT:
		(void) ea_attach_item(record, &fu->fu_sport,
		    sizeof (uint16_t), EXT_UINT16 | EXD_FLOW_SPORT);
		break;
	case AC_FLOW_DPORT:
		(void) ea_attach_item(record, &fu->fu_dport,
		    sizeof (uint16_t), EXT_UINT16 | EXD_FLOW_DPORT);
		break;
	case AC_FLOW_PROTOCOL:
		(void) ea_attach_item(record, &fu->fu_protocol,
		    sizeof (uint8_t), EXT_UINT8 | EXD_FLOW_PROTOCOL);
		break;
	case AC_FLOW_DSFIELD:
		(void) ea_attach_item(record, &fu->fu_dsfield,
		    sizeof (uint8_t), EXT_UINT8 | EXD_FLOW_DSFIELD);
		break;
	case AC_FLOW_CTIME:
		(void) ea_attach_item(record, &fu->fu_ctime,
		    sizeof (uint64_t), EXT_UINT64 | EXD_FLOW_CTIME);
		break;
	case AC_FLOW_LSEEN:
		(void) ea_attach_item(record, &fu->fu_lseen,
		    sizeof (uint64_t), EXT_UINT64 | EXD_FLOW_LSEEN);
		break;
	case AC_FLOW_NBYTES:
		(void) ea_attach_item(record, &fu->fu_nbytes,
		    sizeof (uint64_t), EXT_UINT32 | EXD_FLOW_NBYTES);
		break;
	case AC_FLOW_NPKTS:
		(void) ea_attach_item(record, &fu->fu_npackets,
		    sizeof (uint64_t), EXT_UINT32 | EXD_FLOW_NPKTS);
		break;
	case AC_FLOW_PROJID:
		if (fu->fu_projid >= 0) {
			(void) ea_attach_item(record, &fu->fu_projid,
			    sizeof (uint32_t), EXT_UINT32 | EXD_FLOW_PROJID);
		}
		break;
	case AC_FLOW_UID:
		if (fu->fu_userid >= 0) {
			(void) ea_attach_item(record, &fu->fu_userid,
			    sizeof (uint32_t), EXT_UINT32 | EXD_FLOW_UID);
		}
		break;
	case AC_FLOW_ANAME:
		(void) ea_attach_item(record, fu->fu_aname,
		    strlen(fu->fu_aname) + 1, EXT_STRING | EXD_FLOW_ANAME);
		break;
	default:
		attached = 0;
	}
	return (attached);
}

static ea_object_t *
exacct_assemble_flow_record(flow_usage_t *fu, ulong_t *mask,
    ea_catalog_t record_type)
{
	int res, count;
	ea_object_t *record;

	/*
	 * Assemble usage values into group.
	 */
	record = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | record_type);
	for (res = 1, count = 0; res <= AC_FLOW_MAX_RES; res++)
		if (BT_TEST(mask, res))
			count += exacct_attach_flow_item(fu, record, res);
	if (count == 0) {
		ea_free_object(record, EUP_ALLOC);
		record = NULL;
	}
	return (record);
}

int
exacct_assemble_flow_usage(ac_info_t *ac_flow, flow_usage_t *fu,
    int (*callback)(ac_info_t *, void *, size_t, void *, size_t, size_t *),
    void *ubuf, size_t ubufsize, size_t *actual)
{
	ulong_t mask[AC_MASK_SZ];
	ea_object_t *flow_usage;
	ea_catalog_t record_type;
	void *buf;
	size_t bufsize;
	int ret;

	mutex_enter(&ac_flow->ac_lock);
	if (ac_flow->ac_state == AC_OFF) {
		mutex_exit(&ac_flow->ac_lock);
		return (ENOTACTIVE);
	}
	bt_copy(&ac_flow->ac_mask[0], mask, AC_MASK_SZ);
	mutex_exit(&ac_flow->ac_lock);

	record_type = EXD_GROUP_FLOW;

	flow_usage = exacct_assemble_flow_record(fu, mask, record_type);
	if (flow_usage == NULL) {
		return (0);
	}

	/*
	 * Pack object into buffer and pass to callback.
	 */
	bufsize = ea_pack_object(flow_usage, NULL, 0);
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL) {
		return (ENOMEM);
	}

	(void) ea_pack_object(flow_usage, buf, bufsize);

	ret = callback(ac_flow, ubuf, ubufsize, buf, bufsize, actual);

	/*
	 * Free all previously allocations.
	 */
	kmem_free(buf, bufsize);
	ea_free_object(flow_usage, EUP_ALLOC);
	return (ret);
}

void
exacct_commit_flow(void *arg)
{
	flow_usage_t *f = (flow_usage_t *)arg;
	size_t size;
	ulong_t mask[AC_MASK_SZ];
	struct exacct_globals *acg;
	ac_info_t *ac_flow;

	if (exacct_zone_key == ZONE_KEY_UNINITIALIZED) {
		/*
		 * acctctl module not loaded. Nothing to do.
		 */
		return;
	}

	/*
	 * Even though each zone nominally has its own flow accounting settings
	 * (ac_flow), these are only maintained by and for the global zone.
	 *
	 * If this were to change in the future, this function should grow a
	 * second zoneid (or zone) argument, and use the corresponding zone's
	 * settings rather than always using those of the global zone.
	 */
	acg = zone_getspecific(exacct_zone_key, global_zone);
	ac_flow = &acg->ac_flow;

	mutex_enter(&ac_flow->ac_lock);
	if (ac_flow->ac_state == AC_OFF) {
		mutex_exit(&ac_flow->ac_lock);
		return;
	}
	bt_copy(&ac_flow->ac_mask[0], mask, AC_MASK_SZ);
	mutex_exit(&ac_flow->ac_lock);

	(void) exacct_assemble_flow_usage(ac_flow, f, exacct_commit_callback,
	    NULL, 0, &size);
}

/*
 * int exacct_tag_task(task_t *, void *, size_t, int)
 *
 * Overview
 *   exacct_tag_task() provides the exacct record construction and writing
 *   support required by putacct(2) for task entities.
 *
 * Return values
 *   The result of the write operation is returned, unless the extended
 *   accounting facility is not active, in which case ENOTACTIVE is returned.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
int
exacct_tag_task(ac_info_t *ac_task, task_t *tk, void *ubuf, size_t ubufsz,
    int flags)
{
	int error = 0;
	void *buf;
	size_t bufsize;
	ea_catalog_t cat;
	ea_object_t *tag;

	mutex_enter(&ac_task->ac_lock);
	if (ac_task->ac_state == AC_OFF || ac_task->ac_vnode == NULL) {
		mutex_exit(&ac_task->ac_lock);
		return (ENOTACTIVE);
	}
	mutex_exit(&ac_task->ac_lock);

	tag = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | EXD_GROUP_TASK_TAG);
	(void) ea_attach_item(tag, &tk->tk_tkid, 0,
	    EXT_UINT32 | EXC_DEFAULT | EXD_TASK_TASKID);
	(void) ea_attach_item(tag, tk->tk_zone->zone_nodename, 0,
	    EXT_STRING | EXC_DEFAULT | EXD_TASK_HOSTNAME);
	if (flags == EP_RAW)
		cat = EXT_RAW | EXC_DEFAULT | EXD_TASK_TAG;
	else
		cat = EXT_EXACCT_OBJECT | EXC_DEFAULT | EXD_TASK_TAG;
	(void) ea_attach_item(tag, ubuf, ubufsz, cat);

	bufsize = ea_pack_object(tag, NULL, 0);
	buf = kmem_alloc(bufsize, KM_SLEEP);
	(void) ea_pack_object(tag, buf, bufsize);
	error = exacct_vn_write(ac_task, buf, bufsize);
	kmem_free(buf, bufsize);
	ea_free_object(tag, EUP_ALLOC);
	return (error);
}

/*
 * exacct_tag_proc(pid_t, taskid_t, void *, size_t, int, char *)
 *
 * Overview
 *   exacct_tag_proc() provides the exacct record construction and writing
 *   support required by putacct(2) for processes.
 *
 * Return values
 *   The result of the write operation is returned, unless the extended
 *   accounting facility is not active, in which case ENOTACTIVE is returned.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
int
exacct_tag_proc(ac_info_t *ac_proc, pid_t pid, taskid_t tkid, void *ubuf,
    size_t ubufsz, int flags, const char *hostname)
{
	int error = 0;
	void *buf;
	size_t bufsize;
	ea_catalog_t cat;
	ea_object_t *tag;

	mutex_enter(&ac_proc->ac_lock);
	if (ac_proc->ac_state == AC_OFF || ac_proc->ac_vnode == NULL) {
		mutex_exit(&ac_proc->ac_lock);
		return (ENOTACTIVE);
	}
	mutex_exit(&ac_proc->ac_lock);

	tag = ea_alloc_group(EXT_GROUP | EXC_DEFAULT | EXD_GROUP_PROC_TAG);
	(void) ea_attach_item(tag, &pid, sizeof (uint32_t),
	    EXT_UINT32 | EXC_DEFAULT | EXD_PROC_PID);
	(void) ea_attach_item(tag, &tkid, 0,
	    EXT_UINT32 | EXC_DEFAULT | EXD_TASK_TASKID);
	(void) ea_attach_item(tag, (void *)hostname, 0,
	    EXT_STRING | EXC_DEFAULT | EXD_TASK_HOSTNAME);
	if (flags == EP_RAW)
		cat = EXT_RAW | EXC_DEFAULT | EXD_PROC_TAG;
	else
		cat = EXT_EXACCT_OBJECT | EXC_DEFAULT | EXD_PROC_TAG;
	(void) ea_attach_item(tag, ubuf, ubufsz, cat);

	bufsize = ea_pack_object(tag, NULL, 0);
	buf = kmem_alloc(bufsize, KM_SLEEP);
	(void) ea_pack_object(tag, buf, bufsize);
	error = exacct_vn_write(ac_proc, buf, bufsize);
	kmem_free(buf, bufsize);
	ea_free_object(tag, EUP_ALLOC);
	return (error);
}

/*
 * void exacct_init(void)
 *
 * Overview
 *   Initialized the extended accounting subsystem.
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   Suitable for KM_SLEEP allocations.
 */
void
exacct_init()
{
	exacct_queue = system_taskq;
	exacct_object_cache = kmem_cache_create("exacct_object_cache",
	    sizeof (ea_object_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	task_commit_thread_init();
}

/*
 * exacct_snapshot_proc_mstate() copies a process's microstate accounting data
 * and resource usage counters into a given task_usage_t. It differs from
 * exacct_copy_proc_mstate() in that here a) we are copying to a task_usage_t,
 * b) p_lock will have been acquired earlier in the call path and c) we
 * are here including the process's user and system times.
 */
static void
exacct_snapshot_proc_mstate(proc_t *p, task_usage_t *tu)
{
	tu->tu_utime  = mstate_aggr_state(p, LMS_USER);
	tu->tu_stime  = mstate_aggr_state(p, LMS_SYSTEM);
	tu->tu_minflt = p->p_ru.minflt;
	tu->tu_majflt = p->p_ru.majflt;
	tu->tu_sndmsg = p->p_ru.msgsnd;
	tu->tu_rcvmsg = p->p_ru.msgrcv;
	tu->tu_ioch   = p->p_ru.ioch;
	tu->tu_iblk   = p->p_ru.inblock;
	tu->tu_oblk   = p->p_ru.oublock;
	tu->tu_vcsw   = p->p_ru.nvcsw;
	tu->tu_icsw   = p->p_ru.nivcsw;
	tu->tu_nsig   = p->p_ru.nsignals;
	tu->tu_nswp   = p->p_ru.nswap;
	tu->tu_nscl   = p->p_ru.sysc;
}

/*
 * void exacct_move_mstate(proc_t *, task_t *, task_t *)
 *
 * Overview
 *   exacct_move_mstate() is called by task_change() and accounts for
 *   a process's resource usage when it is moved from one task to another.
 *
 *   The process's usage at this point is recorded in the new task so
 *   that it can be excluded from the calculation of resources consumed
 *   by that task.
 *
 *   The resource usage inherited by the new task is also added to the
 *   aggregate maintained by the old task for processes that have exited.
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   pidlock and p_lock held across exacct_move_mstate().
 */
void
exacct_move_mstate(proc_t *p, task_t *oldtk, task_t *newtk)
{
	task_usage_t tu;

	/* Take a snapshot of this process's mstate and RU counters */
	exacct_snapshot_proc_mstate(p, &tu);

	/*
	 * Use the snapshot to increment the aggregate usage of the old
	 * task, and the inherited usage of the new one.
	 */
	mutex_enter(&oldtk->tk_usage_lock);
	exacct_add_task_mstate(oldtk->tk_usage, &tu);
	mutex_exit(&oldtk->tk_usage_lock);
	mutex_enter(&newtk->tk_usage_lock);
	exacct_add_task_mstate(newtk->tk_inherited, &tu);
	mutex_exit(&newtk->tk_usage_lock);
}
