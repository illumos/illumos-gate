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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>

#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/rctl.h>
#include <sys/rctl_impl.h>
#include <sys/strlog.h>
#include <sys/syslog.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/proc.h>
#include <sys/task.h>

/*
 * setrctl(2), getrctl(2), and private rctlsys(2*) system calls
 *
 * Resource control block (rctlblk_ptr_t, rctl_opaque_t)
 *   The resource control system call interfaces present the resource control
 *   values and flags via the resource control block abstraction, made manifest
 *   via an opaque data type with strict type definitions.  Keeping the formal
 *   definitions in the rcontrol block allows us to be clever in the kernel,
 *   combining attributes where appropriate in the current implementation while
 *   preserving binary compatibility in the face of implementation changes.
 */

#define	RBX_TO_BLK	0x1
#define	RBX_FROM_BLK	0x2
#define	RBX_VAL		0x4
#define	RBX_CTL		0x8

static void
rctlsys_rblk_xfrm(rctl_opaque_t *blk, rctl_dict_entry_t *rde,
    rctl_val_t *val, int flags)
{
	if (flags & RBX_FROM_BLK) {
		if (flags & RBX_VAL) {
			/*
			 * Firing time cannot be set.
			 */
			val->rcv_privilege = blk->rcq_privilege;
			val->rcv_value = blk->rcq_value;
			val->rcv_flagaction = blk->rcq_local_flagaction;
			val->rcv_action_signal = blk->rcq_local_signal;
			val->rcv_action_recip_pid =
			    blk->rcq_local_recipient_pid;
		}
		if (flags & RBX_CTL) {
			rde->rcd_flagaction = blk->rcq_global_flagaction;
			rde->rcd_syslog_level = blk->rcq_global_syslog_level;

			/*
			 * Because the strlog() interface supports fewer options
			 * than are made available via the syslog() interface to
			 * userland, we map the syslog level down to a smaller
			 * set of distinct logging behaviours.
			 */
			rde->rcd_strlog_flags = 0;
			switch (blk->rcq_global_syslog_level) {
				case LOG_EMERG:
				case LOG_ALERT:
				case LOG_CRIT:
					rde->rcd_strlog_flags |= SL_CONSOLE;
					/*FALLTHROUGH*/
				case LOG_ERR:
					rde->rcd_strlog_flags |= SL_ERROR;
					/*FALLTHROUGH*/
				case LOG_WARNING:
					rde->rcd_strlog_flags |= SL_WARN;
					break;
				case LOG_NOTICE:
					rde->rcd_strlog_flags |= SL_CONSOLE;
					/*FALLTHROUGH*/
				case LOG_INFO:	/* informational */
				case LOG_DEBUG:	/* debug-level messages */
				default:
					rde->rcd_strlog_flags |= SL_NOTE;
					break;
			}
		}
	} else {
		bzero(blk,  sizeof (rctl_opaque_t));
		if (flags & RBX_VAL) {
			blk->rcq_privilege = val->rcv_privilege;
			blk->rcq_value = val->rcv_value;
			blk->rcq_enforced_value = rctl_model_value(rde,
			    curproc, val->rcv_value);
			blk->rcq_local_flagaction = val->rcv_flagaction;
			blk->rcq_local_signal = val->rcv_action_signal;
			blk->rcq_firing_time = val->rcv_firing_time;
			blk->rcq_local_recipient_pid =
			    val->rcv_action_recip_pid;
		}
		if (flags & RBX_CTL) {
			blk->rcq_global_flagaction = rde->rcd_flagaction;
			blk->rcq_global_syslog_level = rde->rcd_syslog_level;
		}
	}
}

/*
 * int rctl_invalid_value(rctl_dict_entry_t *, rctl_val_t *)
 *
 * Overview
 *   Perform basic validation of proposed new resource control value against the
 *   global properties set on the control.  Any system call operation presented
 *   with an invalid resource control value should return -1 and set errno to
 *   EINVAL.
 *
 * Return values
 *   0 if valid, 1 if invalid.
 *
 * Caller's context
 *   No restriction on context.
 */
int
rctl_invalid_value(rctl_dict_entry_t *rde, rctl_val_t *rval)
{
	rctl_val_t *sys_rval;

	if (rval->rcv_privilege != RCPRIV_BASIC &&
	    rval->rcv_privilege != RCPRIV_PRIVILEGED &&
	    rval->rcv_privilege != RCPRIV_SYSTEM)
		return (1);

	if (rval->rcv_flagaction & ~RCTL_LOCAL_MASK)
		return (1);

	if (rval->rcv_privilege == RCPRIV_BASIC &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_NOBASIC) != 0)
		return (1);

	if ((rval->rcv_flagaction & RCTL_LOCAL_DENY) == 0 &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_DENY_ALWAYS) != 0)
		return (1);

	if ((rval->rcv_flagaction & RCTL_LOCAL_DENY) &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_DENY_NEVER))
		return (1);

	if ((rval->rcv_flagaction & RCTL_LOCAL_SIGNAL) &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_SIGNAL_NEVER))
		return (1);

	if ((rval->rcv_flagaction & RCTL_LOCAL_SIGNAL) &&
	    rval->rcv_action_signal == 0)
		return (1);

	if (rval->rcv_action_signal == SIGXCPU &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_CPU_TIME) == 0)
		return (1);
	else if (rval->rcv_action_signal == SIGXFSZ &&
	    (rde->rcd_flagaction & RCTL_GLOBAL_FILE_SIZE) == 0)
		return (1);
	else if (rval->rcv_action_signal != SIGHUP &&
	    rval->rcv_action_signal != SIGABRT &&
	    rval->rcv_action_signal != SIGKILL &&
	    rval->rcv_action_signal != SIGTERM &&
	    rval->rcv_action_signal != SIGSTOP &&
	    rval->rcv_action_signal != SIGXCPU &&
	    rval->rcv_action_signal != SIGXFSZ &&
	    rval->rcv_action_signal != SIGXRES &&
	    rval->rcv_action_signal != 0)	/* That is, no signal is ok. */
		return (1);

	sys_rval = rde->rcd_default_value;
	while (sys_rval->rcv_privilege != RCPRIV_SYSTEM)
		sys_rval = sys_rval->rcv_next;

	if (rval->rcv_value > sys_rval->rcv_value)
		return (1);

	return (0);
}

/*
 * static long rctlsys_get(char *name, rctl_opaque_t *old_rblk,
 *   rctl_opaque_t *new_rblk, int flags)
 *
 * Overview
 *   rctlsys_get() is the implementation of the core logic of getrctl(2), the
 *   public system call for fetching resource control values.  Three mutually
 *   exclusive flag values are supported: RCTL_USAGE, RCTL_FIRST and RCTL_NEXT.
 *   When RCTL_USAGE is presented, the current usage for the resource control
 *   is returned in new_blk if the resource control provides an implementation
 *   of the usage operation.  When RCTL_FIRST is presented, the value of
 *   old_rblk is ignored, and the first value in the resource control value
 *   sequence for the named control is transformed and placed in the user
 *   memory location at new_rblk.  In the RCTL_NEXT case, the value of old_rblk
 *   is examined, and the next value in the sequence is transformed and placed
 *   at new_rblk.
 */
static long
rctlsys_get(char *name, rctl_opaque_t *old_rblk, rctl_opaque_t *new_rblk,
    int flags)
{
	rctl_val_t *nval;
	rctl_opaque_t *nblk;
	rctl_hndl_t hndl;
	char *kname;
	size_t klen;
	rctl_dict_entry_t *krde;
	int ret;
	int action = flags & (~RCTLSYS_ACTION_MASK);

	if (flags & (~RCTLSYS_MASK))
		return (set_errno(EINVAL));

	if (action != RCTL_FIRST && action != RCTL_NEXT &&
	    action != RCTL_USAGE)
		return (set_errno(EINVAL));

	if (new_rblk == NULL || name == NULL)
		return (set_errno(EFAULT));

	kname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	krde = kmem_alloc(sizeof (rctl_dict_entry_t), KM_SLEEP);

	if (copyinstr(name, kname, MAXPATHLEN, &klen) != 0) {
		kmem_free(kname, MAXPATHLEN);
		kmem_free(krde, sizeof (rctl_dict_entry_t));
		return (set_errno(EFAULT));
	}

	if ((hndl = rctl_hndl_lookup(kname)) == -1) {
		kmem_free(kname, MAXPATHLEN);
		kmem_free(krde, sizeof (rctl_dict_entry_t));
		return (set_errno(EINVAL));
	}

	if (rctl_global_get(kname, krde) == -1) {
		kmem_free(kname, MAXPATHLEN);
		kmem_free(krde, sizeof (rctl_dict_entry_t));
		return (set_errno(ESRCH));
	}

	kmem_free(kname, MAXPATHLEN);

	if (action != RCTL_USAGE)
		nval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);

	if (action == RCTL_USAGE) {
		rctl_set_t *rset;
		rctl_t *rctl;
		rctl_qty_t usage;

		mutex_enter(&curproc->p_lock);
		if ((rset = rctl_entity_obtain_rset(krde, curproc)) == NULL) {
			mutex_exit(&curproc->p_lock);
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(ESRCH));
		}
		mutex_enter(&rset->rcs_lock);
		if (rctl_set_find(rset, hndl, &rctl) == -1) {
			mutex_exit(&rset->rcs_lock);
			mutex_exit(&curproc->p_lock);
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(ESRCH));
		}
		if (RCTLOP_NO_USAGE(rctl)) {
			mutex_exit(&rset->rcs_lock);
			mutex_exit(&curproc->p_lock);
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(ENOTSUP));
		}
		usage = RCTLOP_GET_USAGE(rctl, curproc);
		mutex_exit(&rset->rcs_lock);
		mutex_exit(&curproc->p_lock);

		nblk = kmem_zalloc(sizeof (rctl_opaque_t), KM_SLEEP);
		nblk->rcq_value = usage;

		ret = copyout(nblk, new_rblk, sizeof (rctl_opaque_t));
		kmem_free(nblk, sizeof (rctl_opaque_t));
		kmem_free(krde, sizeof (rctl_dict_entry_t));
		return (ret == 0 ? 0 : set_errno(EFAULT));
	} else if (action == RCTL_FIRST) {

		mutex_enter(&curproc->p_lock);
		if (ret = rctl_local_get(hndl, NULL, nval, curproc)) {
			mutex_exit(&curproc->p_lock);
			kmem_cache_free(rctl_val_cache, nval);
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(ret));
		}
		mutex_exit(&curproc->p_lock);
	} else {
		/*
		 * RCTL_NEXT
		 */
		rctl_val_t *oval;
		rctl_opaque_t *oblk;

		oblk = kmem_alloc(sizeof (rctl_opaque_t), KM_SLEEP);

		if (copyin(old_rblk, oblk, sizeof (rctl_opaque_t)) == -1) {
			kmem_cache_free(rctl_val_cache, nval);
			kmem_free(oblk, sizeof (rctl_opaque_t));
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(EFAULT));
		}

		oval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);

		rctlsys_rblk_xfrm(oblk, NULL, oval, RBX_FROM_BLK | RBX_VAL);
		mutex_enter(&curproc->p_lock);
		ret = rctl_local_get(hndl, oval, nval, curproc);
		mutex_exit(&curproc->p_lock);

		kmem_cache_free(rctl_val_cache, oval);
		kmem_free(oblk, sizeof (rctl_opaque_t));

		if (ret != 0) {
			kmem_cache_free(rctl_val_cache, nval);
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			return (set_errno(ret));
		}
	}

	nblk = kmem_alloc(sizeof (rctl_opaque_t), KM_SLEEP);

	rctlsys_rblk_xfrm(nblk, krde, nval, RBX_TO_BLK | RBX_VAL | RBX_CTL);

	kmem_free(krde, sizeof (rctl_dict_entry_t));
	kmem_cache_free(rctl_val_cache, nval);

	if (copyout(nblk, new_rblk, sizeof (rctl_opaque_t)) == -1) {
		kmem_free(nblk, sizeof (rctl_opaque_t));
		return (set_errno(EFAULT));
	}

	kmem_free(nblk, sizeof (rctl_opaque_t));

	return (0);
}

/*
 * static long rctlsys_set(char *name, rctl_opaque_t *old_rblk,
 *   rctl_opaque_t *new_rblk, int flags)
 *
 * Overview
 *   rctlsys_set() is the implementation of the core login of setrctl(2), which
 *   allows the establishment of resource control values.  Flags may take on any
 *   of three exclusive values:  RCTL_INSERT, RCTL_DELETE, and RCTL_REPLACE.
 *   RCTL_INSERT ignores old_rblk and inserts the value in the appropriate
 *   position in the ordered sequence of resource control values.  RCTL_DELETE
 *   ignores old_rblk and deletes the first resource control value matching
 *   (value, priority) in the given resource block.  If no matching value is
 *   found, -1 is returned and errno is set to ENOENT.  Finally, in the case of
 *   RCTL_REPLACE, old_rblk is used to match (value, priority); the matching
 *   resource control value in the sequence is replaced with the contents of
 *   new_rblk.  Again, if no match is found, -1 is returned and errno is set to
 *   ENOENT.
 *
 *   rctlsys_set() causes a cursor test, which can reactivate resource controls
 *   that have previously fired.
 */
static long
rctlsys_set(char *name, rctl_opaque_t *old_rblk, rctl_opaque_t *new_rblk,
    int flags)
{
	rctl_val_t *nval;
	rctl_dict_entry_t *rde;
	rctl_opaque_t *nblk;
	rctl_hndl_t hndl;
	char *kname;
	size_t klen;
	long ret = 0;
	proc_t *pp = NULL;
	pid_t pid;
	int action = flags & (~RCTLSYS_ACTION_MASK);
	rctl_val_t *oval;
	rctl_val_t *rval1;
	rctl_val_t *rval2;
	rctl_val_t *tval;
	rctl_opaque_t *oblk;

	if (flags & (~RCTLSYS_MASK))
		return (set_errno(EINVAL));

	if (action != RCTL_INSERT &&
	    action != RCTL_DELETE &&
	    action != RCTL_REPLACE)
		return (set_errno(EINVAL));

	if (new_rblk == NULL || name == NULL)
		return (set_errno(EFAULT));

	kname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (copyinstr(name, kname, MAXPATHLEN, &klen) != 0) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EFAULT));
	}

	if ((hndl = rctl_hndl_lookup(kname)) == -1) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EINVAL));
	}

	kmem_free(kname, MAXPATHLEN);

	rde = rctl_dict_lookup_hndl(hndl);

	nblk = kmem_alloc(sizeof (rctl_opaque_t), KM_SLEEP);

	if (copyin(new_rblk, nblk, sizeof (rctl_opaque_t)) == -1) {
		kmem_free(nblk, sizeof (rctl_opaque_t));
		return (set_errno(EFAULT));
	}

	nval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);

	rctlsys_rblk_xfrm(nblk, NULL, nval, RBX_FROM_BLK | RBX_VAL);

	if (rctl_invalid_value(rde, nval)) {
		kmem_free(nblk, sizeof (rctl_opaque_t));
		kmem_cache_free(rctl_val_cache, nval);
		return (set_errno(EINVAL));
	}

	/* allocate what we might need before potentially grabbing p_lock */
	oblk = kmem_alloc(sizeof (rctl_opaque_t), KM_SLEEP);
	oval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
	rval1 = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
	rval2 = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);

	if (nval->rcv_privilege == RCPRIV_BASIC) {
		if (flags & RCTL_USE_RECIPIENT_PID) {
			pid = nval->rcv_action_recip_pid;

			/* case for manipulating rctl values on other procs */
			if (pid != curproc->p_pid) {
				/* cannot be other pid on process rctls */
				if (rde->rcd_entity == RCENTITY_PROCESS) {
					ret = set_errno(EINVAL);
					goto rctlsys_out;
				}
				/*
				 * must have privilege to manipulate controls
				 * on other processes
				 */
				if (secpolicy_rctlsys(CRED(), B_FALSE) != 0) {
					ret = set_errno(EACCES);
					goto rctlsys_out;
				}

				pid = nval->rcv_action_recip_pid;
				mutex_enter(&pidlock);
				pp = prfind(pid);
				if (!pp) {
					mutex_exit(&pidlock);
					ret = set_errno(ESRCH);
					goto rctlsys_out;
				}

				/*
				 * idle or zombie procs have either not yet
				 * set up their rctls or have already done
				 * their rctl_set_tearoff's.
				 */
				if (pp->p_stat == SZOMB ||
				    pp->p_stat == SIDL) {
					mutex_exit(&pidlock);
					ret = set_errno(ESRCH);
					goto rctlsys_out;
				}

				/*
				 * hold this pp's p_lock to ensure that
				 * it does not do it's rctl_set_tearoff
				 * If we did not do this, we could
				 * potentially add rctls to the entity
				 * with a recipient that is a process
				 * that has exited.
				 */
				mutex_enter(&pp->p_lock);
				mutex_exit(&pidlock);

				/*
				 * We know that curproc's task, project,
				 * and zone pointers will not change
				 * because functions that change them
				 * call holdlwps(SHOLDFORK1) first.
				 */

				/*
				 * verify that the found pp is in the
				 * current task.  If it is, then it
				 * is also within the current project
				 * and zone.
				 */
				if (rde->rcd_entity == RCENTITY_TASK &&
				    pp->p_task != curproc->p_task) {
					ret = set_errno(ESRCH);
					goto rctlsys_out;
				}

				ASSERT(pp->p_task->tk_proj ==
				    curproc->p_task->tk_proj);
				ASSERT(pp->p_zone == curproc->p_zone);


				nval->rcv_action_recipient = pp;
				nval->rcv_action_recip_pid = pid;

			} else {
				/* for manipulating rctl values on this proc */
				mutex_enter(&curproc->p_lock);
				pp = curproc;
				nval->rcv_action_recipient = curproc;
				nval->rcv_action_recip_pid = curproc->p_pid;
			}

		} else {
			/* RCTL_USE_RECIPIENT_PID not set, use this proc */
			mutex_enter(&curproc->p_lock);
			pp = curproc;
			nval->rcv_action_recipient = curproc;
			nval->rcv_action_recip_pid = curproc->p_pid;
		}

	} else {
		/* privileged controls have no recipient pid */
		mutex_enter(&curproc->p_lock);
		pp = curproc;
		nval->rcv_action_recipient = NULL;
		nval->rcv_action_recip_pid = -1;
	}

	nval->rcv_firing_time = 0;

	if (action == RCTL_REPLACE) {

		if (copyin(old_rblk, oblk, sizeof (rctl_opaque_t)) == -1) {
			ret = set_errno(EFAULT);
			goto rctlsys_out;
		}

		rctlsys_rblk_xfrm(oblk, NULL, oval, RBX_FROM_BLK | RBX_VAL);

		if (rctl_invalid_value(rde, oval)) {
			ret = set_errno(EINVAL);
			goto rctlsys_out;
		}

		if (oval->rcv_privilege == RCPRIV_BASIC) {
			if (!(flags & RCTL_USE_RECIPIENT_PID)) {
				oval->rcv_action_recipient = curproc;
				oval->rcv_action_recip_pid = curproc->p_pid;
			}
		} else {
			oval->rcv_action_recipient = NULL;
			oval->rcv_action_recip_pid = -1;
		}

		/*
		 * Find the real value we're attempting to replace on the
		 * sequence, rather than trusting the one delivered from
		 * userland.
		 */
		if (ret = rctl_local_get(hndl, NULL, rval1, pp)) {
			(void) set_errno(ret);
			goto rctlsys_out;
		}

		do {
			if (rval1->rcv_privilege == RCPRIV_SYSTEM ||
			    rctl_val_cmp(oval, rval1, 0) == 0)
				break;

			tval = rval1;
			rval1 = rval2;
			rval2 = tval;
		} while (rctl_local_get(hndl, rval2, rval1, pp) == 0);

		if (rval1->rcv_privilege == RCPRIV_SYSTEM) {
			if (rctl_val_cmp(oval, rval1, 1) == 0)
				ret = set_errno(EPERM);
			else
				ret = set_errno(ESRCH);

			goto rctlsys_out;
		}

		bcopy(rval1, oval, sizeof (rctl_val_t));

		/*
		 * System controls are immutable.
		 */
		if (nval->rcv_privilege == RCPRIV_SYSTEM) {
			ret = set_errno(EPERM);
			goto rctlsys_out;
		}

		/*
		 * Only privileged processes in the global zone can modify
		 * privileged rctls of type RCENTITY_ZONE; replacing privileged
		 * controls with basic ones are not allowed either.  Lowering a
		 * lowerable one might be OK for privileged processes in a
		 * non-global zone, but lowerable rctls probably don't make
		 * sense for zones (hence, not modifiable from within a zone).
		 */
		if (rde->rcd_entity == RCENTITY_ZONE &&
		    (nval->rcv_privilege == RCPRIV_PRIVILEGED ||
		    oval->rcv_privilege == RCPRIV_PRIVILEGED) &&
		    secpolicy_rctlsys(CRED(), B_TRUE) != 0) {
			ret = set_errno(EACCES);
			goto rctlsys_out;
		}

		/*
		 * Must be privileged to replace a privileged control with
		 * a basic one.
		 */
		if (oval->rcv_privilege == RCPRIV_PRIVILEGED &&
		    nval->rcv_privilege != RCPRIV_PRIVILEGED &&
		    secpolicy_rctlsys(CRED(), B_FALSE) != 0) {
			ret = set_errno(EACCES);
			goto rctlsys_out;
		}

		/*
		 * Must have lowerable global property for non-privileged
		 * to lower the value of a privileged control; otherwise must
		 * have sufficient privileges to modify privileged controls
		 * at all.
		 */
		if (oval->rcv_privilege == RCPRIV_PRIVILEGED &&
		    nval->rcv_privilege == RCPRIV_PRIVILEGED &&
		    ((((rde->rcd_flagaction & RCTL_GLOBAL_LOWERABLE) == 0) ||
		    oval->rcv_flagaction != nval->rcv_flagaction ||
		    oval->rcv_action_signal != nval->rcv_action_signal ||
		    oval->rcv_value < nval->rcv_value)) &&
		    secpolicy_rctlsys(CRED(), B_FALSE) != 0) {
			ret = set_errno(EACCES);
			goto rctlsys_out;
		}

		if (ret = rctl_local_replace(hndl, oval, nval, pp)) {
			(void) set_errno(ret);
			goto rctlsys_out;
		}

		/* ensure that nval is not freed */
		nval = NULL;

	} else if (action == RCTL_INSERT) {
		/*
		 * System controls are immutable.
		 */
		if (nval->rcv_privilege == RCPRIV_SYSTEM) {
			ret = set_errno(EPERM);
			goto rctlsys_out;
		}

		/*
		 * Only privileged processes in the global zone may add
		 * privileged zone.* rctls.  Only privileged processes
		 * may add other privileged rctls.
		 */
		if (nval->rcv_privilege == RCPRIV_PRIVILEGED) {
			if ((rde->rcd_entity == RCENTITY_ZONE &&
			    secpolicy_rctlsys(CRED(), B_TRUE) != 0) ||
			    (rde->rcd_entity != RCENTITY_ZONE &&
			    secpolicy_rctlsys(CRED(), B_FALSE) != 0)) {
				ret = set_errno(EACCES);
				goto rctlsys_out;
			}
		}

		/*
		 * Only one basic control is allowed per rctl.
		 * If a basic control is being inserted, delete
		 * any other basic control.
		 */
		if ((nval->rcv_privilege == RCPRIV_BASIC) &&
		    (rctl_local_get(hndl, NULL, rval1, pp) == 0)) {
			do {
				if (rval1->rcv_privilege == RCPRIV_BASIC &&
				    rval1->rcv_action_recipient == curproc) {
					(void) rctl_local_delete(hndl, rval1,
					    pp);
					if (rctl_local_get(hndl, NULL, rval1,
					    pp) != 0)
						break;
				}

				tval = rval1;
				rval1 = rval2;
				rval2 = tval;
			} while (rctl_local_get(hndl, rval2, rval1, pp)
			    == 0);
		}


		if (ret = rctl_local_insert(hndl, nval, pp)) {
			(void) set_errno(ret);
			goto rctlsys_out;
		}

		/* ensure that nval is not freed */
		nval = NULL;

	} else {
		/*
		 * RCTL_DELETE
		 */
		if (nval->rcv_privilege == RCPRIV_SYSTEM) {
			ret = set_errno(EPERM);
			goto rctlsys_out;
		}

		if (nval->rcv_privilege == RCPRIV_PRIVILEGED) {
			if ((rde->rcd_entity == RCENTITY_ZONE &&
			    secpolicy_rctlsys(CRED(), B_TRUE) != 0) ||
			    (rde->rcd_entity != RCENTITY_ZONE &&
			    secpolicy_rctlsys(CRED(), B_FALSE) != 0)) {
				ret = set_errno(EACCES);
				goto rctlsys_out;
			}
		}

		if (ret = rctl_local_delete(hndl, nval, pp)) {
			(void) set_errno(ret);
			goto rctlsys_out;
		}
	}

rctlsys_out:

	if (pp)
		mutex_exit(&pp->p_lock);

	kmem_free(nblk, sizeof (rctl_opaque_t));
	kmem_free(oblk, sizeof (rctl_opaque_t));

	/* only free nval if we did not rctl_local_insert it */
	if (nval)
		kmem_cache_free(rctl_val_cache, nval);

	kmem_cache_free(rctl_val_cache, oval);
	kmem_cache_free(rctl_val_cache, rval1);
	kmem_cache_free(rctl_val_cache, rval2);

	return (ret);
}

static long
rctlsys_lst(char *ubuf, size_t ubufsz)
{
	char *kbuf;
	size_t kbufsz;

	kbufsz = rctl_build_name_buf(&kbuf);

	if (kbufsz <= ubufsz &&
	    copyout(kbuf, ubuf, kbufsz) != 0) {
		kmem_free(kbuf, kbufsz);
		return (set_errno(EFAULT));
	}

	kmem_free(kbuf, kbufsz);

	return (kbufsz);
}

static long
rctlsys_ctl(char *name, rctl_opaque_t *rblk, int flags)
{
	rctl_dict_entry_t *krde;
	rctl_opaque_t *krblk;
	char *kname;
	size_t klen;

	kname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (name == NULL || copyinstr(name, kname, MAXPATHLEN, &klen) != 0) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EFAULT));
	}

	switch (flags) {
	case RCTLCTL_GET:
		krde = kmem_alloc(sizeof (rctl_dict_entry_t), KM_SLEEP);
		krblk = kmem_zalloc(sizeof (rctl_opaque_t), KM_SLEEP);

		if (rctl_global_get(kname, krde) == -1) {
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			kmem_free(krblk, sizeof (rctl_opaque_t));
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(ESRCH));
		}

		rctlsys_rblk_xfrm(krblk, krde, NULL, RBX_TO_BLK | RBX_CTL);

		if (copyout(krblk, rblk, sizeof (rctl_opaque_t)) != 0) {
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			kmem_free(krblk, sizeof (rctl_opaque_t));
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(EFAULT));
		}

		kmem_free(krde, sizeof (rctl_dict_entry_t));
		kmem_free(krblk, sizeof (rctl_opaque_t));
		kmem_free(kname, MAXPATHLEN);
		break;
	case RCTLCTL_SET:
		if (secpolicy_rctlsys(CRED(), B_TRUE) != 0) {
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(EPERM));
		}

		krde = kmem_alloc(sizeof (rctl_dict_entry_t), KM_SLEEP);
		krblk = kmem_zalloc(sizeof (rctl_opaque_t), KM_SLEEP);

		if (rctl_global_get(kname, krde) == -1) {
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			kmem_free(krblk, sizeof (rctl_opaque_t));
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(ESRCH));
		}

		if (copyin(rblk, krblk, sizeof (rctl_opaque_t)) != 0) {
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			kmem_free(krblk, sizeof (rctl_opaque_t));
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(EFAULT));
		}

		rctlsys_rblk_xfrm(krblk, krde, NULL, RBX_FROM_BLK | RBX_CTL);

		if (rctl_global_set(kname, krde) == -1) {
			kmem_free(krde, sizeof (rctl_dict_entry_t));
			kmem_free(krblk, sizeof (rctl_opaque_t));
			kmem_free(kname, MAXPATHLEN);
			return (set_errno(ESRCH));
		}

		kmem_free(krde, sizeof (rctl_dict_entry_t));
		kmem_free(krblk, sizeof (rctl_opaque_t));
		kmem_free(kname, MAXPATHLEN);

		break;
	default:
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EINVAL));
	}

	return (0);
}

/*
 * The arbitrary maximum number of rctl_opaque_t that we can pass to
 * rctl_projset().
 */
#define	RCTL_PROJSET_MAXSIZE	1024

static long
rctlsys_projset(char *name, rctl_opaque_t *rblk, size_t size, int flags)
{
	rctl_dict_entry_t *krde;
	rctl_opaque_t *krblk;
	char *kname;
	size_t klen;
	rctl_hndl_t hndl;
	rctl_val_t *new_values = NULL;
	rctl_val_t *alloc_values = NULL;
	rctl_val_t *new_val;
	rctl_val_t *alloc_val;
	int error = 0;
	int count;

	kname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (name == NULL || copyinstr(name, kname, MAXPATHLEN, &klen) != 0) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EFAULT));
	}

	if (size > RCTL_PROJSET_MAXSIZE) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EINVAL));
	}

	if ((hndl = rctl_hndl_lookup(kname)) == -1) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EINVAL));
	}

	krde = rctl_dict_lookup_hndl(hndl);

	/* If not a project entity then exit */
	if ((krde->rcd_entity != RCENTITY_PROJECT) || (size <= 0)) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EINVAL));
	}

	if (secpolicy_rctlsys(CRED(), B_FALSE) != 0) {
		kmem_free(kname, MAXPATHLEN);
		return (set_errno(EPERM));
	}

	/* Allocate an array large enough for all resource control blocks */
	krblk = kmem_zalloc(sizeof (rctl_opaque_t) * size, KM_SLEEP);

	if (copyin(rblk, krblk, sizeof (rctl_opaque_t) * size) == 0) {

		for (count = 0; (count < size) && (error == 0); count++) {
			new_val = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
			alloc_val = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);

			rctlsys_rblk_xfrm(&krblk[count], NULL, new_val,
			    RBX_FROM_BLK | RBX_VAL);

			/*
			 * Project entity resource control values should always
			 * be privileged
			 */
			if (new_val->rcv_privilege != RCPRIV_PRIVILEGED) {
				kmem_cache_free(rctl_val_cache, new_val);
				kmem_cache_free(rctl_val_cache, alloc_val);

				error = EPERM;
			} else if (rctl_invalid_value(krde, new_val) == 0) {

				/*
				 * This is a project entity; we do not set
				 * rcv_action_recipient or rcv_action_recip_pid
				 */
				new_val->rcv_action_recipient = NULL;
				new_val->rcv_action_recip_pid = -1;
				new_val->rcv_flagaction |= RCTL_LOCAL_PROJDB;
				new_val->rcv_firing_time = 0;

				new_val->rcv_prev = NULL;
				new_val->rcv_next = new_values;
				new_values = new_val;

				/*
				 * alloc_val is left largely uninitialized, it
				 * is a pre-allocated rctl_val_t which is used
				 * later in rctl_local_replace_all() /
				 * rctl_local_insert_all().
				 */
				alloc_val->rcv_prev = NULL;
				alloc_val->rcv_next = alloc_values;
				alloc_values = alloc_val;
			} else {
				kmem_cache_free(rctl_val_cache, new_val);
				kmem_cache_free(rctl_val_cache, alloc_val);

				error = EINVAL;
			}
		}

	} else {
		error = EFAULT;
	}

	kmem_free(krblk, sizeof (rctl_opaque_t) * size);
	kmem_free(kname, MAXPATHLEN);

	if (error) {
		/*
		 * We will have the same number of items in the alloc_values
		 * linked list, as we have in new_values.  However, we remain
		 * cautious, and teardown the linked lists individually.
		 */
		while (new_values != NULL) {
			new_val = new_values;
			new_values = new_values->rcv_next;
			kmem_cache_free(rctl_val_cache, new_val);
		}

		while (alloc_values != NULL) {
			alloc_val = alloc_values;
			alloc_values = alloc_values->rcv_next;
			kmem_cache_free(rctl_val_cache, alloc_val);
		}

		return (set_errno(error));
	}

	/*
	 * We take the p_lock here to maintain consistency with other functions
	 * - rctlsys_get() and rctlsys_set()
	 */
	mutex_enter(&curproc->p_lock);
	if (flags & TASK_PROJ_PURGE)  {
		(void) rctl_local_replace_all(hndl, new_values, alloc_values,
		    curproc);
	} else {
		(void) rctl_local_insert_all(hndl, new_values, alloc_values,
		    curproc);
	}
	mutex_exit(&curproc->p_lock);

	return (0);
}

long
rctlsys(int code, char *name, void *obuf, void *nbuf, size_t obufsz, int flags)
{
	switch (code) {
	case 0:
		return (rctlsys_get(name, obuf, nbuf, flags));

	case 1:
		return (rctlsys_set(name, obuf, nbuf, flags));

	case 2:
		/*
		 * Private call for rctl_walk(3C).
		 */
		return (rctlsys_lst(obuf, obufsz));

	case 3:
		/*
		 * Private code for rctladm(8):  "rctlctl".
		 */
		return (rctlsys_ctl(name, obuf, flags));
	case 4:
		/*
		 * Private code for setproject(3PROJECT).
		 */
		return (rctlsys_projset(name, nbuf, obufsz, flags));

	default:
		return (set_errno(EINVAL));
	}
}
