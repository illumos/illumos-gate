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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * A CPR derivative specifically for starfire/starcat
 * X86 doesn't make use of the quiesce interfaces, it's kept for simplicity.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/ddi.h>
#define	SUNDDI_IMPL
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/devctl.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <nfs/lm.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/callb.h>
#include <sys/clock.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/epm.h>
#include <sys/vfs.h>
#include <sys/promif.h>
#include <sys/conf.h>
#include <sys/cyclic.h>

#include <sys/dr.h>
#include <sys/dr_util.h>

extern void	e_ddi_enter_driver_list(struct devnames *dnp, int *listcnt);
extern void	e_ddi_exit_driver_list(struct devnames *dnp, int listcnt);
extern int	is_pseudo_device(dev_info_t *dip);

extern kmutex_t	cpu_lock;
extern dr_unsafe_devs_t dr_unsafe_devs;

static int		dr_is_real_device(dev_info_t *dip);
static int		dr_is_unsafe_major(major_t major);
static int		dr_bypass_device(char *dname);
static int		dr_check_dip(dev_info_t *dip, void *arg, uint_t ref);
static int		dr_resolve_devname(dev_info_t *dip, char *buffer,
				char *alias);
static sbd_error_t	*drerr_int(int e_code, uint64_t *arr, int idx,
				int majors);
static int		dr_add_int(uint64_t *arr, int idx, int len,
				uint64_t val);

int dr_pt_test_suspend(dr_handle_t *hp);

/*
 * dr_quiesce.c interface
 * NOTE: states used internally by dr_suspend and dr_resume
 */
typedef enum dr_suspend_state {
	DR_SRSTATE_BEGIN = 0,
	DR_SRSTATE_USER,
	DR_SRSTATE_DRIVER,
	DR_SRSTATE_FULL
} suspend_state_t;

struct dr_sr_handle {
	dr_handle_t		*sr_dr_handlep;
	dev_info_t		*sr_failed_dip;
	suspend_state_t		sr_suspend_state;
	uint_t			sr_flags;
	uint64_t		sr_err_ints[DR_MAX_ERR_INT];
	int			sr_err_idx;
};

#define	SR_FLAG_WATCHDOG	0x1

/*
 * XXX
 * This hack will go away before RTI.  Just for testing.
 * List of drivers to bypass when performing a suspend.
 */
static char *dr_bypass_list[] = {
	""
};


#define		SKIP_SYNC	/* bypass sync ops in dr_suspend */

/*
 * dr_skip_user_threads is used to control if user threads should
 * be suspended.  If dr_skip_user_threads is true, the rest of the
 * flags are not used; if it is false, dr_check_user_stop_result
 * will be used to control whether or not we need to check suspend
 * result, and dr_allow_blocked_threads will be used to control
 * whether or not we allow suspend to continue if there are blocked
 * threads.  We allow all combinations of dr_check_user_stop_result
 * and dr_allow_block_threads, even though it might not make much
 * sense to not allow block threads when we don't even check stop
 * result.
 */
static int	dr_skip_user_threads = 0;	/* default to FALSE */
static int	dr_check_user_stop_result = 1;	/* default to TRUE */
static int	dr_allow_blocked_threads = 1;	/* default to TRUE */

#define	DR_CPU_LOOP_MSEC	1000

static void
dr_stop_intr(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	kpreempt_disable();
	cyclic_suspend();
}

static void
dr_enable_intr(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	cyclic_resume();
	kpreempt_enable();
}

dr_sr_handle_t *
dr_get_sr_handle(dr_handle_t *hp)
{
	dr_sr_handle_t *srh;

	srh = GETSTRUCT(dr_sr_handle_t, 1);
	srh->sr_dr_handlep = hp;

	return (srh);
}

void
dr_release_sr_handle(dr_sr_handle_t *srh)
{
	ASSERT(srh->sr_failed_dip == NULL);
	FREESTRUCT(srh, dr_sr_handle_t, 1);
}

static int
dr_is_real_device(dev_info_t *dip)
{
	struct regspec *regbuf = NULL;
	int length = 0;
	int rc;

	if (ddi_get_driver(dip) == NULL)
		return (0);

	if (DEVI(dip)->devi_pm_flags & (PMC_NEEDS_SR|PMC_PARENTAL_SR))
		return (1);
	if (DEVI(dip)->devi_pm_flags & PMC_NO_SR)
		return (0);

	/*
	 * now the general case
	 */
	rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&regbuf, &length);
	ASSERT(rc != DDI_PROP_NO_MEMORY);
	if (rc != DDI_PROP_SUCCESS) {
		return (0);
	} else {
		if ((length > 0) && (regbuf != NULL))
			kmem_free(regbuf, length);
		return (1);
	}
}

static int
dr_is_unsafe_major(major_t major)
{
	char    *dname, **cpp;
	int	i, ndevs;

	if ((dname = ddi_major_to_name(major)) == NULL) {
		PR_QR("dr_is_unsafe_major: invalid major # %d\n", major);
		return (0);
	}

	ndevs = dr_unsafe_devs.ndevs;
	for (i = 0, cpp = dr_unsafe_devs.devnames; i < ndevs; i++) {
		if (strcmp(dname, *cpp++) == 0)
			return (1);
	}
	return (0);
}

static int
dr_bypass_device(char *dname)
{
	int i;
	char **lname;

	if (dname == NULL)
		return (0);

	/* check the bypass list */
	for (i = 0, lname = &dr_bypass_list[i]; **lname != '\0'; lname++) {
		if (strcmp(dname, dr_bypass_list[i++]) == 0)
			return (1);
	}
	return (0);
}

static int
dr_resolve_devname(dev_info_t *dip, char *buffer, char *alias)
{
	major_t	devmajor;
	char	*aka, *name;

	*buffer = *alias = 0;

	if (dip == NULL)
		return (-1);

	if ((name = ddi_get_name(dip)) == NULL)
		name = "<null name>";

	aka = name;

	if ((devmajor = ddi_name_to_major(aka)) != DDI_MAJOR_T_NONE)
		aka = ddi_major_to_name(devmajor);

	(void) strcpy(buffer, name);

	if (strcmp(name, aka))
		(void) strcpy(alias, aka);
	else
		*alias = 0;

	return (0);
}

struct dr_ref {
	int		*refcount;
	int		*refcount_non_gldv3;
	uint64_t	*arr;
	int		*idx;
	int		len;
};

/* ARGSUSED */
static int
dr_check_dip(dev_info_t *dip, void *arg, uint_t ref)
{
	major_t		major;
	char		*dname;
	struct dr_ref	*rp = (struct dr_ref *)arg;

	if (dip == NULL)
		return (DDI_WALK_CONTINUE);

	if (!dr_is_real_device(dip))
		return (DDI_WALK_CONTINUE);

	dname = ddi_binding_name(dip);

	if (dr_bypass_device(dname))
		return (DDI_WALK_CONTINUE);

	if (dname && ((major = ddi_name_to_major(dname)) != (major_t)-1)) {
		if (ref && rp->refcount) {
			*rp->refcount += ref;
			PR_QR("\n  %s (major# %d) is referenced(%u)\n", dname,
			    major, ref);
		}
		if (ref && rp->refcount_non_gldv3) {
			if (NETWORK_PHYSDRV(major) && !GLDV3_DRV(major))
				*rp->refcount_non_gldv3 += ref;
		}
		if (dr_is_unsafe_major(major) && i_ddi_devi_attached(dip)) {
			PR_QR("\n  %s (major# %d) not hotpluggable\n", dname,
			    major);
			if (rp->arr != NULL && rp->idx != NULL)
				*rp->idx = dr_add_int(rp->arr, *rp->idx,
				    rp->len, (uint64_t)major);
		}
	}
	return (DDI_WALK_CONTINUE);
}

static int
dr_check_unsafe_major(dev_info_t *dip, void *arg)
{
	return (dr_check_dip(dip, arg, 0));
}


/*ARGSUSED*/
void
dr_check_devices(dev_info_t *dip, int *refcount, dr_handle_t *handle,
    uint64_t *arr, int *idx, int len, int *refcount_non_gldv3)
{
	struct dr_ref bref = {0};

	if (dip == NULL)
		return;

	bref.refcount = refcount;
	bref.refcount_non_gldv3 = refcount_non_gldv3;
	bref.arr = arr;
	bref.idx = idx;
	bref.len = len;

	ASSERT(e_ddi_branch_held(dip));
	(void) e_ddi_branch_referenced(dip, dr_check_dip, &bref);
}

/*
 * The "dip" argument's parent (if it exists) must be held busy.
 */
static int
dr_suspend_devices(dev_info_t *dip, dr_sr_handle_t *srh)
{
	dr_handle_t	*handle;
	major_t		major;
	char		*dname;
	int		circ;

	/*
	 * If dip is the root node, it has no siblings and it is
	 * always held. If dip is not the root node, dr_suspend_devices()
	 * will be invoked with the parent held busy.
	 */
	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		char	d_name[40], d_alias[40], *d_info;

		ndi_devi_enter(dip, &circ);
		if (dr_suspend_devices(ddi_get_child(dip), srh)) {
			ndi_devi_exit(dip, circ);
			return (ENXIO);
		}
		ndi_devi_exit(dip, circ);

		if (!dr_is_real_device(dip))
			continue;

		major = (major_t)-1;
		if ((dname = ddi_binding_name(dip)) != NULL)
			major = ddi_name_to_major(dname);

		if (dr_bypass_device(dname)) {
			PR_QR(" bypassed suspend of %s (major# %d)\n", dname,
			    major);
			continue;
		}

		if (drmach_verify_sr(dip, 1)) {
			PR_QR(" bypassed suspend of %s (major# %d)\n", dname,
			    major);
			continue;
		}

		if ((d_info = ddi_get_name_addr(dip)) == NULL)
			d_info = "<null>";

		d_name[0] = 0;
		if (dr_resolve_devname(dip, d_name, d_alias) == 0) {
			if (d_alias[0] != 0) {
				prom_printf("\tsuspending %s@%s (aka %s)\n",
				    d_name, d_info, d_alias);
			} else {
				prom_printf("\tsuspending %s@%s\n", d_name,
				    d_info);
			}
		} else {
			prom_printf("\tsuspending %s@%s\n", dname, d_info);
		}

		if (devi_detach(dip, DDI_SUSPEND) != DDI_SUCCESS) {
			prom_printf("\tFAILED to suspend %s@%s\n",
			    d_name[0] ? d_name : dname, d_info);

			srh->sr_err_idx = dr_add_int(srh->sr_err_ints,
			    srh->sr_err_idx, DR_MAX_ERR_INT, (uint64_t)major);

			ndi_hold_devi(dip);
			srh->sr_failed_dip = dip;

			handle = srh->sr_dr_handlep;
			dr_op_err(CE_IGNORE, handle, ESBD_SUSPEND, "%s@%s",
			    d_name[0] ? d_name : dname, d_info);

			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static void
dr_resume_devices(dev_info_t *start, dr_sr_handle_t *srh)
{
	dr_handle_t	*handle;
	dev_info_t	*dip, *next, *last = NULL;
	major_t		major;
	char		*bn;
	int		circ;

	major = (major_t)-1;

	/* attach in reverse device tree order */
	while (last != start) {
		dip = start;
		next = ddi_get_next_sibling(dip);
		while (next != last && dip != srh->sr_failed_dip) {
			dip = next;
			next = ddi_get_next_sibling(dip);
		}
		if (dip == srh->sr_failed_dip) {
			/* release hold acquired in dr_suspend_devices() */
			srh->sr_failed_dip = NULL;
			ndi_rele_devi(dip);
		} else if (dr_is_real_device(dip) &&
		    srh->sr_failed_dip == NULL) {

			if ((bn = ddi_binding_name(dip)) != NULL) {
				major = ddi_name_to_major(bn);
			} else {
				bn = "<null>";
			}
			if (!dr_bypass_device(bn) &&
			    !drmach_verify_sr(dip, 0)) {
				char	d_name[40], d_alias[40], *d_info;

				d_name[0] = 0;
				d_info = ddi_get_name_addr(dip);
				if (d_info == NULL)
					d_info = "<null>";

				if (!dr_resolve_devname(dip, d_name, d_alias)) {
					if (d_alias[0] != 0) {
						prom_printf("\tresuming "
						    "%s@%s (aka %s)\n", d_name,
						    d_info, d_alias);
					} else {
						prom_printf("\tresuming "
						    "%s@%s\n", d_name, d_info);
					}
				} else {
					prom_printf("\tresuming %s@%s\n", bn,
					    d_info);
				}

				if (devi_attach(dip, DDI_RESUME) !=
				    DDI_SUCCESS) {
					/*
					 * Print a console warning,
					 * set an e_code of ESBD_RESUME,
					 * and save the driver major
					 * number in the e_rsc.
					 */
					prom_printf("\tFAILED to resume %s@%s",
					    d_name[0] ? d_name : bn, d_info);

					srh->sr_err_idx =
					    dr_add_int(srh->sr_err_ints,
					    srh->sr_err_idx, DR_MAX_ERR_INT,
					    (uint64_t)major);

					handle = srh->sr_dr_handlep;

					dr_op_err(CE_IGNORE, handle,
					    ESBD_RESUME, "%s@%s",
					    d_name[0] ? d_name : bn, d_info);
				}
			}
		}

		/* Hold parent busy while walking its children */
		ndi_devi_enter(dip, &circ);
		dr_resume_devices(ddi_get_child(dip), srh);
		ndi_devi_exit(dip, circ);
		last = dip;
	}
}

/*
 * True if thread is virtually stopped.  Similar to CPR_VSTOPPED
 * but from DR point of view.  These user threads are waiting in
 * the kernel.  Once they complete in the kernel, they will process
 * the stop signal and stop.
 */
#define	DR_VSTOPPED(t)			\
	((t)->t_state == TS_SLEEP &&	\
	(t)->t_wchan != NULL &&		\
	(t)->t_astflag &&		\
	((t)->t_proc_flag & TP_CHKPT))

/* ARGSUSED */
static int
dr_stop_user_threads(dr_sr_handle_t *srh)
{
	int		count;
	int		bailout;
	dr_handle_t	*handle = srh->sr_dr_handlep;
	static fn_t	f = "dr_stop_user_threads";
	kthread_id_t 	tp;

	extern void add_one_utstop();
	extern void utstop_timedwait(clock_t);
	extern void utstop_init(void);

#define	DR_UTSTOP_RETRY	4
#define	DR_UTSTOP_WAIT	hz

	if (dr_skip_user_threads)
		return (DDI_SUCCESS);

	utstop_init();

	/* we need to try a few times to get past fork, etc. */
	srh->sr_err_idx = 0;
	for (count = 0; count < DR_UTSTOP_RETRY; count++) {
		/* walk the entire threadlist */
		mutex_enter(&pidlock);
		for (tp = curthread->t_next; tp != curthread; tp = tp->t_next) {
			proc_t *p = ttoproc(tp);

			/* handle kernel threads separately */
			if (p->p_as == &kas || p->p_stat == SZOMB)
				continue;

			mutex_enter(&p->p_lock);
			thread_lock(tp);

			if (tp->t_state == TS_STOPPED) {
				/* add another reason to stop this thread */
				tp->t_schedflag &= ~TS_RESUME;
			} else {
				tp->t_proc_flag |= TP_CHKPT;

				thread_unlock(tp);
				mutex_exit(&p->p_lock);
				add_one_utstop();
				mutex_enter(&p->p_lock);
				thread_lock(tp);

				aston(tp);

				if (ISWAKEABLE(tp) || ISWAITING(tp)) {
					setrun_locked(tp);
				}

			}

			/* grab thread if needed */
			if (tp->t_state == TS_ONPROC && tp->t_cpu != CPU)
				poke_cpu(tp->t_cpu->cpu_id);


			thread_unlock(tp);
			mutex_exit(&p->p_lock);
		}
		mutex_exit(&pidlock);


		/* let everything catch up */
		utstop_timedwait(count * count * DR_UTSTOP_WAIT);


		/* now, walk the threadlist again to see if we are done */
		mutex_enter(&pidlock);
		for (tp = curthread->t_next, bailout = 0;
		    tp != curthread; tp = tp->t_next) {
			proc_t *p = ttoproc(tp);

			/* handle kernel threads separately */
			if (p->p_as == &kas || p->p_stat == SZOMB)
				continue;

			/*
			 * If this thread didn't stop, and we don't allow
			 * unstopped blocked threads, bail.
			 */
			thread_lock(tp);
			if (!CPR_ISTOPPED(tp) &&
			    !(dr_allow_blocked_threads &&
			    DR_VSTOPPED(tp))) {
				bailout = 1;
				if (count == DR_UTSTOP_RETRY - 1) {
					/*
					 * save the pid for later reporting
					 */
					srh->sr_err_idx =
					    dr_add_int(srh->sr_err_ints,
					    srh->sr_err_idx, DR_MAX_ERR_INT,
					    (uint64_t)p->p_pid);

					cmn_err(CE_WARN, "%s: "
					    "failed to stop thread: "
					    "process=%s, pid=%d",
					    f, p->p_user.u_psargs, p->p_pid);

					PR_QR("%s: failed to stop thread: "
					    "process=%s, pid=%d, t_id=0x%p, "
					    "t_state=0x%x, t_proc_flag=0x%x, "
					    "t_schedflag=0x%x\n",
					    f, p->p_user.u_psargs, p->p_pid,
					    (void *)tp, tp->t_state,
					    tp->t_proc_flag, tp->t_schedflag);
				}

			}
			thread_unlock(tp);
		}
		mutex_exit(&pidlock);

		/* were all the threads stopped? */
		if (!bailout)
			break;
	}

	/* were we unable to stop all threads after a few tries? */
	if (bailout) {
		handle->h_err = drerr_int(ESBD_UTHREAD, srh->sr_err_ints,
		    srh->sr_err_idx, 0);
		return (ESRCH);
	}

	return (DDI_SUCCESS);
}

static void
dr_start_user_threads(void)
{
	kthread_id_t tp;

	mutex_enter(&pidlock);

	/* walk all threads and release them */
	for (tp = curthread->t_next; tp != curthread; tp = tp->t_next) {
		proc_t *p = ttoproc(tp);

		/* skip kernel threads */
		if (ttoproc(tp)->p_as == &kas)
			continue;

		mutex_enter(&p->p_lock);
		tp->t_proc_flag &= ~TP_CHKPT;
		mutex_exit(&p->p_lock);

		thread_lock(tp);
		if (CPR_ISTOPPED(tp)) {
			/* back on the runq */
			tp->t_schedflag |= TS_RESUME;
			setrun_locked(tp);
		}
		thread_unlock(tp);
	}

	mutex_exit(&pidlock);
}

static void
dr_signal_user(int sig)
{
	struct proc *p;

	mutex_enter(&pidlock);

	for (p = practive; p != NULL; p = p->p_next) {
		/* only user threads */
		if (p->p_exec == NULL || p->p_stat == SZOMB ||
		    p == proc_init || p == ttoproc(curthread))
			continue;

		mutex_enter(&p->p_lock);
		sigtoproc(p, NULL, sig);
		mutex_exit(&p->p_lock);
	}

	mutex_exit(&pidlock);

	/* add a bit of delay */
	delay(hz);
}

void
dr_resume(dr_sr_handle_t *srh)
{
	switch (srh->sr_suspend_state) {
	case DR_SRSTATE_FULL:

		ASSERT(MUTEX_HELD(&cpu_lock));

		/*
		 * Prevent false alarm in tod_validate() due to tod
		 * value change between suspend and resume
		 */
		mutex_enter(&tod_lock);
		tod_status_set(TOD_DR_RESUME_DONE);
		mutex_exit(&tod_lock);

		dr_enable_intr(); 	/* enable intr & clock */

		start_cpus();
		mutex_exit(&cpu_lock);

		/*
		 * This should only be called if drmach_suspend_last()
		 * was called and state transitioned to DR_SRSTATE_FULL
		 * to prevent resume attempts on device instances that
		 * were not previously suspended.
		 */
		drmach_resume_first();

		/* FALLTHROUGH */

	case DR_SRSTATE_DRIVER:
		/*
		 * resume drivers
		 */
		srh->sr_err_idx = 0;

		/* no parent dip to hold busy */
		dr_resume_devices(ddi_root_node(), srh);

		if (srh->sr_err_idx && srh->sr_dr_handlep) {
			(srh->sr_dr_handlep)->h_err = drerr_int(ESBD_RESUME,
			    srh->sr_err_ints, srh->sr_err_idx, 1);
		}

		/*
		 * resume the lock manager
		 */
		lm_cprresume();

		/* FALLTHROUGH */

	case DR_SRSTATE_USER:
		/*
		 * finally, resume user threads
		 */
		if (!dr_skip_user_threads) {
			prom_printf("DR: resuming user threads...\n");
			dr_start_user_threads();
		}
		/* FALLTHROUGH */

	case DR_SRSTATE_BEGIN:
	default:
		/*
		 * let those who care know that we've just resumed
		 */
		PR_QR("sending SIGTHAW...\n");
		dr_signal_user(SIGTHAW);
		break;
	}

	prom_printf("DR: resume COMPLETED\n");
}

int
dr_suspend(dr_sr_handle_t *srh)
{
	dr_handle_t	*handle;
	int		force;
	int		dev_errs_idx;
	uint64_t	dev_errs[DR_MAX_ERR_INT];
	int		rc = DDI_SUCCESS;

	handle = srh->sr_dr_handlep;

	force = dr_cmd_flags(handle) & SBD_FLAG_FORCE;

	prom_printf("\nDR: suspending user threads...\n");
	srh->sr_suspend_state = DR_SRSTATE_USER;
	if (((rc = dr_stop_user_threads(srh)) != DDI_SUCCESS) &&
	    dr_check_user_stop_result) {
		dr_resume(srh);
		return (rc);
	}

	if (!force) {
		struct dr_ref drc = {0};

		prom_printf("\nDR: checking devices...\n");
		dev_errs_idx = 0;

		drc.arr = dev_errs;
		drc.idx = &dev_errs_idx;
		drc.len = DR_MAX_ERR_INT;

		/*
		 * Since the root node can never go away, it
		 * doesn't have to be held.
		 */
		ddi_walk_devs(ddi_root_node(), dr_check_unsafe_major, &drc);
		if (dev_errs_idx) {
			handle->h_err = drerr_int(ESBD_UNSAFE, dev_errs,
			    dev_errs_idx, 1);
			dr_resume(srh);
			return (DDI_FAILURE);
		}
		PR_QR("done\n");
	} else {
		prom_printf("\nDR: dr_suspend invoked with force flag\n");
	}

#ifndef	SKIP_SYNC
	/*
	 * This sync swap out all user pages
	 */
	vfs_sync(SYNC_ALL);
#endif

	/*
	 * special treatment for lock manager
	 */
	lm_cprsuspend();

#ifndef	SKIP_SYNC
	/*
	 * sync the file system in case we never make it back
	 */
	sync();
#endif

	/*
	 * now suspend drivers
	 */
	prom_printf("DR: suspending drivers...\n");
	srh->sr_suspend_state = DR_SRSTATE_DRIVER;
	srh->sr_err_idx = 0;
	/* No parent to hold busy */
	if ((rc = dr_suspend_devices(ddi_root_node(), srh)) != DDI_SUCCESS) {
		if (srh->sr_err_idx && srh->sr_dr_handlep) {
			(srh->sr_dr_handlep)->h_err = drerr_int(ESBD_SUSPEND,
			    srh->sr_err_ints, srh->sr_err_idx, 1);
		}
		dr_resume(srh);
		return (rc);
	}

	drmach_suspend_last();

	/*
	 * finally, grab all cpus
	 */
	srh->sr_suspend_state = DR_SRSTATE_FULL;

	mutex_enter(&cpu_lock);
	pause_cpus(NULL, NULL);
	dr_stop_intr();

	return (rc);
}

int
dr_pt_test_suspend(dr_handle_t *hp)
{
	dr_sr_handle_t *srh;
	int		err;
	uint_t		psmerr;
	static fn_t	f = "dr_pt_test_suspend";

	PR_QR("%s...\n", f);

	srh = dr_get_sr_handle(hp);
	if ((err = dr_suspend(srh)) == DDI_SUCCESS) {
		dr_resume(srh);
		if ((hp->h_err) && ((psmerr = hp->h_err->e_code) != 0)) {
			PR_QR("%s: error on dr_resume()", f);
			switch (psmerr) {
			case ESBD_RESUME:
				PR_QR("Couldn't resume devices: %s\n",
				    DR_GET_E_RSC(hp->h_err));
				break;

			case ESBD_KTHREAD:
				PR_ALL("psmerr is ESBD_KTHREAD\n");
				break;
			default:
				PR_ALL("Resume error unknown = %d\n", psmerr);
				break;
			}
		}
	} else {
		PR_ALL("%s: dr_suspend() failed, err = 0x%x\n", f, err);
		psmerr = hp->h_err ? hp->h_err->e_code : ESBD_NOERROR;
		switch (psmerr) {
		case ESBD_UNSAFE:
			PR_ALL("Unsafe devices (major #): %s\n",
			    DR_GET_E_RSC(hp->h_err));
			break;

		case ESBD_RTTHREAD:
			PR_ALL("RT threads (PIDs): %s\n",
			    DR_GET_E_RSC(hp->h_err));
			break;

		case ESBD_UTHREAD:
			PR_ALL("User threads (PIDs): %s\n",
			    DR_GET_E_RSC(hp->h_err));
			break;

		case ESBD_SUSPEND:
			PR_ALL("Non-suspendable devices (major #): %s\n",
			    DR_GET_E_RSC(hp->h_err));
			break;

		case ESBD_RESUME:
			PR_ALL("Could not resume devices (major #): %s\n",
			    DR_GET_E_RSC(hp->h_err));
			break;

		case ESBD_KTHREAD:
			PR_ALL("psmerr is ESBD_KTHREAD\n");
			break;

		case ESBD_NOERROR:
			PR_ALL("sbd_error_t error code not set\n");
			break;

		default:
			PR_ALL("Unknown error psmerr = %d\n", psmerr);
			break;
		}
	}
	dr_release_sr_handle(srh);

	return (0);
}

/*
 * Add a new integer value to the end of an array.  Don't allow duplicates to
 * appear in the array, and don't allow the array to overflow.  Return the new
 * total number of entries in the array.
 */
static int
dr_add_int(uint64_t *arr, int idx, int len, uint64_t val)
{
	int i;

	if (arr == NULL)
		return (0);

	if (idx >= len)
		return (idx);

	for (i = 0; i < idx; i++) {
		if (arr[i] == val)
			return (idx);
	}

	arr[idx++] = val;

	return (idx);
}

/*
 * Construct an sbd_error_t featuring a string representation of an array of
 * integers as its e_rsc.
 */
static sbd_error_t *
drerr_int(int e_code, uint64_t *arr, int idx, int majors)
{
	int		i, n, buf_len, buf_idx, buf_avail;
	char		*dname;
	char		*buf;
	sbd_error_t	*new_sbd_err;
	static char	s_ellipsis[] = "...";

	if (arr == NULL || idx <= 0)
		return (NULL);

	/* MAXPATHLEN is the size of the e_rsc field in sbd_error_t. */
	buf = (char *)kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	/*
	 * This is the total working area of the buffer.  It must be computed
	 * as the size of 'buf', minus reserved space for the null terminator
	 * and the ellipsis string.
	 */
	buf_len = MAXPATHLEN - (strlen(s_ellipsis) + 1);

	/* Construct a string representation of the array values */
	for (buf_idx = 0, i = 0; i < idx; i++) {
		buf_avail = buf_len - buf_idx;
		if (majors) {
			dname = ddi_major_to_name(arr[i]);
			if (dname) {
				n = snprintf(&buf[buf_idx], buf_avail, "%s, ",
				    dname);
			} else {
				n = snprintf(&buf[buf_idx], buf_avail,
				    "major %" PRIu64 ", ", arr[i]);
			}
		} else {
			n = snprintf(&buf[buf_idx], buf_avail, "%" PRIu64 ", ",
			    arr[i]);
		}

		/* An ellipsis gets appended when no more values fit */
		if (n >= buf_avail) {
			(void) strcpy(&buf[buf_idx], s_ellipsis);
			break;
		}

		buf_idx += n;
	}

	/* If all the contents fit, remove the trailing comma */
	if (n < buf_avail) {
		buf[--buf_idx] = '\0';
		buf[--buf_idx] = '\0';
	}

	/* Return an sbd_error_t with the buffer and e_code */
	new_sbd_err = drerr_new(1, e_code, buf);
	kmem_free(buf, MAXPATHLEN);
	return (new_sbd_err);
}
