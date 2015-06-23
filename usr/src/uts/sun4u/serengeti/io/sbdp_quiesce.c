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

/*
 * A CPR derivative specifically for sbd
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

#ifdef DEBUG
#include <sys/note.h>
#endif

#include <sys/promif.h>
#include <sys/conf.h>
#include <sys/cyclic.h>

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_priv.h>
#include <sys/cpu_sgnblk_defs.h>

static char *
sbdp_get_err_buf(sbd_error_t *ep)
{
	return (ep->e_rsc);
}

extern void	e_ddi_enter_driver_list(struct devnames *dnp, int *listcnt);
extern void	e_ddi_exit_driver_list(struct devnames *dnp, int listcnt);
extern int	is_pseudo_device(dev_info_t *dip);

extern kmutex_t	cpu_lock;

static int	sbdp_is_real_device(dev_info_t *dip);
#ifdef DEBUG
static int	sbdp_bypass_device(char *dname);
#endif
static int	sbdp_check_dip(dev_info_t *dip, void *arg, uint_t ref);

static int	sbdp_resolve_devname(dev_info_t *dip, char *buffer,
				char *alias);

int sbdp_test_suspend(sbdp_handle_t *hp);

#define	SR_STATE(srh)			((srh)->sr_suspend_state)
#define	SR_SET_STATE(srh, state)	(SR_STATE((srh)) = (state))
#define	SR_FAILED_DIP(srh)		((srh)->sr_failed_dip)

#define	SR_FLAG_WATCHDOG	0x1
#define	SR_CHECK_FLAG(srh, flag)	((srh)->sr_flags & (flag))
#define	SR_SET_FLAG(srh, flag)		((srh)->sr_flags |= (flag))
#define	SR_CLEAR_FLAG(srh, flag)	((srh)->sr_flags &= ~(flag))

#ifdef DEBUG
/*
 * Just for testing. List of drivers to bypass when performing a suspend.
 */
static char *sbdp_bypass_list[] = {
	/* "sgsbbc", this is an example when needed */
	""
};
#endif

#define		SKIP_SYNC	/* bypass sync ops in sbdp_suspend */

/*
 * sbdp_skip_user_threads is used to control if user threads should
 * be suspended.  If sbdp_skip_user_threads is true, the rest of the
 * flags are not used; if it is false, sbdp_check_user_stop_result
 * will be used to control whether or not we need to check suspend
 * result, and sbdp_allow_blocked_threads will be used to control
 * whether or not we allow suspend to continue if there are blocked
 * threads.  We allow all combinations of sbdp_check_user_stop_result
 * and sbdp_allow_block_threads, even though it might not make much
 * sense to not allow block threads when we don't even check stop
 * result.
 */
static int	sbdp_skip_user_threads = 0;		/* default to FALSE */
static int	sbdp_check_user_stop_result = 1;	/* default to TRUE */
static int	sbdp_allow_blocked_threads = 1;		/* default to TRUE */


static void
sbdp_stop_intr(void)
{
	kpreempt_disable();
	cyclic_suspend();
}

static void
sbdp_enable_intr(void)
{
	cyclic_resume();
	kpreempt_enable();
}

sbdp_sr_handle_t *
sbdp_get_sr_handle(void)
{
	sbdp_sr_handle_t *srh;
	srh = kmem_zalloc(sizeof (sbdp_sr_handle_t), KM_SLEEP);

	return (srh);
}

void
sbdp_release_sr_handle(sbdp_sr_handle_t *srh)
{
	ASSERT(SR_FAILED_DIP(srh) == NULL);
	kmem_free((caddr_t)srh, sizeof (sbdp_sr_handle_t));
}

static int
sbdp_is_real_device(dev_info_t *dip)
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

#ifdef DEBUG
static int
sbdp_bypass_device(char *dname)
{
	int i;
	char **lname;
	/* check the bypass list */
	for (i = 0, lname = &sbdp_bypass_list[i]; **lname != '\0'; lname++) {
		SBDP_DBG_QR("Checking %s\n", *lname);
		if (strcmp(dname, sbdp_bypass_list[i++]) == 0)
			return (1);
	}
	return (0);
}
#endif

static int
sbdp_resolve_devname(dev_info_t *dip, char *buffer, char *alias)
{
	major_t	devmajor;
	char	*aka, *name;

	*buffer = *alias = 0;

	if (dip == NULL)
		return (-1);

	if ((name = ddi_get_name(dip)) == NULL)
		name = "<null name>";

	aka = name;

	if ((devmajor = ddi_name_to_major(aka)) != -1)
		aka = ddi_major_to_name(devmajor);

	(void) strcpy(buffer, name);

	if (strcmp(name, aka))
		(void) strcpy(alias, aka);
	else
		*alias = 0;

	return (0);
}

typedef struct sbdp_ref {
	int *refcount;
	int *refcount_non_gldv3;
	sbd_error_t *sep;
} sbdp_ref_t;

static int
sbdp_check_dip(dev_info_t *dip, void *arg, uint_t ref)
{
	char		*dname;
	sbdp_ref_t	*sbrp = (sbdp_ref_t *)arg;

	if (dip == NULL)
		return (DDI_WALK_CONTINUE);

	ASSERT(sbrp->sep != NULL);
	ASSERT(sbrp->refcount != NULL);

	if (!sbdp_is_real_device(dip))
		return (DDI_WALK_CONTINUE);

	dname = ddi_binding_name(dip);

	if ((strcmp(dname, "pciclass,060940") == 0) || (strcmp(dname,
	    "pciclass,060980") == 0)) {
		(void) ddi_pathname(dip, sbdp_get_err_buf(sbrp->sep));
		sbdp_set_err(sbrp->sep, ESBD_BUSY, NULL);
		(*sbrp->refcount)++;
		return (DDI_WALK_TERMINATE);
	}

#ifdef DEBUG
	if (sbdp_bypass_device(dname))
		return (DDI_WALK_CONTINUE);
#endif

	if (ref) {
		major_t	major;

		(*sbrp->refcount)++;
		SBDP_DBG_QR("\n%s (major# %d) is referenced\n",
		    dname, ddi_name_to_major(dname));
		(void) ddi_pathname(dip, sbdp_get_err_buf(sbrp->sep));
		major = ddi_driver_major(dip);
		if (sbrp->refcount_non_gldv3 && NETWORK_PHYSDRV(major) &&
		    !GLDV3_DRV(major)) {
			(*sbrp->refcount_non_gldv3)++;
			return (DDI_WALK_CONTINUE);
		}
		sbdp_set_err(sbrp->sep, ESBD_BUSY, NULL);
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

void
sbdp_check_devices(dev_info_t *dip, int *refcount, sbd_error_t *sep,
    int *refcount_non_gldv3)
{
	sbdp_ref_t sbr;

	sbr.refcount = refcount;
	sbr.refcount_non_gldv3 = refcount_non_gldv3;
	sbr.sep = sep;

	ASSERT(e_ddi_branch_held(dip));

	(void) e_ddi_branch_referenced(dip, sbdp_check_dip, &sbr);
}

/*
 * Starting from the root node suspend all devices in the device tree.
 * Assumes that all devices have already been marked busy.
 */
static int
sbdp_suspend_devices_(dev_info_t *dip, sbdp_sr_handle_t *srh)
{
	major_t	major;
	char	*dname;

	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		char	d_name[40], d_alias[40], *d_info;

		if (sbdp_suspend_devices_(ddi_get_child(dip), srh)) {
			return (ENXIO);
		}

		if (!sbdp_is_real_device(dip))
			continue;

		major = (major_t)-1;
		if ((dname = DEVI(dip)->devi_binding_name) != NULL)
			major = ddi_name_to_major(dname);

#ifdef DEBUG
		if (sbdp_bypass_device(dname)) {
			SBDP_DBG_QR("bypassed suspend of %s (major# %d)\n",
			    dname, major);
			continue;
		}
#endif

		if ((d_info = ddi_get_name_addr(dip)) == NULL)
			d_info = "<null>";

		d_name[0] = 0;
		if (sbdp_resolve_devname(dip, d_name, d_alias) == 0) {
			if (d_alias[0] != 0) {
				SBDP_DBG_QR("\tsuspending %s@%s (aka %s)\n",
				    d_name, d_info, d_alias);
			} else {
				SBDP_DBG_QR("\tsuspending %s@%s\n",
				    d_name, d_info);
			}
		} else {
			SBDP_DBG_QR("\tsuspending %s@%s\n", dname, d_info);
		}

		if (devi_detach(dip, DDI_SUSPEND) != DDI_SUCCESS) {
			(void) sprintf(sbdp_get_err_buf(&srh->sep),
			    "%d", major);

			sbdp_set_err(&srh->sep, ESGT_SUSPEND, NULL);
			ndi_hold_devi(dip);
			SR_FAILED_DIP(srh) = dip;
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
sbdp_suspend_devices_enter(dev_info_t *dip, void *arg)
{
	struct dev_info *devi = DEVI(dip);
	ndi_devi_enter(dip, &devi->devi_circular);
	return (DDI_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
sbdp_suspend_devices_exit(dev_info_t *dip, void *arg)
{
	struct dev_info *devi = DEVI(dip);
	ndi_devi_exit(dip, devi->devi_circular);
	return (DDI_WALK_CONTINUE);
}

/*
 * Before suspending devices first mark all device nodes busy. This
 * avoids a deadlock situation when another thread holds a device busy
 * and accesses an already suspended device.
 */
static int
sbdp_suspend_devices(dev_info_t *dip, sbdp_sr_handle_t *srh)
{
	int	rv;

	/* assumes dip is ddi_root_node so no ndi_devi_enter required */
	ASSERT(dip == ddi_root_node());
	ddi_walk_devs(dip, sbdp_suspend_devices_enter, NULL);
	rv = sbdp_suspend_devices_(dip, srh);
	ddi_walk_devs(dip, sbdp_suspend_devices_exit, NULL);
	return (rv);
}

static void
sbdp_resume_devices(dev_info_t *start, sbdp_sr_handle_t *srh)
{
	int circ;
	dev_info_t	*dip, *next, *last = NULL;
	char		*bn;
	sbd_error_t	*sep;

	sep = &srh->sep;

	/* attach in reverse device tree order */
	while (last != start) {
		dip = start;
		next = ddi_get_next_sibling(dip);
		while (next != last && dip != SR_FAILED_DIP(srh)) {
			dip = next;
			next = ddi_get_next_sibling(dip);
		}
		if (dip == SR_FAILED_DIP(srh)) {
			/* Release hold acquired in sbdp_suspend_devices() */
			ndi_rele_devi(dip);
			SR_FAILED_DIP(srh) = NULL;
		} else if (sbdp_is_real_device(dip) &&
		    SR_FAILED_DIP(srh) == NULL) {

			if (DEVI(dip)->devi_binding_name != NULL) {
				bn = ddi_binding_name(dip);
			}
#ifdef DEBUG
			if (!sbdp_bypass_device(bn)) {
#else
			{
#endif
				char	d_name[40], d_alias[40], *d_info;

				d_name[0] = 0;
				d_info = ddi_get_name_addr(dip);
				if (d_info == NULL)
					d_info = "<null>";

				if (!sbdp_resolve_devname(dip, d_name,
				    d_alias)) {
					if (d_alias[0] != 0) {
						SBDP_DBG_QR("\tresuming "
						    "%s@%s (aka %s)\n",
						    d_name, d_info,
						    d_alias);
					} else {
						SBDP_DBG_QR("\tresuming "
						    "%s@%s\n",
						    d_name, d_info);
					}
				} else {
					SBDP_DBG_QR("\tresuming %s@%s\n",
					    bn, d_info);
				}

				if (devi_attach(dip, DDI_RESUME) !=
				    DDI_SUCCESS) {
					/*
					 * Print a console warning,
					 * set an errno of ESGT_RESUME,
					 * and save the driver major
					 * number in the e_str.
					 */

					(void) sprintf(sbdp_get_err_buf(sep),
					    "%s@%s",
					    d_name[0] ? d_name : bn, d_info);
					SBDP_DBG_QR("\tFAILED to resume "
					    "%s\n", sbdp_get_err_buf(sep));
					sbdp_set_err(sep,
					    ESGT_RESUME, NULL);
				}
			}
		}
		ndi_devi_enter(dip, &circ);
		sbdp_resume_devices(ddi_get_child(dip), srh);
		ndi_devi_exit(dip, circ);
		last = dip;
	}
}

/*
 * True if thread is virtually stopped.  Similar to CPR_VSTOPPED
 * but from DR point of view.  These user threads are waiting in
 * the kernel.  Once they return from kernel, they will process
 * the stop signal and stop.
 */
#define	SBDP_VSTOPPED(t)			\
	((t)->t_state == TS_SLEEP &&		\
	(t)->t_wchan != NULL &&			\
	(t)->t_astflag &&		\
	((t)->t_proc_flag & TP_CHKPT))


static int
sbdp_stop_user_threads(sbdp_sr_handle_t *srh)
{
	int		count;
	char		cache_psargs[PSARGSZ];
	kthread_id_t	cache_tp;
	uint_t		cache_t_state;
	int		bailout;
	sbd_error_t	*sep;
	kthread_id_t 	tp;

	extern void add_one_utstop();
	extern void utstop_timedwait(clock_t);
	extern void utstop_init(void);

#define	SBDP_UTSTOP_RETRY	4
#define	SBDP_UTSTOP_WAIT	hz

	if (sbdp_skip_user_threads)
		return (DDI_SUCCESS);

	sep = &srh->sep;
	ASSERT(sep);

	utstop_init();

	/* we need to try a few times to get past fork, etc. */
	for (count = 0; count < SBDP_UTSTOP_RETRY; count++) {
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
		utstop_timedwait(count * count * SBDP_UTSTOP_WAIT);


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
			    !(sbdp_allow_blocked_threads &&
			    SBDP_VSTOPPED(tp))) {

				/* nope, cache the details for later */
				bcopy(p->p_user.u_psargs, cache_psargs,
				    sizeof (cache_psargs));
				cache_tp = tp;
				cache_t_state = tp->t_state;
				bailout = 1;
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
		cmn_err(CE_NOTE, "process: %s id: %p state: %x\n",
		    cache_psargs, (void *)cache_tp, cache_t_state);

		(void) sprintf(sbdp_get_err_buf(sep), "%s", cache_psargs);
		sbdp_set_err(sep, ESGT_UTHREAD, NULL);
		return (ESRCH);
	}

	return (DDI_SUCCESS);
}

static void
sbdp_start_user_threads(void)
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
sbdp_signal_user(int sig)
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

static uint_t saved_watchdog_seconds;

void
sbdp_resume(sbdp_sr_handle_t *srh)
{
	/*
	 * update the signature block
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_RESUME_INPROGRESS, SIGSUBST_NULL,
	    CPU->cpu_id);

	switch (SR_STATE(srh)) {
	case SBDP_SRSTATE_FULL:

		ASSERT(MUTEX_HELD(&cpu_lock));

		/*
		 * Prevent false alarm in tod_validate() due to tod
		 * value change between suspend and resume
		 */
		mutex_enter(&tod_lock);
		tod_status_set(TOD_DR_RESUME_DONE);
		mutex_exit(&tod_lock);

		sbdp_enable_intr(); 	/* enable intr & clock */

		/*
		 * release all the other cpus
		 * using start_cpus() vice sbdp_release_cpus()
		 */
		start_cpus();
		mutex_exit(&cpu_lock);

		/*
		 * If we suspended hw watchdog at suspend,
		 * re-enable it now.
		 */
		if (SR_CHECK_FLAG(srh, SR_FLAG_WATCHDOG)) {
			mutex_enter(&tod_lock);
			tod_ops.tod_set_watchdog_timer(
			    saved_watchdog_seconds);
			mutex_exit(&tod_lock);
		}

		/* FALLTHROUGH */

	case SBDP_SRSTATE_DRIVER:
		/*
		 * resume devices: root node doesn't have to
		 * be held in any way.
		 */
		sbdp_resume_devices(ddi_root_node(), srh);

		/*
		 * resume the lock manager
		 */
		lm_cprresume();

		/* FALLTHROUGH */

	case SBDP_SRSTATE_USER:
		/*
		 * finally, resume user threads
		 */
		if (!sbdp_skip_user_threads) {
			SBDP_DBG_QR("DR: resuming user threads...\n");
			sbdp_start_user_threads();
		}
		/* FALLTHROUGH */

	case SBDP_SRSTATE_BEGIN:
	default:
		/*
		 * let those who care know that we've just resumed
		 */
		SBDP_DBG_QR("sending SIGTHAW...\n");
		sbdp_signal_user(SIGTHAW);
		break;
	}

	/*
	 * update the signature block
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, CPU->cpu_id);

	SBDP_DBG_QR("DR: resume COMPLETED\n");
}

int
sbdp_suspend(sbdp_sr_handle_t *srh)
{
	int force;
	int rc = DDI_SUCCESS;

	force = (srh && (srh->sr_flags & SBDP_IOCTL_FLAG_FORCE));

	/*
	 * if no force flag, check for unsafe drivers
	 */
	if (force) {
		SBDP_DBG_QR("\nsbdp_suspend invoked with force flag");
	}

	/*
	 * update the signature block
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_QUIESCE_INPROGRESS, SIGSUBST_NULL,
	    CPU->cpu_id);

	/*
	 * first, stop all user threads
	 */
	SBDP_DBG_QR("SBDP: suspending user threads...\n");
	SR_SET_STATE(srh, SBDP_SRSTATE_USER);
	if (((rc = sbdp_stop_user_threads(srh)) != DDI_SUCCESS) &&
	    sbdp_check_user_stop_result) {
		sbdp_resume(srh);
		return (rc);
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
	SBDP_DBG_QR("SBDP: suspending drivers...\n");
	SR_SET_STATE(srh, SBDP_SRSTATE_DRIVER);

	/*
	 * Root node doesn't have to be held in any way.
	 */
	if ((rc = sbdp_suspend_devices(ddi_root_node(), srh)) != DDI_SUCCESS) {
		sbdp_resume(srh);
		return (rc);
	}

	/*
	 * finally, grab all cpus
	 */
	SR_SET_STATE(srh, SBDP_SRSTATE_FULL);

	/*
	 * if watchdog was activated, disable it
	 */
	if (watchdog_activated) {
		mutex_enter(&tod_lock);
		saved_watchdog_seconds = tod_ops.tod_clear_watchdog_timer();
		mutex_exit(&tod_lock);
		SR_SET_FLAG(srh, SR_FLAG_WATCHDOG);
	} else {
		SR_CLEAR_FLAG(srh, SR_FLAG_WATCHDOG);
	}

	mutex_enter(&cpu_lock);
	pause_cpus(NULL, NULL);
	sbdp_stop_intr();

	/*
	 * update the signature block
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_QUIESCED, SIGSUBST_NULL, CPU->cpu_id);

	return (rc);
}

/*ARGSUSED*/
int
sbdp_test_suspend(sbdp_handle_t *hp)
{
	sbdp_sr_handle_t	*srh;
	int			err;

	SBDP_DBG_QR("%s...\n", "sbdp_test_suspend");

	srh = sbdp_get_sr_handle();

	srh->sr_flags = hp->h_flags;

	if ((err = sbdp_suspend(srh)) == DDI_SUCCESS) {
		sbdp_resume(srh);
	} else {
		SBDP_DBG_MISC("sbdp_suspend() failed, err = 0x%x\n", err);
	}
	sbdp_release_sr_handle(srh);

	return (0);
}

#ifdef	DEBUG
int
sbdp_passthru_test_quiesce(sbdp_handle_t *hp, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	return (sbdp_test_suspend(hp));
}
#endif
