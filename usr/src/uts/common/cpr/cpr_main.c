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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * This module contains the guts of checkpoint-resume mechanism.
 * All code in this module is platform independent.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/callb.h>
#include <sys/processor.h>
#include <sys/machsystm.h>
#include <sys/clock.h>
#include <sys/vfs.h>
#include <sys/kmem.h>
#include <nfs/lm.h>
#include <sys/systm.h>
#include <sys/cpr.h>
#include <sys/bootconf.h>
#include <sys/cyclic.h>
#include <sys/filio.h>
#include <sys/fs/ufs_filio.h>
#include <sys/epm.h>
#include <sys/modctl.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/promif.h>

extern struct cpr_terminator cpr_term;

extern int cpr_alloc_statefile(int);
extern void cpr_start_kernel_threads(void);
extern void cpr_abbreviate_devpath(char *, char *);
extern void cpr_convert_promtime(cpr_time_t *);
extern void cpr_send_notice(void);
extern void cpr_set_bitmap_size(void);
extern void cpr_stat_init();
extern void cpr_statef_close(void);
extern void flush_windows(void);

extern int pm_powering_down;

static int cpr_suspend(void);
static int cpr_resume(void);
static void cpr_suspend_init(void);

cpr_time_t wholecycle_tv;
int cpr_suspend_succeeded;
pfn_t curthreadpfn;
int curthreadremapped;

/*
 * save or restore abort_enable;  this prevents a drop
 * to kadb or prom during cpr_resume_devices() when
 * there is no kbd present;  see abort_sequence_enter()
 */
static void
cpr_sae(int stash)
{
	static int saved_ae = -1;

	if (stash) {
		saved_ae = abort_enable;
		abort_enable = 0;
	} else if (saved_ae != -1) {
		abort_enable = saved_ae;
		saved_ae = -1;
	}
}


/*
 * The main switching point for cpr, this routine starts the ckpt
 * and state file saving routines; on resume the control is
 * returned back to here and it then calls the resume routine.
 */
int
cpr_main(void)
{
	label_t saveq = ttolwp(curthread)->lwp_qsav;
	int rc;

	if (rc = cpr_default_setup(1))
		return (rc);

	/*
	 * Remember where we are for resume
	 */
	if (!setjmp(&ttolwp(curthread)->lwp_qsav)) {
		/*
		 * try to checkpoint the system, if failed return back
		 * to userland, otherwise power off.
		 */
		rc = cpr_suspend();
		if (rc || cpr_reusable_mode) {
			/*
			 * We don't really want to go down, or
			 * something went wrong in suspend, do what we can
			 * to put the system back to an operable state then
			 * return back to userland.
			 */
			(void) cpr_resume();
		}
	} else {
		/*
		 * This is the resumed side of longjmp, restore the previous
		 * longjmp pointer if there is one so this will be transparent
		 * to the world.
		 */
		ttolwp(curthread)->lwp_qsav = saveq;
		CPR->c_flags &= ~C_SUSPENDING;
		CPR->c_flags |= C_RESUMING;

		/*
		 * resume the system back to the original state
		 */
		rc = cpr_resume();
	}

	(void) cpr_default_setup(0);

	return (rc);
}


/*
 * check/disable or re-enable UFS logging
 */
static void
cpr_log_status(int enable, int *svstat, vnode_t *vp)
{
	int cmd, status, error;
	char *str, *able;
	fiolog_t fl;
	refstr_t *mntpt;

	str = "cpr_log_status";
	bzero(&fl, sizeof (fl));
	fl.error = FIOLOG_ENONE;

	/*
	 * when disabling, first get and save logging status (0 or 1)
	 */
	if (enable == 0) {
		if (error = VOP_IOCTL(vp, _FIOISLOG,
		    (uintptr_t)&status, FKIOCTL, CRED(), NULL)) {
			mntpt = vfs_getmntpoint(vp->v_vfsp);
			prom_printf("%s: \"%s\", cant get logging "
			    "status, error %d\n", str, refstr_value(mntpt),
			    error);
			refstr_rele(mntpt);
			return;
		}
		*svstat = status;
		if (cpr_debug & CPR_DEBUG5) {
			mntpt = vfs_getmntpoint(vp->v_vfsp);
			CPR_DEBUG(CPR_DEBUG5,
			    "%s: \"%s\", logging status = %d\n",
			    str, refstr_value(mntpt), status);
			refstr_rele(mntpt);
		};

		able = "disable";
		cmd = _FIOLOGDISABLE;
	} else {
		able = "enable";
		cmd = _FIOLOGENABLE;
	}

	/*
	 * disable or re-enable logging when the saved status is 1
	 */
	if (*svstat == 1) {
		error = VOP_IOCTL(vp, cmd, (uintptr_t)&fl,
		    FKIOCTL, CRED(), NULL);
		if (error) {
			mntpt = vfs_getmntpoint(vp->v_vfsp);
			prom_printf("%s: \"%s\", cant %s logging, error %d\n",
			    str, refstr_value(mntpt), able, error);
			refstr_rele(mntpt);
		} else {
			if (cpr_debug & CPR_DEBUG5) {
				mntpt = vfs_getmntpoint(vp->v_vfsp);
				CPR_DEBUG(CPR_DEBUG5,
				    "%s: \"%s\", logging is now %sd\n",
				    str, refstr_value(mntpt), able);
				refstr_rele(mntpt);
			}
		}
	}

	/*
	 * when enabling logging, reset the saved status
	 * to unknown for next time
	 */
	if (enable)
		*svstat = -1;
}


/*
 * enable/disable UFS logging on filesystems containing cpr_default_path
 * and cpr statefile.  since the statefile can be on any fs, that fs
 * needs to be handled separately.  this routine and cprboot expect that
 * CPR_CONFIG and CPR_DEFAULT both reside on the same fs, rootfs.  cprboot
 * is loaded from the device with rootfs and uses the same device to open
 * both CPR_CONFIG and CPR_DEFAULT (see common/support.c).  moving either
 * file outside of rootfs would cause errors during cprboot, plus cpr and
 * fsck problems with the new fs if logging were enabled.
 */
static int
cpr_ufs_logging(int enable)
{
	static int def_status = -1, sf_status = -1;
	struct vfs *vfsp;
	char *fname;
	vnode_t *vp;
	int error;

	if (cpr_reusable_mode)
		return (0);

	if (error = cpr_open_deffile(FREAD, &vp))
		return (error);
	cpr_log_status(enable, &def_status, vp);
	vfsp = vp->v_vfsp;
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED());
	VN_RELE(vp);

	fname = cpr_build_statefile_path();
	if (fname == NULL)
		return (ENOENT);
	if (error = vn_open(fname, UIO_SYSSPACE, FCREAT|FWRITE,
	    0600, &vp, CRCREAT, 0)) {
		prom_printf("cpr_ufs_logging: cant open/create \"%s\", "
		    "error %d\n", fname, error);
		return (error);
	}

	/*
	 * check logging status for the statefile if it resides
	 * on a different fs and the type is a regular file
	 */
	if (vp->v_vfsp != vfsp && vp->v_type == VREG)
		cpr_log_status(enable, &sf_status, vp);
	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED());
	VN_RELE(vp);

	return (0);
}


/*
 * Check if klmmod is loaded and call a lock manager service; if klmmod
 * is not loaded, the services aren't needed and a call would trigger a
 * modload, which would block since another thread would never run.
 */
static void
cpr_lock_mgr(void (*service)(void))
{
	if (mod_find_by_filename(NULL, "misc/klmmod") != NULL)
		(*service)();
}

/*
 * Take the system down to a checkpointable state and write
 * the state file, the following are sequentially executed:
 *
 *    - Request all user threads to stop themselves
 *    - push out and invalidate user pages
 *    - bring statefile inode incore to prevent a miss later
 *    - request all daemons to stop
 *    - check and make sure all threads are stopped
 *    - sync the file system
 *    - suspend all devices
 *    - block intrpts
 *    - dump system state and memory to state file
 */
static int
cpr_suspend(void)
{
	int sf_realloc, rc, skt_rc, nverr;

	cpr_set_substate(C_ST_SUSPEND_BEGIN);

	cpr_suspend_init();

	cpr_save_time();

	cpr_tod_get(&wholecycle_tv);
	CPR_STAT_EVENT_START("Suspend Total");

	if (!cpr_reusable_mode) {
		/*
		 * We need to validate default file before fs functionality
		 * is disabled.
		 */
		if (rc = cpr_validate_definfo(0))
			return (rc);
	}

	i_cpr_save_machdep_info();

	/* Stop PM scans ASAP */
	(void) callb_execute_class(CB_CL_CPR_PM, CB_CODE_CPR_CHKPT);

	pm_dispatch_to_dep_thread(PM_DEP_WK_CPR_SUSPEND,
	    NULL, NULL, PM_DEP_WAIT, NULL, 0);

	cpr_set_substate(C_ST_MP_OFFLINE);
	if (rc = cpr_mp_offline())
		return (rc);

	/*
	 * Ask the user threads to stop by themselves, but
	 * if they don't or can't after 3 retries, we give up on CPR.
	 * The 3 retry is not a random number because 2 is possible if
	 * a thread has been forked before the parent thread is stopped.
	 */
	CPR_DEBUG(CPR_DEBUG1, "\nstopping user threads...");
	CPR_STAT_EVENT_START("  stop users");
	cpr_set_substate(C_ST_STOP_USER_THREADS);
	if (rc = cpr_stop_user_threads())
		return (rc);
	CPR_STAT_EVENT_END("  stop users");
	CPR_DEBUG(CPR_DEBUG1, "done\n");

	pm_save_direct_levels();

	/*
	 * User threads are stopped.  We will start communicating with the
	 * user via prom_printf (some debug output may have already happened)
	 * so let anybody who cares know about this (bug 4096122)
	 */
	(void) callb_execute_class(CB_CL_CPR_PROMPRINTF, CB_CODE_CPR_CHKPT);

	cpr_send_notice();
	if (cpr_debug)
		prom_printf("\n");

	(void) callb_execute_class(CB_CL_CPR_POST_USER, CB_CODE_CPR_CHKPT);

	/*
	 * Reattach any drivers which originally exported the
	 * no-involuntary-power-cycles property.  We need to do this before
	 * stopping kernel threads because modload is implemented using
	 * a kernel thread.
	 */
	cpr_set_substate(C_ST_PM_REATTACH_NOINVOL);
	if (!pm_reattach_noinvol())
		return (ENXIO);

	/*
	 * if ufs logging is enabled, we need to disable before
	 * stopping kernel threads so that ufs delete and roll
	 * threads can do the work.
	 */
	cpr_set_substate(C_ST_DISABLE_UFS_LOGGING);
	if (rc = cpr_ufs_logging(0))
		return (rc);

	/*
	 * Use sync_all to swap out all user pages and find out how much
	 * extra space needed for user pages that don't have back store
	 * space left.
	 */
	CPR_STAT_EVENT_START("  swapout upages");
	vfs_sync(SYNC_ALL);
	CPR_STAT_EVENT_END("  swapout upages");

	cpr_set_bitmap_size();

alloc_statefile:
	/*
	 * If our last state was C_ST_DUMP_NOSPC, we're trying to realloc
	 * the statefile, otherwise this is the first attempt.
	 */
	sf_realloc = (CPR->c_substate == C_ST_DUMP_NOSPC) ? 1 : 0;

	CPR_STAT_EVENT_START("  alloc statefile");
	cpr_set_substate(C_ST_STATEF_ALLOC);
	if (rc = cpr_alloc_statefile(sf_realloc)) {
		if (sf_realloc)
			prom_printf("realloc failed\n");
		return (rc);
	}
	CPR_STAT_EVENT_END("  alloc statefile");

	/*
	 * Sync the filesystem to preserve its integrity.
	 *
	 * This sync is also used to flush out all B_DELWRI buffers (fs cache)
	 * which are mapped and neither dirty nor referenced before
	 * cpr_invalidate_pages destroys them. fsflush does similar thing.
	 */
	sync();

	/*
	 * destroy all clean file mapped kernel pages
	 */
	CPR_STAT_EVENT_START("  clean pages");
	CPR_DEBUG(CPR_DEBUG1, "cleaning up mapped pages...");
	(void) callb_execute_class(CB_CL_CPR_VM, CB_CODE_CPR_CHKPT);
	CPR_DEBUG(CPR_DEBUG1, "done\n");
	CPR_STAT_EVENT_END("  clean pages");


	/*
	 * Hooks needed by lock manager prior to suspending.
	 * Refer to code for more comments.
	 */
	cpr_lock_mgr(lm_cprsuspend);

	/*
	 * Now suspend all the devices
	 */
	CPR_STAT_EVENT_START("  stop drivers");
	CPR_DEBUG(CPR_DEBUG1, "suspending drivers...");
	cpr_set_substate(C_ST_SUSPEND_DEVICES);
	pm_powering_down = 1;
	rc = cpr_suspend_devices(ddi_root_node());
	pm_powering_down = 0;
	if (rc)
		return (rc);
	CPR_DEBUG(CPR_DEBUG1, "done\n");
	CPR_STAT_EVENT_END("  stop drivers");

	/*
	 * Stop all daemon activities
	 */
	cpr_set_substate(C_ST_STOP_KERNEL_THREADS);
	if (skt_rc = cpr_stop_kernel_threads())
		return (skt_rc);

	(void) callb_execute_class(CB_CL_CPR_POST_KERNEL, CB_CODE_CPR_CHKPT);

	pm_reattach_noinvol_fini();

	cpr_sae(1);

	(void) callb_execute_class(CB_CL_CPR_CALLOUT, CB_CODE_CPR_CHKPT);

	/*
	 * It's safer to do tod_get before we disable all intr.
	 */
	CPR_STAT_EVENT_START("  write statefile");

	/*
	 * it's time to ignore the outside world, stop the real time
	 * clock and disable any further intrpt activity.
	 */
	i_cpr_handle_xc(1);	/* turn it on to disable xc assertion */

	mutex_enter(&cpu_lock);
	cyclic_suspend();
	mutex_exit(&cpu_lock);

	mon_clock_stop();
	mon_clock_unshare();
	mon_clock_start();

	i_cpr_stop_intr();
	CPR_DEBUG(CPR_DEBUG1, "interrupt is stopped\n");

	/*
	 * Since we will now disable the mechanism that causes prom_printfs
	 * to power up (if needed) the console fb/monitor, we assert that
	 * it must be up now.
	 */
	ASSERT(pm_cfb_is_up());
	prom_suspend_prepost();

	/*
	 * getting ready to write ourself out, flush the register
	 * windows to make sure that our stack is good when we
	 * come back on the resume side.
	 */
	flush_windows();

	/*
	 * FATAL: NO MORE MEMORY ALLOCATION ALLOWED AFTER THIS POINT!!!
	 *
	 * The system is quiesced at this point, we are ready to either dump
	 * to the state file for a extended sleep or a simple shutdown for
	 * systems with non-volatile memory.
	 */

	/*
	 * special handling for reusable:
	 */
	if (cpr_reusable_mode) {
		cpr_set_substate(C_ST_SETPROPS_1);
		if (nverr = cpr_set_properties(1))
			return (nverr);
	}

	cpr_set_substate(C_ST_DUMP);
	rc = cpr_dump(C_VP);

	/*
	 * if any error occured during dump, more
	 * special handling for reusable:
	 */
	if (rc && cpr_reusable_mode) {
		cpr_set_substate(C_ST_SETPROPS_0);
		if (nverr = cpr_set_properties(0))
			return (nverr);
	}

	if (rc == ENOSPC) {
		cpr_set_substate(C_ST_DUMP_NOSPC);
		(void) cpr_resume();
		goto alloc_statefile;
	} else if (rc == 0) {
		if (cpr_reusable_mode) {
			cpr_set_substate(C_ST_REUSABLE);
			longjmp(&ttolwp(curthread)->lwp_qsav);
		} else
			rc = cpr_set_properties(1);
	}
	return (rc);
}


/*
 * Bring the system back up from a checkpoint, at this point
 * the VM has been minimally restored by boot, the following
 * are executed sequentially:
 *
 *    - machdep setup and enable interrupts (mp startup if it's mp)
 *    - resume all devices
 *    - restart daemons
 *    - put all threads back on run queue
 */
static int
cpr_resume(void)
{
	cpr_time_t pwron_tv, *ctp;
	char *str;
	int rc = 0;

	/*
	 * The following switch is used to resume the system
	 * that was suspended to a different level.
	 */
	CPR_DEBUG(CPR_DEBUG1, "\nEntering cpr_resume...\n");

	/*
	 * Note:
	 *
	 * The rollback labels rb_xyz do not represent the cpr resume
	 * state when event 'xyz' has happened. Instead they represent
	 * the state during cpr suspend when event 'xyz' was being
	 * entered (and where cpr suspend failed). The actual call that
	 * failed may also need to be partially rolled back, since they
	 * aren't atomic in most cases.  In other words, rb_xyz means
	 * "roll back all cpr suspend events that happened before 'xyz',
	 * and the one that caused the failure, if necessary."
	 */
	switch (CPR->c_substate) {
	case C_ST_DUMP:
		/*
		 * This is most likely a full-fledged cpr_resume after
		 * a complete and successful cpr suspend. Just roll back
		 * everything.
		 */
		break;

	case C_ST_REUSABLE:
	case C_ST_DUMP_NOSPC:
	case C_ST_SETPROPS_0:
	case C_ST_SETPROPS_1:
		/*
		 * C_ST_REUSABLE and C_ST_DUMP_NOSPC are the only two
		 * special switch cases here. The other two do not have
		 * any state change during cpr_suspend() that needs to
		 * be rolled back. But these are exit points from
		 * cpr_suspend, so theoretically (or in the future), it
		 * is possible that a need for roll back of a state
		 * change arises between these exit points.
		 */
		goto rb_dump;

	case C_ST_STOP_KERNEL_THREADS:
		goto rb_stop_kernel_threads;

	case C_ST_SUSPEND_DEVICES:
		goto rb_suspend_devices;

	case C_ST_STATEF_ALLOC:
		goto rb_statef_alloc;

	case C_ST_DISABLE_UFS_LOGGING:
		goto rb_disable_ufs_logging;

	case C_ST_PM_REATTACH_NOINVOL:
		goto rb_pm_reattach_noinvol;

	case C_ST_STOP_USER_THREADS:
		goto rb_stop_user_threads;

	case C_ST_MP_OFFLINE:
		goto rb_mp_offline;

	default:
		goto rb_others;
	}

rb_all:
	/*
	 * setup debugger trapping.
	 */
	if (cpr_suspend_succeeded)
		i_cpr_set_tbr();

	/*
	 * tell prom to monitor keys before the kernel comes alive
	 */
	mon_clock_start();

	/*
	 * perform platform-dependent initialization
	 */
	if (cpr_suspend_succeeded)
		i_cpr_machdep_setup();

	/*
	 * system did not really go down if we jump here
	 */
rb_dump:
	/*
	 * IMPORTANT:  SENSITIVE RESUME SEQUENCE
	 *
	 * DO NOT ADD ANY INITIALIZATION STEP BEFORE THIS POINT!!
	 */
	(void) callb_execute_class(CB_CL_CPR_DMA, CB_CODE_CPR_RESUME);
	if (cpr_suspend_succeeded)
		(void) callb_execute_class(CB_CL_CPR_RPC, CB_CODE_CPR_RESUME);

	prom_resume_prepost();

	if (cpr_suspend_succeeded && (boothowto & RB_DEBUG))
		kdi_dvec_cpr_restart();

	/*
	 * let the tmp callout catch up.
	 */
	(void) callb_execute_class(CB_CL_CPR_CALLOUT, CB_CODE_CPR_RESUME);

	i_cpr_enable_intr();

	mon_clock_stop();
	mon_clock_share();

	mutex_enter(&cpu_lock);
	cyclic_resume();
	mutex_exit(&cpu_lock);

	mon_clock_start();

	i_cpr_handle_xc(0);	/* turn it off to allow xc assertion */

	(void) callb_execute_class(CB_CL_CPR_POST_KERNEL, CB_CODE_CPR_RESUME);

	/*
	 * statistics gathering
	 */
	if (cpr_suspend_succeeded) {
		/*
		 * Prevent false alarm in tod_validate() due to tod
		 * value change between suspend and resume
		 */
		cpr_tod_fault_reset();

		cpr_convert_promtime(&pwron_tv);

		ctp = &cpr_term.tm_shutdown;
		CPR_STAT_EVENT_END_TMZ("  write statefile", ctp);
		CPR_STAT_EVENT_END_TMZ("Suspend Total", ctp);

		CPR_STAT_EVENT_START_TMZ("Resume Total", &pwron_tv);

		str = "  prom time";
		CPR_STAT_EVENT_START_TMZ(str, &pwron_tv);
		ctp = &cpr_term.tm_cprboot_start;
		CPR_STAT_EVENT_END_TMZ(str, ctp);

		str = "  read statefile";
		CPR_STAT_EVENT_START_TMZ(str, ctp);
		ctp = &cpr_term.tm_cprboot_end;
		CPR_STAT_EVENT_END_TMZ(str, ctp);
	}

rb_stop_kernel_threads:
	/*
	 * Put all threads back to where they belong; get the kernel
	 * daemons straightened up too. Note that the callback table
	 * locked during cpr_stop_kernel_threads() is released only
	 * in cpr_start_kernel_threads(). Ensure modunloading is
	 * disabled before starting kernel threads, we don't want
	 * modunload thread to start changing device tree underneath.
	 */
	modunload_disable();
	cpr_start_kernel_threads();

rb_suspend_devices:
	CPR_DEBUG(CPR_DEBUG1, "resuming devices...");
	CPR_STAT_EVENT_START("  start drivers");

	/*
	 * The policy here is to continue resume everything we can if we did
	 * not successfully finish suspend; and panic if we are coming back
	 * from a fully suspended system.
	 */
	rc = cpr_resume_devices(ddi_root_node(), 0);

	cpr_sae(0);

	str = "Failed to resume one or more devices.";
	if (rc && CPR->c_substate == C_ST_DUMP)
		cpr_err(CE_PANIC, str);
	else if (rc)
		cpr_err(CE_WARN, str);
	CPR_STAT_EVENT_END("  start drivers");
	CPR_DEBUG(CPR_DEBUG1, "done\n");

	/*
	 * If we had disabled modunloading in this cpr resume cycle (i.e. we
	 * resumed from a state earlier than C_ST_SUSPEND_DEVICES), re-enable
	 * modunloading now.
	 */
	if (CPR->c_substate != C_ST_SUSPEND_DEVICES)
		modunload_enable();

	/*
	 * Hooks needed by lock manager prior to resuming.
	 * Refer to code for more comments.
	 */
	cpr_lock_mgr(lm_cprresume);

	/*
	 * This is a partial (half) resume during cpr suspend, we
	 * haven't yet given up on the suspend. On return from here,
	 * cpr_suspend() will try to reallocate and retry the suspend.
	 */
	if (CPR->c_substate == C_ST_DUMP_NOSPC) {
		mon_clock_stop();
		return (0);
	}

rb_statef_alloc:
	cpr_statef_close();

rb_disable_ufs_logging:
	/*
	 * if ufs logging was disabled, re-enable
	 */
	(void) cpr_ufs_logging(1);

rb_pm_reattach_noinvol:
	/*
	 * When pm_reattach_noinvol() succeeds, modunload_thread will
	 * remain disabled until after cpr suspend passes the
	 * C_ST_STOP_KERNEL_THREADS state. If any failure happens before
	 * cpr suspend reaches this state, we'll need to enable modunload
	 * thread during rollback.
	 */
	if (CPR->c_substate == C_ST_DISABLE_UFS_LOGGING ||
	    CPR->c_substate == C_ST_STATEF_ALLOC ||
	    CPR->c_substate == C_ST_SUSPEND_DEVICES ||
	    CPR->c_substate == C_ST_STOP_KERNEL_THREADS) {
		pm_reattach_noinvol_fini();
	}

	(void) callb_execute_class(CB_CL_CPR_POST_USER, CB_CODE_CPR_RESUME);
	(void) callb_execute_class(CB_CL_CPR_PROMPRINTF, CB_CODE_CPR_RESUME);

	pm_restore_direct_levels();

rb_stop_user_threads:
	CPR_DEBUG(CPR_DEBUG1, "starting user threads...");
	cpr_start_user_threads();
	CPR_DEBUG(CPR_DEBUG1, "done\n");

rb_mp_offline:
	if (cpr_mp_online())
		cpr_err(CE_WARN, "Failed to online all the processors.");

rb_others:
	pm_dispatch_to_dep_thread(PM_DEP_WK_CPR_RESUME, NULL, NULL, PM_DEP_WAIT,
		NULL, 0);

	(void) callb_execute_class(CB_CL_CPR_PM, CB_CODE_CPR_RESUME);

	/*
	 * now that all the drivers are going, kernel kbd driver can
	 * take over, turn off prom monitor clock
	 */
	mon_clock_stop();

	if (cpr_suspend_succeeded) {
		cpr_restore_time();
		cpr_stat_record_events();
	}

	if (!cpr_reusable_mode)
		cpr_clear_definfo();

	CPR_DEBUG(CPR_DEBUG1, "Sending SIGTHAW...");
	cpr_signal_user(SIGTHAW);
	CPR_DEBUG(CPR_DEBUG1, "done\n");

	CPR_STAT_EVENT_END("Resume Total");

	CPR_STAT_EVENT_START_TMZ("WHOLE CYCLE", &wholecycle_tv);
	CPR_STAT_EVENT_END("WHOLE CYCLE");

	if (cpr_debug & CPR_DEBUG1)
		cmn_err(CE_CONT, "\nThe system is back where you left!\n");

	CPR_STAT_EVENT_START("POST CPR DELAY");

#ifdef CPR_STAT
	ctp = &cpr_term.tm_shutdown;
	CPR_STAT_EVENT_START_TMZ("PWROFF TIME", ctp);
	CPR_STAT_EVENT_END_TMZ("PWROFF TIME", &pwron_tv);

	CPR_STAT_EVENT_PRINT();
#endif /* CPR_STAT */

	return (rc);
}

static void
cpr_suspend_init(void)
{
	cpr_time_t *ctp;

	cpr_stat_init();

	/*
	 * If cpr_suspend() failed before cpr_dump() gets a chance
	 * to reinitialize the terminator of the statefile,
	 * the values of the old terminator will still linger around.
	 * Since the terminator contains information that we need to
	 * decide whether suspend succeeded or not, we need to
	 * reinitialize it as early as possible.
	 */
	cpr_term.real_statef_size = 0;
	ctp = &cpr_term.tm_shutdown;
	bzero(ctp, sizeof (*ctp));
	ctp = &cpr_term.tm_cprboot_start;
	bzero(ctp, sizeof (*ctp));
	ctp = &cpr_term.tm_cprboot_end;
	bzero(ctp, sizeof (*ctp));

	/*
	 * Lookup the physical address of our thread structure.  This should
	 * never be invalid and the entire thread structure is expected
	 * to reside within the same pfn.
	 */
	curthreadpfn = hat_getpfnum(kas.a_hat, (caddr_t)curthread);
	ASSERT(curthreadpfn != PFN_INVALID);
	ASSERT(curthreadpfn == hat_getpfnum(kas.a_hat,
	    (caddr_t)curthread + sizeof (kthread_t) - 1));

	cpr_suspend_succeeded = 0;
}
