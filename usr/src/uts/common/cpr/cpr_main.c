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
#include <sys/srn.h>
#include <sys/cpr_impl.h>

#define	PPM(dip) ((dev_info_t *)DEVI(dip)->devi_pm_ppm)

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
extern void (*srn_signal)(int, int);
extern void init_cpu_syscall(struct cpu *);
extern void i_cpr_pre_resume_cpus();
extern void i_cpr_post_resume_cpus();
extern int cpr_is_ufs(struct vfs *);

extern int pm_powering_down;
extern kmutex_t srn_clone_lock;
extern int srn_inuse;

static int cpr_suspend(int);
static int cpr_resume(int);
static void cpr_suspend_init(int);
#if defined(__x86)
static int cpr_suspend_cpus(void);
static void cpr_resume_cpus(void);
#endif
static int cpr_all_online(void);
static void cpr_restore_offline(void);

cpr_time_t wholecycle_tv;
int cpr_suspend_succeeded;
pfn_t curthreadpfn;
int curthreadremapped;

extern cpuset_t cpu_ready_set;

extern processorid_t i_cpr_bootcpuid(void);
extern cpu_t *i_cpr_bootcpu(void);
extern void tsc_adjust_delta(hrtime_t tdelta);
extern void tsc_resume(void);
extern int tsc_resume_in_cyclic;

/*
 * Set this variable to 1, to have device drivers resume in an
 * uniprocessor environment. This is to allow drivers that assume
 * that they resume on a UP machine to continue to work. Should be
 * deprecated once the broken drivers are fixed
 */
int cpr_resume_uniproc = 0;

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
cpr_main(int sleeptype)
{
	int rc, rc2;
	label_t saveq;
	klwp_t *tlwp = ttolwp(curthread);

	if (sleeptype == CPR_TODISK) {
		if ((rc = cpr_default_setup(1)) != 0)
			return (rc);
		ASSERT(tlwp);
		saveq = tlwp->lwp_qsav;
	}

	if (sleeptype == CPR_TORAM) {
		rc = cpr_suspend(sleeptype);
		PMD(PMD_SX, ("cpr_suspend rets %x\n", rc))
		if (rc == 0) {
			int i_cpr_power_down(int sleeptype);

			/*
			 * From this point on, we should be at a high
			 * spl, interrupts disabled, and all but one
			 * cpu's paused (effectively UP/single threaded).
			 * So this is were we want to put ASSERTS()
			 * to let us know otherwise.
			 */
			ASSERT(cpus_paused());

			/*
			 * Now do the work of actually putting this
			 * machine to sleep!
			 */
			rc = i_cpr_power_down(sleeptype);
			if (rc == 0) {
				PMD(PMD_SX, ("back from successful suspend\n"))
			}
			/*
			 * We do care about the return value from cpr_resume
			 * at this point, as it will tell us if one of the
			 * resume functions failed (cpr_resume_devices())
			 * However, for this to return and _not_ panic, means
			 * that we must be in one of the test functions.  So
			 * check for that and return an appropriate message.
			 */
			rc2 = cpr_resume(sleeptype);
			if (rc2 != 0) {
				ASSERT(cpr_test_point > 0);
				cmn_err(CE_NOTE,
				    "cpr_resume returned non-zero: %d\n", rc2);
				PMD(PMD_SX, ("cpr_resume rets %x\n", rc2))
			}
			ASSERT(!cpus_paused());
		} else {
			PMD(PMD_SX, ("failed suspend, resuming\n"))
			rc = cpr_resume(sleeptype);
		}
		return (rc);
	}
	/*
	 * Remember where we are for resume after reboot
	 */
	if (!setjmp(&tlwp->lwp_qsav)) {
		/*
		 * try to checkpoint the system, if failed return back
		 * to userland, otherwise power off.
		 */
		rc = cpr_suspend(sleeptype);
		if (rc || cpr_reusable_mode) {
			/*
			 * We don't really want to go down, or
			 * something went wrong in suspend, do what we can
			 * to put the system back to an operable state then
			 * return back to userland.
			 */
			PMD(PMD_SX, ("failed suspend, resuming\n"))
			(void) cpr_resume(sleeptype);
			PMD(PMD_SX, ("back from failed suspend resume\n"))
		}
	} else {
		/*
		 * This is the resumed side of longjmp, restore the previous
		 * longjmp pointer if there is one so this will be transparent
		 * to the world.
		 * This path is only for CPR_TODISK, where we reboot
		 */
		ASSERT(sleeptype == CPR_TODISK);
		tlwp->lwp_qsav = saveq;
		CPR->c_flags &= ~C_SUSPENDING;
		CPR->c_flags |= C_RESUMING;

		/*
		 * resume the system back to the original state
		 */
		rc = cpr_resume(sleeptype);
		PMD(PMD_SX, ("back from successful suspend; resume rets %x\n",
		    rc))
	}

	(void) cpr_default_setup(0);

	return (rc);
}


#if defined(__sparc)

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
		    (uintptr_t)&status, FKIOCTL, CRED(), NULL, NULL)) {
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
			errp("%s: \"%s\", logging status = %d\n",
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
		    FKIOCTL, CRED(), NULL, NULL);
		if (error) {
			mntpt = vfs_getmntpoint(vp->v_vfsp);
			prom_printf("%s: \"%s\", cant %s logging, error %d\n",
			    str, refstr_value(mntpt), able, error);
			refstr_rele(mntpt);
		} else {
			if (cpr_debug & CPR_DEBUG5) {
				mntpt = vfs_getmntpoint(vp->v_vfsp);
				errp("%s: \"%s\", logging is now %sd\n",
				    str, refstr_value(mntpt), able);
				refstr_rele(mntpt);
			};
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
	vfsp = vp->v_vfsp;
	if (!cpr_is_ufs(vfsp)) {
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (0);
	}

	cpr_log_status(enable, &def_status, vp);
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
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
	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);

	return (0);
}
#endif


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

int
cpr_suspend_cpus(void)
{
	int	ret = 0;
	extern void *i_cpr_save_context(void *arg);

	mutex_enter(&cpu_lock);

	/*
	 * the machine could not have booted without a bootcpu
	 */
	ASSERT(i_cpr_bootcpu() != NULL);

	/*
	 * bring all the offline cpus online
	 */
	if ((ret = cpr_all_online())) {
		mutex_exit(&cpu_lock);
		return (ret);
	}

	/*
	 * Set the affinity to be the boot processor
	 * This is cleared in either cpr_resume_cpus() or cpr_unpause_cpus()
	 */
	affinity_set(i_cpr_bootcpuid());

	ASSERT(CPU->cpu_id == 0);

	PMD(PMD_SX, ("curthread running on bootcpu\n"))

	/*
	 * pause all other running CPUs and save the CPU state at the sametime
	 */
	pause_cpus(NULL, i_cpr_save_context);

	mutex_exit(&cpu_lock);

	return (0);
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
 *    - SPARC code will not be called with CPR_TORAM, caller filters
 */
static int
cpr_suspend(int sleeptype)
{
#if defined(__sparc)
	int sf_realloc, nverr;
#endif
	int	rc = 0;
	int	skt_rc = 0;

	PMD(PMD_SX, ("cpr_suspend %x\n", sleeptype))
	cpr_set_substate(C_ST_SUSPEND_BEGIN);

	cpr_suspend_init(sleeptype);

	cpr_save_time();

	cpr_tod_get(&wholecycle_tv);
	CPR_STAT_EVENT_START("Suspend Total");

	i_cpr_alloc_cpus();

#if defined(__sparc)
	ASSERT(sleeptype == CPR_TODISK);
	if (!cpr_reusable_mode) {
		/*
		 * We need to validate default file before fs
		 * functionality is disabled.
		 */
		if (rc = cpr_validate_definfo(0))
			return (rc);
	}
	i_cpr_save_machdep_info();
#endif

	PMD(PMD_SX, ("cpr_suspend: stop scans\n"))
	/* Stop PM scans ASAP */
	(void) callb_execute_class(CB_CL_CPR_PM, CB_CODE_CPR_CHKPT);

	pm_dispatch_to_dep_thread(PM_DEP_WK_CPR_SUSPEND,
	    NULL, NULL, PM_DEP_WAIT, NULL, 0);

#if defined(__sparc)
	ASSERT(sleeptype == CPR_TODISK);
	cpr_set_substate(C_ST_MP_OFFLINE);
	if (rc = cpr_mp_offline())
		return (rc);
#endif
	/*
	 * Ask Xorg to suspend the frame buffer, and wait for it to happen
	 */
	mutex_enter(&srn_clone_lock);
	if (srn_signal) {
		PMD(PMD_SX, ("cpr_suspend: (*srn_signal)(..., "
		    "SRN_SUSPEND_REQ)\n"))
		srn_inuse = 1;	/* because *(srn_signal) cv_waits */
		(*srn_signal)(SRN_TYPE_APM, SRN_SUSPEND_REQ);
		srn_inuse = 0;
	} else {
		PMD(PMD_SX, ("cpr_suspend: srn_signal NULL\n"))
	}
	mutex_exit(&srn_clone_lock);

	/*
	 * Ask the user threads to stop by themselves, but
	 * if they don't or can't after 3 retries, we give up on CPR.
	 * The 3 retry is not a random number because 2 is possible if
	 * a thread has been forked before the parent thread is stopped.
	 */
	CPR_DEBUG(CPR_DEBUG1, "\nstopping user threads...");
	CPR_STAT_EVENT_START("  stop users");
	cpr_set_substate(C_ST_STOP_USER_THREADS);
	PMD(PMD_SX, ("cpr_suspend: stop user threads\n"))
	if (rc = cpr_stop_user_threads())
		return (rc);
	CPR_STAT_EVENT_END("  stop users");
	CPR_DEBUG(CPR_DEBUG1, "done\n");

	PMD(PMD_SX, ("cpr_suspend: save direct levels\n"))
	pm_save_direct_levels();

	/*
	 * User threads are stopped.  We will start communicating with the
	 * user via prom_printf (some debug output may have already happened)
	 * so let anybody who cares know about this (bug 4096122)
	 */
	(void) callb_execute_class(CB_CL_CPR_PROMPRINTF, CB_CODE_CPR_CHKPT);

	PMD(PMD_SX, ("cpr_suspend: send notice\n"))
#ifndef DEBUG
	cpr_send_notice();
	if (cpr_debug)
		prom_printf("\n");
#endif

	PMD(PMD_SX, ("cpr_suspend: POST USER callback\n"))
	(void) callb_execute_class(CB_CL_CPR_POST_USER, CB_CODE_CPR_CHKPT);

	/*
	 * Reattach any drivers which originally exported the
	 * no-involuntary-power-cycles property.  We need to do this before
	 * stopping kernel threads because modload is implemented using
	 * a kernel thread.
	 */
	cpr_set_substate(C_ST_PM_REATTACH_NOINVOL);
	PMD(PMD_SX, ("cpr_suspend: reattach noinvol\n"))
	if (!pm_reattach_noinvol())
		return (ENXIO);

#if defined(__sparc)
	ASSERT(sleeptype == CPR_TODISK);
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
	 * If our last state was C_ST_DUMP_NOSPC, we're trying to
	 * realloc the statefile, otherwise this is the first attempt.
	 */
	sf_realloc = (CPR->c_substate == C_ST_DUMP_NOSPC) ? 1 : 0;

	CPR_STAT_EVENT_START("  alloc statefile");
	cpr_set_substate(C_ST_STATEF_ALLOC);
	if (rc = cpr_alloc_statefile(sf_realloc)) {
		if (sf_realloc)
			errp("realloc failed\n");
		return (rc);
	}
	CPR_STAT_EVENT_END("  alloc statefile");

	/*
	 * Sync the filesystem to preserve its integrity.
	 *
	 * This sync is also used to flush out all B_DELWRI buffers
	 * (fs cache) which are mapped and neither dirty nor referenced
	 * before cpr_invalidate_pages destroys them.
	 * fsflush does similar thing.
	 */
	sync();

	/*
	 * destroy all clean file mapped kernel pages
	 */
	CPR_STAT_EVENT_START("  clean pages");
	CPR_DEBUG(CPR_DEBUG1, ("cleaning up mapped pages..."));
	(void) callb_execute_class(CB_CL_CPR_VM, CB_CODE_CPR_CHKPT);
	CPR_DEBUG(CPR_DEBUG1, ("done\n"));
	CPR_STAT_EVENT_END("  clean pages");
#endif


	/*
	 * Hooks needed by lock manager prior to suspending.
	 * Refer to code for more comments.
	 */
	PMD(PMD_SX, ("cpr_suspend: lock mgr\n"))
	cpr_lock_mgr(lm_cprsuspend);

	/*
	 * Now suspend all the devices
	 */
	CPR_STAT_EVENT_START("  stop drivers");
	CPR_DEBUG(CPR_DEBUG1, "suspending drivers...");
	cpr_set_substate(C_ST_SUSPEND_DEVICES);
	pm_powering_down = 1;
	PMD(PMD_SX, ("cpr_suspend: suspending devices\n"))
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
	PMD(PMD_SX, ("cpr_suspend: stopping kernel threads\n"))
	if (skt_rc = cpr_stop_kernel_threads())
		return (skt_rc);

	PMD(PMD_SX, ("cpr_suspend: POST KERNEL callback\n"))
	(void) callb_execute_class(CB_CL_CPR_POST_KERNEL, CB_CODE_CPR_CHKPT);

	PMD(PMD_SX, ("cpr_suspend: reattach noinvol fini\n"))
	pm_reattach_noinvol_fini();

	cpr_sae(1);

	PMD(PMD_SX, ("cpr_suspend: CPR CALLOUT callback\n"))
	(void) callb_execute_class(CB_CL_CPR_CALLOUT, CB_CODE_CPR_CHKPT);

	if (sleeptype == CPR_TODISK) {
		/*
		 * It's safer to do tod_get before we disable all intr.
		 */
		CPR_STAT_EVENT_START("  write statefile");
	}

	/*
	 * it's time to ignore the outside world, stop the real time
	 * clock and disable any further intrpt activity.
	 */
	PMD(PMD_SX, ("cpr_suspend: handle xc\n"))
	i_cpr_handle_xc(1);	/* turn it on to disable xc assertion */

	mutex_enter(&cpu_lock);
	PMD(PMD_SX, ("cpr_suspend: cyclic suspend\n"))
	cyclic_suspend();
	mutex_exit(&cpu_lock);

	/*
	 * Due to the different methods of resuming the system between
	 * CPR_TODISK (boot cprboot on SPARC, which reloads kernel image)
	 * and CPR_TORAM (restart via reset into existing kernel image)
	 * cpus are not suspended and restored in the SPARC case, since it
	 * is necessary to restart the cpus and pause them before restoring
	 * the OBP image
	 */

#if defined(__x86)

	/* pause aux cpus */
	PMD(PMD_SX, ("pause aux cpus\n"))

	cpr_set_substate(C_ST_MP_PAUSED);

	if ((rc = cpr_suspend_cpus()) != 0)
		return (rc);
#endif

	PMD(PMD_SX, ("cpr_suspend: stop intr\n"))
	i_cpr_stop_intr();
	CPR_DEBUG(CPR_DEBUG1, "interrupt is stopped\n");

	/*
	 * Since we will now disable the mechanism that causes prom_printfs
	 * to power up (if needed) the console fb/monitor, we assert that
	 * it must be up now.
	 */
	ASSERT(pm_cfb_is_up());
	PMD(PMD_SX, ("cpr_suspend: prom suspend prepost\n"))
	prom_suspend_prepost();

#if defined(__sparc)
	/*
	 * getting ready to write ourself out, flush the register
	 * windows to make sure that our stack is good when we
	 * come back on the resume side.
	 */
	flush_windows();
#endif

	/*
	 * For S3, we're done
	 */
	if (sleeptype == CPR_TORAM) {
		PMD(PMD_SX, ("cpr_suspend rets %x\n", rc))
		cpr_set_substate(C_ST_NODUMP);
		return (rc);
	}
#if defined(__sparc)
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
	 * if any error occurred during dump, more
	 * special handling for reusable:
	 */
	if (rc && cpr_reusable_mode) {
		cpr_set_substate(C_ST_SETPROPS_0);
		if (nverr = cpr_set_properties(0))
			return (nverr);
	}

	if (rc == ENOSPC) {
		cpr_set_substate(C_ST_DUMP_NOSPC);
		(void) cpr_resume(sleeptype);
		goto alloc_statefile;
	} else if (rc == 0) {
		if (cpr_reusable_mode) {
			cpr_set_substate(C_ST_REUSABLE);
			longjmp(&ttolwp(curthread)->lwp_qsav);
		} else
			rc = cpr_set_properties(1);
	}
#endif
	PMD(PMD_SX, ("cpr_suspend: return %d\n", rc))
	return (rc);
}

void
cpr_resume_cpus(void)
{
	/*
	 * this is a cut down version of start_other_cpus()
	 * just do the initialization to wake the other cpus
	 */

#if defined(__x86)
	/*
	 * Initialize our syscall handlers
	 */
	init_cpu_syscall(CPU);

#endif

	i_cpr_pre_resume_cpus();

	/*
	 * Restart the paused cpus
	 */
	mutex_enter(&cpu_lock);
	start_cpus();
	mutex_exit(&cpu_lock);

	i_cpr_post_resume_cpus();

	mutex_enter(&cpu_lock);
	/*
	 * clear the affinity set in cpr_suspend_cpus()
	 */
	affinity_clear();

	/*
	 * offline all the cpus that were brought online during suspend
	 */
	cpr_restore_offline();

	mutex_exit(&cpu_lock);
}

void
cpr_unpause_cpus(void)
{
	/*
	 * Now restore the system back to what it was before we suspended
	 */

	PMD(PMD_SX, ("cpr_unpause_cpus: restoring system\n"))

	mutex_enter(&cpu_lock);
	/*
	 * Restart the paused cpus
	 */
	start_cpus();

	/*
	 * clear the affinity set in cpr_suspend_cpus()
	 */
	affinity_clear();

	/*
	 * offline all the cpus that were brought online during suspend
	 */
	cpr_restore_offline();

	mutex_exit(&cpu_lock);
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
cpr_resume(int sleeptype)
{
	cpr_time_t pwron_tv, *ctp;
	char *str;
	int rc = 0;

	/*
	 * The following switch is used to resume the system
	 * that was suspended to a different level.
	 */
	CPR_DEBUG(CPR_DEBUG1, "\nEntering cpr_resume...\n");
	PMD(PMD_SX, ("cpr_resume %x\n", sleeptype))

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
#if defined(__sparc)
	case C_ST_DUMP:
		/*
		 * This is most likely a full-fledged cpr_resume after
		 * a complete and successful cpr suspend. Just roll back
		 * everything.
		 */
		ASSERT(sleeptype == CPR_TODISK);
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
		ASSERT(sleeptype == CPR_TODISK);
		goto rb_dump;
#endif

	case C_ST_NODUMP:
		PMD(PMD_SX, ("cpr_resume: NODUMP\n"))
		goto rb_nodump;

	case C_ST_STOP_KERNEL_THREADS:
		PMD(PMD_SX, ("cpr_resume: STOP_KERNEL_THREADS\n"))
		goto rb_stop_kernel_threads;

	case C_ST_SUSPEND_DEVICES:
		PMD(PMD_SX, ("cpr_resume: SUSPEND_DEVICES\n"))
		goto rb_suspend_devices;

#if defined(__sparc)
	case C_ST_STATEF_ALLOC:
		ASSERT(sleeptype == CPR_TODISK);
		goto rb_statef_alloc;

	case C_ST_DISABLE_UFS_LOGGING:
		ASSERT(sleeptype == CPR_TODISK);
		goto rb_disable_ufs_logging;
#endif

	case C_ST_PM_REATTACH_NOINVOL:
		PMD(PMD_SX, ("cpr_resume: REATTACH_NOINVOL\n"))
		goto rb_pm_reattach_noinvol;

	case C_ST_STOP_USER_THREADS:
		PMD(PMD_SX, ("cpr_resume: STOP_USER_THREADS\n"))
		goto rb_stop_user_threads;

#if defined(__sparc)
	case C_ST_MP_OFFLINE:
		PMD(PMD_SX, ("cpr_resume: MP_OFFLINE\n"))
		goto rb_mp_offline;
#endif

#if defined(__x86)
	case C_ST_MP_PAUSED:
		PMD(PMD_SX, ("cpr_resume: MP_PAUSED\n"))
		goto rb_mp_paused;
#endif


	default:
		PMD(PMD_SX, ("cpr_resume: others\n"))
		goto rb_others;
	}

rb_all:
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
rb_nodump:
	/*
	 * If we did suspend to RAM, we didn't generate a dump
	 */
	PMD(PMD_SX, ("cpr_resume: CPR DMA callback\n"))
	(void) callb_execute_class(CB_CL_CPR_DMA, CB_CODE_CPR_RESUME);
	if (cpr_suspend_succeeded) {
		PMD(PMD_SX, ("cpr_resume: CPR RPC callback\n"))
		(void) callb_execute_class(CB_CL_CPR_RPC, CB_CODE_CPR_RESUME);
	}

	prom_resume_prepost();
#if !defined(__sparc)
	/*
	 * Need to sync the software clock with the hardware clock.
	 * On Sparc, this occurs in the sparc-specific cbe.  However
	 * on x86 this needs to be handled _before_ we bring other cpu's
	 * back online.  So we call a resume function in timestamp.c
	 */
	if (tsc_resume_in_cyclic == 0)
		tsc_resume();

#endif

#if defined(__sparc)
	if (cpr_suspend_succeeded && (boothowto & RB_DEBUG))
		kdi_dvec_cpr_restart();
#endif


#if defined(__x86)
rb_mp_paused:
	PT(PT_RMPO);
	PMD(PMD_SX, ("resume aux cpus\n"))

	if (cpr_suspend_succeeded) {
		cpr_resume_cpus();
	} else {
		cpr_unpause_cpus();
	}
#endif

	/*
	 * let the tmp callout catch up.
	 */
	PMD(PMD_SX, ("cpr_resume: CPR CALLOUT callback\n"))
	(void) callb_execute_class(CB_CL_CPR_CALLOUT, CB_CODE_CPR_RESUME);

	i_cpr_enable_intr();

	mutex_enter(&cpu_lock);
	PMD(PMD_SX, ("cpr_resume: cyclic resume\n"))
	cyclic_resume();
	mutex_exit(&cpu_lock);

	PMD(PMD_SX, ("cpr_resume: handle xc\n"))
	i_cpr_handle_xc(0);	/* turn it off to allow xc assertion */

	PMD(PMD_SX, ("cpr_resume: CPR POST KERNEL callback\n"))
	(void) callb_execute_class(CB_CL_CPR_POST_KERNEL, CB_CODE_CPR_RESUME);

	/*
	 * statistics gathering
	 */
	if (cpr_suspend_succeeded) {
		/*
		 * Prevent false alarm in tod_validate() due to tod
		 * value change between suspend and resume
		 */
		cpr_tod_status_set(TOD_CPR_RESUME_DONE);

		cpr_convert_promtime(&pwron_tv);

		ctp = &cpr_term.tm_shutdown;
		if (sleeptype == CPR_TODISK)
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
	PMD(PMD_SX, ("cpr_resume: modunload disable\n"))
	modunload_disable();
	PMD(PMD_SX, ("cpr_resume: start kernel threads\n"))
	cpr_start_kernel_threads();

rb_suspend_devices:
	CPR_DEBUG(CPR_DEBUG1, "resuming devices...");
	CPR_STAT_EVENT_START("  start drivers");

	PMD(PMD_SX,
	    ("cpr_resume: rb_suspend_devices: cpr_resume_uniproc = %d\n",
	    cpr_resume_uniproc))

#if defined(__x86)
	/*
	 * If cpr_resume_uniproc is set, then pause all the other cpus
	 * apart from the current cpu, so that broken drivers that think
	 * that they are on a uniprocessor machine will resume
	 */
	if (cpr_resume_uniproc) {
		mutex_enter(&cpu_lock);
		pause_cpus(NULL, NULL);
		mutex_exit(&cpu_lock);
	}
#endif

	/*
	 * The policy here is to continue resume everything we can if we did
	 * not successfully finish suspend; and panic if we are coming back
	 * from a fully suspended system.
	 */
	PMD(PMD_SX, ("cpr_resume: resume devices\n"))
	rc = cpr_resume_devices(ddi_root_node(), 0);

	cpr_sae(0);

	str = "Failed to resume one or more devices.";

	if (rc) {
		if (CPR->c_substate == C_ST_DUMP ||
		    (sleeptype == CPR_TORAM &&
		    CPR->c_substate == C_ST_NODUMP)) {
			if (cpr_test_point == FORCE_SUSPEND_TO_RAM) {
				PMD(PMD_SX, ("cpr_resume: resume device "
				    "warn\n"))
				cpr_err(CE_WARN, str);
			} else {
				PMD(PMD_SX, ("cpr_resume: resume device "
				    "panic\n"))
				cpr_err(CE_PANIC, str);
			}
		} else {
			PMD(PMD_SX, ("cpr_resume: resume device warn\n"))
			cpr_err(CE_WARN, str);
		}
	}

	CPR_STAT_EVENT_END("  start drivers");
	CPR_DEBUG(CPR_DEBUG1, "done\n");

#if defined(__x86)
	/*
	 * If cpr_resume_uniproc is set, then unpause all the processors
	 * that were paused before resuming the drivers
	 */
	if (cpr_resume_uniproc) {
		mutex_enter(&cpu_lock);
		start_cpus();
		mutex_exit(&cpu_lock);
	}
#endif

	/*
	 * If we had disabled modunloading in this cpr resume cycle (i.e. we
	 * resumed from a state earlier than C_ST_SUSPEND_DEVICES), re-enable
	 * modunloading now.
	 */
	if (CPR->c_substate != C_ST_SUSPEND_DEVICES) {
		PMD(PMD_SX, ("cpr_resume: modload enable\n"))
		modunload_enable();
	}

	/*
	 * Hooks needed by lock manager prior to resuming.
	 * Refer to code for more comments.
	 */
	PMD(PMD_SX, ("cpr_resume: lock mgr\n"))
	cpr_lock_mgr(lm_cprresume);

#if defined(__sparc)
	/*
	 * This is a partial (half) resume during cpr suspend, we
	 * haven't yet given up on the suspend. On return from here,
	 * cpr_suspend() will try to reallocate and retry the suspend.
	 */
	if (CPR->c_substate == C_ST_DUMP_NOSPC) {
		return (0);
	}

	if (sleeptype == CPR_TODISK) {
rb_statef_alloc:
		cpr_statef_close();

rb_disable_ufs_logging:
		/*
		 * if ufs logging was disabled, re-enable
		 */
		(void) cpr_ufs_logging(1);
	}
#endif

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
		PMD(PMD_SX, ("cpr_resume: reattach noinvol fini\n"))
		pm_reattach_noinvol_fini();
	}

	PMD(PMD_SX, ("cpr_resume: CPR POST USER callback\n"))
	(void) callb_execute_class(CB_CL_CPR_POST_USER, CB_CODE_CPR_RESUME);
	PMD(PMD_SX, ("cpr_resume: CPR PROMPRINTF callback\n"))
	(void) callb_execute_class(CB_CL_CPR_PROMPRINTF, CB_CODE_CPR_RESUME);

	PMD(PMD_SX, ("cpr_resume: restore direct levels\n"))
	pm_restore_direct_levels();

rb_stop_user_threads:
	CPR_DEBUG(CPR_DEBUG1, "starting user threads...");
	PMD(PMD_SX, ("cpr_resume: starting user threads\n"))
	cpr_start_user_threads();
	CPR_DEBUG(CPR_DEBUG1, "done\n");
	/*
	 * Ask Xorg to resume the frame buffer, and wait for it to happen
	 */
	mutex_enter(&srn_clone_lock);
	if (srn_signal) {
		PMD(PMD_SX, ("cpr_suspend: (*srn_signal)(..., "
		    "SRN_NORMAL_RESUME)\n"))
		srn_inuse = 1;		/* because (*srn_signal) cv_waits */
		(*srn_signal)(SRN_TYPE_APM, SRN_NORMAL_RESUME);
		srn_inuse = 0;
	} else {
		PMD(PMD_SX, ("cpr_suspend: srn_signal NULL\n"))
	}
	mutex_exit(&srn_clone_lock);

#if defined(__sparc)
rb_mp_offline:
	if (cpr_mp_online())
		cpr_err(CE_WARN, "Failed to online all the processors.");
#endif

rb_others:
	PMD(PMD_SX, ("cpr_resume: dep thread\n"))
	pm_dispatch_to_dep_thread(PM_DEP_WK_CPR_RESUME, NULL, NULL,
	    PM_DEP_WAIT, NULL, 0);

	PMD(PMD_SX, ("cpr_resume: CPR PM callback\n"))
	(void) callb_execute_class(CB_CL_CPR_PM, CB_CODE_CPR_RESUME);

	if (cpr_suspend_succeeded) {
		cpr_stat_record_events();
	}

#if defined(__sparc)
	if (sleeptype == CPR_TODISK && !cpr_reusable_mode)
		cpr_clear_definfo();
#endif

	i_cpr_free_cpus();
	CPR_DEBUG(CPR_DEBUG1, "Sending SIGTHAW...");
	PMD(PMD_SX, ("cpr_resume: SIGTHAW\n"))
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

	PMD(PMD_SX, ("cpr_resume returns %x\n", rc))
	return (rc);
}

static void
cpr_suspend_init(int sleeptype)
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

	if (sleeptype == CPR_TODISK) {
		/*
		 * Lookup the physical address of our thread structure.
		 * This should never be invalid and the entire thread structure
		 * is expected to reside within the same pfn.
		 */
		curthreadpfn = hat_getpfnum(kas.a_hat, (caddr_t)curthread);
		ASSERT(curthreadpfn != PFN_INVALID);
		ASSERT(curthreadpfn == hat_getpfnum(kas.a_hat,
		    (caddr_t)curthread + sizeof (kthread_t) - 1));
	}

	cpr_suspend_succeeded = 0;
}

/*
 * bring all the offline cpus online
 */
static int
cpr_all_online(void)
{
	int	rc = 0;

#ifdef	__sparc
	/*
	 * do nothing
	 */
#else

	cpu_t	*cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_list;
	do {
		cp->cpu_cpr_flags &= ~CPU_CPR_ONLINE;
		if (!CPU_ACTIVE(cp)) {
			if ((rc = cpu_online(cp)) != 0)
				break;
			CPU_SET_CPR_FLAGS(cp, CPU_CPR_ONLINE);
		}
	} while ((cp = cp->cpu_next) != cpu_list);

	if (rc) {
		/*
		 * an online operation failed so offline the cpus
		 * that were onlined above to restore the system
		 * to its original state
		 */
		cpr_restore_offline();
	}
#endif
	return (rc);
}

/*
 * offline all the cpus that were brought online by cpr_all_online()
 */
static void
cpr_restore_offline(void)
{

#ifdef	__sparc
	/*
	 * do nothing
	 */
#else

	cpu_t	*cp;
	int	rc = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_list;
	do {
		if (CPU_CPR_IS_ONLINE(cp)) {
			rc =  cpu_offline(cp, 0);
			/*
			 * this offline should work, since the cpu was
			 * offline originally and was successfully onlined
			 * by cpr_all_online()
			 */
			ASSERT(rc == 0);
			cp->cpu_cpr_flags &= ~CPU_CPR_ONLINE;
		}
	} while ((cp = cp->cpu_next) != cpu_list);

#endif

}
