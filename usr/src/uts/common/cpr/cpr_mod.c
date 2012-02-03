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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * System call to checkpoint and resume the currently running kernel
 */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/cred.h>
#include <sys/uadmin.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/cpr.h>
#include <sys/swap.h>
#include <sys/vfs.h>
#include <sys/autoconf.h>
#include <sys/machsystm.h>

extern int i_cpr_is_supported(int sleeptype);
extern int cpr_is_ufs(struct vfs *);
extern int cpr_is_zfs(struct vfs *);
extern int cpr_check_spec_statefile(void);
extern int cpr_reusable_mount_check(void);
extern int i_cpr_reusable_supported(void);
extern int i_cpr_reusefini(void);
extern struct mod_ops mod_miscops;

extern int cpr_init(int);
extern void cpr_done(void);
extern void i_cpr_stop_other_cpus(void);
extern int i_cpr_power_down(int);

#if defined(__sparc)
extern void cpr_forget_cprconfig(void);
#endif

static struct modlmisc modlmisc = {
	&mod_miscops, "checkpoint resume"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int cpr_reusable_mode;

kmutex_t	cpr_slock;	/* cpr serial lock */
cpr_t		cpr_state;
int		cpr_debug;
int		cpr_test_mode; /* true if called via uadmin testmode */
int		cpr_test_point = LOOP_BACK_NONE;	/* cpr test point */
int		cpr_mp_enable = 0;	/* set to 1 to enable MP suspend */
major_t		cpr_device = 0;		/* major number for S3 on one device */

/*
 * All the loadable module related code follows
 */
int
_init(void)
{
	register int e;

	if ((e = mod_install(&modlinkage)) == 0) {
		mutex_init(&cpr_slock, NULL, MUTEX_DEFAULT, NULL);
	}
	return (e);
}

int
_fini(void)
{
	register int e;

	if ((e = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&cpr_slock);
	}
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static
int
atoi(char *p)
{
	int	i;

	i = (*p++ - '0');

	while (*p != '\0')
		i = 10 * i + (*p++ - '0');

	return (i);
}

int
cpr(int fcn, void *mdep)
{

#if defined(__sparc)
	static const char noswapstr[] = "reusable statefile requires "
	    "that no swap area be configured.\n";
	static const char blockstr[] = "reusable statefile must be "
	    "a block device.  See power.conf(4) and pmconfig(1M).\n";
	static const char normalfmt[] = "cannot run normal "
	    "checkpoint/resume when in reusable statefile mode. "
	    "use uadmin A_FREEZE AD_REUSEFINI (uadmin %d %d) "
	    "to exit reusable statefile mode.\n";
	static const char modefmt[] = "%s in reusable mode.\n";
#endif
	register int rc = 0;
	int cpr_sleeptype;

	/*
	 * First, reject commands that we don't (yet) support on this arch.
	 * This is easier to understand broken out like this than grotting
	 * through the second switch below.
	 */

	switch (fcn) {
#if defined(__sparc)
	case AD_CHECK_SUSPEND_TO_RAM:
	case AD_SUSPEND_TO_RAM:
		return (ENOTSUP);
	case AD_CHECK_SUSPEND_TO_DISK:
	case AD_SUSPEND_TO_DISK:
	case AD_CPR_REUSEINIT:
	case AD_CPR_NOCOMPRESS:
	case AD_CPR_FORCE:
	case AD_CPR_REUSABLE:
	case AD_CPR_REUSEFINI:
	case AD_CPR_TESTZ:
	case AD_CPR_TESTNOZ:
	case AD_CPR_TESTHALT:
	case AD_CPR_SUSP_DEVICES:
		cpr_sleeptype = CPR_TODISK;
		break;
#endif
#if defined(__x86)
	case AD_CHECK_SUSPEND_TO_DISK:
	case AD_SUSPEND_TO_DISK:
	case AD_CPR_REUSEINIT:
	case AD_CPR_NOCOMPRESS:
	case AD_CPR_FORCE:
	case AD_CPR_REUSABLE:
	case AD_CPR_REUSEFINI:
	case AD_CPR_TESTZ:
	case AD_CPR_TESTNOZ:
	case AD_CPR_TESTHALT:
	case AD_CPR_PRINT:
		return (ENOTSUP);
	/* The DEV_* values need to be removed after sys-syspend is fixed */
	case DEV_CHECK_SUSPEND_TO_RAM:
	case DEV_SUSPEND_TO_RAM:
	case AD_CPR_SUSP_DEVICES:
	case AD_CHECK_SUSPEND_TO_RAM:
	case AD_SUSPEND_TO_RAM:
	case AD_LOOPBACK_SUSPEND_TO_RAM_PASS:
	case AD_LOOPBACK_SUSPEND_TO_RAM_FAIL:
	case AD_FORCE_SUSPEND_TO_RAM:
	case AD_DEVICE_SUSPEND_TO_RAM:
		cpr_sleeptype = CPR_TORAM;
		break;
#endif
	}
#if defined(__sparc)
	/*
	 * Need to know if we're in reusable mode, but we will likely have
	 * rebooted since REUSEINIT, so we have to get the info from the
	 * file system
	 */
	if (!cpr_reusable_mode)
		cpr_reusable_mode = cpr_get_reusable_mode();

	cpr_forget_cprconfig();
#endif

	switch (fcn) {

#if defined(__sparc)
	case AD_CPR_REUSEINIT:
		if (!i_cpr_reusable_supported())
			return (ENOTSUP);
		if (!cpr_statefile_is_spec()) {
			cpr_err(CE_CONT, blockstr);
			return (EINVAL);
		}
		if ((rc = cpr_check_spec_statefile()) != 0)
			return (rc);
		if (swapinfo) {
			cpr_err(CE_CONT, noswapstr);
			return (EINVAL);
		}
		cpr_test_mode = 0;
		break;

	case AD_CPR_NOCOMPRESS:
	case AD_CPR_COMPRESS:
	case AD_CPR_FORCE:
		if (cpr_reusable_mode) {
			cpr_err(CE_CONT, normalfmt, A_FREEZE, AD_REUSEFINI);
			return (ENOTSUP);
		}
		cpr_test_mode = 0;
		break;

	case AD_CPR_REUSABLE:
		if (!i_cpr_reusable_supported())
			return (ENOTSUP);
		if (!cpr_statefile_is_spec()) {
			cpr_err(CE_CONT, blockstr);
			return (EINVAL);
		}
		if ((rc = cpr_check_spec_statefile()) != 0)
			return (rc);
		if (swapinfo) {
			cpr_err(CE_CONT, noswapstr);
			return (EINVAL);
		}
		if ((rc = cpr_reusable_mount_check()) != 0)
			return (rc);
		cpr_test_mode = 0;
		break;

	case AD_CPR_REUSEFINI:
		if (!i_cpr_reusable_supported())
			return (ENOTSUP);
		cpr_test_mode = 0;
		break;

	case AD_CPR_TESTZ:
	case AD_CPR_TESTNOZ:
	case AD_CPR_TESTHALT:
		if (cpr_reusable_mode) {
			cpr_err(CE_CONT, normalfmt, A_FREEZE, AD_REUSEFINI);
			return (ENOTSUP);
		}
		cpr_test_mode = 1;
		break;

	case AD_CPR_CHECK:
		if (!i_cpr_is_supported(cpr_sleeptype) || cpr_reusable_mode)
			return (ENOTSUP);
		return (0);

	case AD_CPR_PRINT:
		CPR_STAT_EVENT_END("POST CPR DELAY");
		cpr_stat_event_print();
		return (0);
#endif

	case AD_CPR_DEBUG0:
		cpr_debug = 0;
		return (0);

	case AD_CPR_DEBUG1:
	case AD_CPR_DEBUG2:
	case AD_CPR_DEBUG3:
	case AD_CPR_DEBUG4:
	case AD_CPR_DEBUG5:
	case AD_CPR_DEBUG7:
	case AD_CPR_DEBUG8:
		cpr_debug |= CPR_DEBUG_BIT(fcn);
		return (0);

	case AD_CPR_DEBUG9:
		cpr_debug |= CPR_DEBUG6;
		return (0);

	/* The DEV_* values need to be removed after sys-syspend is fixed */
	case DEV_CHECK_SUSPEND_TO_RAM:
	case DEV_SUSPEND_TO_RAM:
	case AD_CHECK_SUSPEND_TO_RAM:
	case AD_SUSPEND_TO_RAM:
		cpr_test_point = LOOP_BACK_NONE;
		break;

	case AD_LOOPBACK_SUSPEND_TO_RAM_PASS:
		cpr_test_point = LOOP_BACK_PASS;
		break;

	case AD_LOOPBACK_SUSPEND_TO_RAM_FAIL:
		cpr_test_point = LOOP_BACK_FAIL;
		break;

	case AD_FORCE_SUSPEND_TO_RAM:
		cpr_test_point = FORCE_SUSPEND_TO_RAM;
		break;

	case AD_DEVICE_SUSPEND_TO_RAM:
		if (mdep == NULL) {
			/* Didn't pass enough arguments */
			return (EINVAL);
		}
		cpr_test_point = DEVICE_SUSPEND_TO_RAM;
		cpr_device = (major_t)atoi((char *)mdep);
		break;

	case AD_CPR_SUSP_DEVICES:
		cpr_test_point = FORCE_SUSPEND_TO_RAM;
		if (cpr_suspend_devices(ddi_root_node()) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "Some devices did not suspend "
			    "and may be unusable");
		(void) cpr_resume_devices(ddi_root_node(), 0);
		return (0);

	default:
		return (ENOTSUP);
	}

	if (!i_cpr_is_supported(cpr_sleeptype))
		return (ENOTSUP);

#if defined(__sparc)
	if ((cpr_sleeptype == CPR_TODISK &&
	    !cpr_is_ufs(rootvfs) && !cpr_is_zfs(rootvfs)))
		return (ENOTSUP);
#endif

	if (fcn == AD_CHECK_SUSPEND_TO_RAM ||
	    fcn == DEV_CHECK_SUSPEND_TO_RAM) {
		ASSERT(i_cpr_is_supported(cpr_sleeptype));
		return (0);
	}

#if defined(__sparc)
	if (fcn == AD_CPR_REUSEINIT) {
		if (mutex_tryenter(&cpr_slock) == 0)
			return (EBUSY);
		if (cpr_reusable_mode) {
			cpr_err(CE_CONT, modefmt, "already");
			mutex_exit(&cpr_slock);
			return (EBUSY);
		}
		rc = i_cpr_reuseinit();
		mutex_exit(&cpr_slock);
		return (rc);
	}

	if (fcn == AD_CPR_REUSEFINI) {
		if (mutex_tryenter(&cpr_slock) == 0)
			return (EBUSY);
		if (!cpr_reusable_mode) {
			cpr_err(CE_CONT, modefmt, "not");
			mutex_exit(&cpr_slock);
			return (EINVAL);
		}
		rc = i_cpr_reusefini();
		mutex_exit(&cpr_slock);
		return (rc);
	}
#endif

	/*
	 * acquire cpr serial lock and init cpr state structure.
	 */
	if (rc = cpr_init(fcn))
		return (rc);

#if defined(__sparc)
	if (fcn == AD_CPR_REUSABLE) {
		if ((rc = i_cpr_check_cprinfo()) != 0)  {
			mutex_exit(&cpr_slock);
			return (rc);
		}
	}
#endif

	/*
	 * Call the main cpr routine. If we are successful, we will be coming
	 * down from the resume side, otherwise we are still in suspend.
	 */
	cpr_err(CE_CONT, "System is being suspended");
	if (rc = cpr_main(cpr_sleeptype)) {
		CPR->c_flags |= C_ERROR;
		PMD(PMD_SX, ("cpr: Suspend operation failed.\n"))
		cpr_err(CE_NOTE, "Suspend operation failed.");
	} else if (CPR->c_flags & C_SUSPENDING) {

		/*
		 * In the suspend to RAM case, by the time we get
		 * control back we're already resumed
		 */
		if (cpr_sleeptype == CPR_TORAM) {
			PMD(PMD_SX, ("cpr: cpr CPR_TORAM done\n"))
			cpr_done();
			return (rc);
		}

#if defined(__sparc)

		PMD(PMD_SX, ("cpr: Suspend operation succeeded.\n"))
		/*
		 * Back from a successful checkpoint
		 */
		if (fcn == AD_CPR_TESTZ || fcn == AD_CPR_TESTNOZ) {
			mdboot(0, AD_BOOT, "", B_FALSE);
			/* NOTREACHED */
		}

		/* make sure there are no more changes to the device tree */
		PMD(PMD_SX, ("cpr: dev tree freeze\n"))
		devtree_freeze();

		/*
		 * stop other cpus and raise our priority.  since there is only
		 * one active cpu after this, and our priority will be too high
		 * for us to be preempted, we're essentially single threaded
		 * from here on out.
		 */
		PMD(PMD_SX, ("cpr: stop other cpus\n"))
		i_cpr_stop_other_cpus();
		PMD(PMD_SX, ("cpr: spl6\n"))
		(void) spl6();

		/*
		 * try and reset leaf devices.  reset_leaves() should only
		 * be called when there are no other threads that could be
		 * accessing devices
		 */
		PMD(PMD_SX, ("cpr: reset leaves\n"))
		reset_leaves();

		/*
		 * If i_cpr_power_down() succeeds, it'll not return
		 *
		 * Drives with write-cache enabled need to flush
		 * their cache.
		 */
		if (fcn != AD_CPR_TESTHALT) {
			PMD(PMD_SX, ("cpr: power down\n"))
			(void) i_cpr_power_down(cpr_sleeptype);
		}
		ASSERT(cpr_sleeptype == CPR_TODISK);
		/* currently CPR_TODISK comes back via a boot path */
		CPR_DEBUG(CPR_DEBUG1, "(Done. Please Switch Off)\n");
		halt(NULL);
		/* NOTREACHED */
#endif
	}
	PMD(PMD_SX, ("cpr: cpr done\n"))
	cpr_done();
	return (rc);
}
