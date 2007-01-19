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

extern int i_cpr_is_supported(void);
extern int cpr_is_ufs(struct vfs *);
extern int cpr_check_spec_statefile(void);
extern int cpr_reusable_mount_check(void);
extern void cpr_forget_cprconfig(void);
extern int i_cpr_reusable_supported(void);
extern int i_cpr_reusefini(void);

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "checkpoint resume"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

char _depends_on[] = "misc/bootdev";	/* i_devname_to_promname() */

int cpr_reusable_mode;

kmutex_t	cpr_slock;	/* cpr serial lock */
cpr_t		cpr_state;
int		cpr_debug;
int		cpr_test_mode; /* true if called via uadmin testmode */

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

int
cpr(int fcn)
{
	static const char noswapstr[] = "reusable statefile requires "
	    "that no swap area be configured.\n";
	static const char blockstr[] = "reusable statefile must be "
	    "a block device.  See power.conf(4) and pmconfig(1M).\n";
	static const char normalfmt[] = "cannot run normal "
	    "checkpoint/resume when in reusable statefile mode. "
	    "use uadmin A_FREEZE AD_REUSEFINI (uadmin %d %d) "
	    "to exit reusable statefile mode.\n";
	static const char modefmt[] = "%s in reusable mode.\n";
	register int rc = 0;
	extern int cpr_init(int);
	extern void cpr_done(void);

	/*
	 * Need to know if we're in reusable mode, but we will likely have
	 * rebooted since REUSEINIT, so we have to get the info from the
	 * file system
	 */
	if (!cpr_reusable_mode)
		cpr_reusable_mode = cpr_get_reusable_mode();

	cpr_forget_cprconfig();
	switch (fcn) {

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
		if (!i_cpr_is_supported() || cpr_reusable_mode)
			return (ENOTSUP);
		return (0);

	case AD_CPR_PRINT:
		CPR_STAT_EVENT_END("POST CPR DELAY");
		cpr_stat_event_print();
		return (0);

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

	default:
		return (ENOTSUP);
	}

	if (!i_cpr_is_supported() || !cpr_is_ufs(rootvfs))
		return (ENOTSUP);

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

	/*
	 * acquire cpr serial lock and init cpr state structure.
	 */
	if (rc = cpr_init(fcn))
		return (rc);

	if (fcn == AD_CPR_REUSABLE) {
		if ((rc = i_cpr_check_cprinfo()) != 0)  {
			mutex_exit(&cpr_slock);
			return (rc);
		}
	}

	/*
	 * Call the main cpr routine. If we are successful, we will be coming
	 * down from the resume side, otherwise we are still in suspend.
	 */
	cpr_err(CE_CONT, "System is being suspended");
	if (rc = cpr_main()) {
		CPR->c_flags |= C_ERROR;
		cpr_err(CE_NOTE, "Suspend operation failed.");
	} else if (CPR->c_flags & C_SUSPENDING) {
		extern void cpr_power_down();
		/*
		 * Back from a successful checkpoint
		 */
		if (fcn == AD_CPR_TESTZ || fcn == AD_CPR_TESTNOZ) {
			mdboot(0, AD_BOOT, "", B_FALSE);
			/* NOTREACHED */
		}

		/* make sure there are no more changes to the device tree */
		devtree_freeze();

		/*
		 * stop other cpus and raise our priority.  since there is only
		 * one active cpu after this, and our priority will be too high
		 * for us to be preempted, we're essentially single threaded
		 * from here on out.
		 */
		stop_other_cpus();
		(void) spl6();

		/*
		 * try and reset leaf devices.  reset_leaves() should only
		 * be called when there are no other threads that could be
		 * accessing devices
		 */
		reset_leaves();

		/*
		 * If cpr_power_down() succeeds, it'll not return.
		 *
		 * Drives with write-cache enabled need to flush
		 * their cache.
		 */
		if (fcn != AD_CPR_TESTHALT)
			cpr_power_down();

		CPR_DEBUG(CPR_DEBUG1, "(Done. Please Switch Off)\n");
		halt(NULL);
		/* NOTREACHED */
	}
	/*
	 * For resuming: release resources and the serial lock.
	 */
	cpr_done();
	return (rc);
}
