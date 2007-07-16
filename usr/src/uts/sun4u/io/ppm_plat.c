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
 * Platform Power Management master pseudo driver platform support.
 */

#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ppmvar.h>

/*
 * This flag disables vcore/vid feature by default.
 */
uint_t	ppm_do_vcore = 0;

/*
 * PPMDC_CPU_NEXT operation
 */
static int
ppm_cpu_next(ppm_domain_t *domp, int level)
{
#ifdef DEBUG
	char *str = "ppm_cpu_next";
#endif
	ppm_dc_t *dc;
	int index = level - 1;
	int ret = 0;

	dc = ppm_lookup_dc(domp, PPMDC_CPU_NEXT);
	for (; dc && (dc->cmd == PPMDC_CPU_NEXT); dc = dc->next) {
		switch (dc->method) {
		case PPMDC_CPUSPEEDKIO:
			ret = ldi_ioctl(dc->lh, dc->m_un.cpu.iowr,
			    (intptr_t)index, FWRITE | FKIOCTL, kcred, NULL);
			if (ret)
				return (ret);
			break;

		default:
			PPMD(D_CPU, ("%s: unsupported method(0x%x)\n",
			    str, dc->method))
			return (-1);
		}
	}
	return (ret);
}

/*
 * PPMDC_PRE_CHNG operation
 */
static int
ppm_cpu_pre_chng(ppm_domain_t *domp, int oldl, int speedup)
{
#ifdef DEBUG
	char *str = "ppm_cpu_pre_chng";
#endif
	ppm_dc_t *dc;
	int lowest;
	int ret = 0;

	dc = ppm_lookup_dc(domp, PPMDC_PRE_CHNG);
	for (; dc && (dc->cmd == PPMDC_PRE_CHNG); dc = dc->next) {

		switch (dc->method) {
		case PPMDC_VCORE:
			lowest = domp->devlist->lowest;
			if ((oldl != lowest) || (speedup != 1))
				break;

			/* raise core voltage */
			if (ppm_do_vcore > 0) {
				ret = ldi_ioctl(dc->lh,
				    dc->m_un.cpu.iowr,
				    (intptr_t)&dc->m_un.cpu.val,
				    FWRITE | FKIOCTL, kcred, NULL);
				if (ret != 0)
					return (ret);
				if (dc->m_un.cpu.delay > 0)
					drv_usecwait(dc->m_un.cpu.delay);
			}
			break;

		default:
			PPMD(D_CPU, ("%s: unsupported method(0x%x)\n",
			    str, dc->method))
			return (-1);
		}
	}

	return (ret);
}

/*
 * PPMDC_CPU_GO operation
 */
/* ARGSUSED */
static int
ppm_cpu_go(ppm_domain_t *domp, int level)
{
	ppm_dc_t *dc;
	int ret = 0;

	dc = ppm_lookup_dc(domp, PPMDC_CPU_GO);
	if (dc == NULL) {
		return (ret);
	}
	switch (dc->method) {
	case PPMDC_KIO:
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)dc->m_un.kio.val, FWRITE | FKIOCTL,
		    kcred, NULL);
		break;
	default:
		return (-1);
	}

	return (ret);
}

/*
 * PPMDC_POST_CHNG operation
 */
static int
ppm_cpu_post_chng(ppm_domain_t *domp, int newl, int speedup)
{
#ifdef DEBUG
	char *str = "ppm_cpu_post_chng";
#endif
	ppm_dc_t *dc;
	int	lowest;
	int ret = 0;

	dc = ppm_lookup_dc(domp, PPMDC_POST_CHNG);
	for (; dc && (dc->cmd == PPMDC_POST_CHNG); dc = dc->next) {

		switch (dc->method) {
		case PPMDC_VCORE:
			lowest = domp->devlist->lowest;
			if ((newl != lowest) || (speedup != 0))
				break;

			/* lower core voltage */
			if (ppm_do_vcore > 0) {
				ret = ldi_ioctl(dc->lh,
				    dc->m_un.cpu.iowr,
				    (intptr_t)&dc->m_un.cpu.val,
				    FWRITE | FKIOCTL, kcred, NULL);
				if (ret != 0)
					return (ret);
				if (dc->m_un.cpu.delay > 0)
					drv_usecwait(dc->m_un.cpu.delay);
			}
			break;

		default:
			PPMD(D_CPU, ("%s: unsupported method(0x%x)\n",
			    str, dc->method))
			return (-1);
		}
	}
	return (ret);
}

/*
 * The effective cpu estar model is: program all cpus to be ready to go
 * the same next(or new) speed level, program all other system bus resident
 * devices to the same next speed level.  At last, pull the trigger to
 * initiate the speed change for all system bus resident devices
 * simultaneously.
 *
 * On Excalibur, the Safari bus resident devices are Cheetah/Cheetah+ and
 * Schizo.  On Enchilada, the JBus resident devides are Jalapeno(s) and
 * Tomatillo(s).
 */
int
ppm_change_cpu_power(ppm_dev_t *ppmd, int newlevel)
{
#ifdef DEBUG
	char *str = "ppm_change_cpu_power";
#endif
	ppm_unit_t *unitp;
	ppm_domain_t *domp;
	ppm_dev_t *cpup;
	dev_info_t *dip;
	int level, oldlevel;
	int speedup, incr, lowest, highest;
	char *chstr;
	int ret;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	ASSERT(unitp);
	domp = ppmd->domp;
	cpup = domp->devlist;
	lowest = cpup->lowest;
	highest = cpup->highest;

	/*
	 * Not all cpus may have transitioned to a known level by this time
	 */
	oldlevel = (cpup->level == PM_LEVEL_UNKNOWN) ? highest : cpup->level;
	dip = cpup->dip;
	ASSERT(dip);

	PPMD(D_CPU, ("%s: old %d, new %d, highest %d, lowest %d\n",
	    str, oldlevel, newlevel, highest, lowest))

	if (newlevel > oldlevel) {
		chstr = "UP";
		speedup = 1;
		incr = 1;
	} else if (newlevel < oldlevel) {
		chstr = "DOWN";
		speedup = 0;
		incr = -1;
	} else
		return (DDI_SUCCESS);

	/*
	 * This loop will execute 1x or 2x depending on
	 * number of times we need to change clock rates
	 */
	for (level = oldlevel+incr; level != newlevel+incr; level += incr) {
		/* bring each cpu to next level */
		for (; cpup; cpup = cpup->next) {
			if (cpup->level == level)
				continue;

			ret = pm_power(cpup->dip, 0, level);
			PPMD(D_CPU, ("%s: \"%s\", %s to level %d, ret %d\n",
			    str, cpup->path, chstr, level, ret))
			if (ret == DDI_SUCCESS) {
				cpup->level = level;
				cpup->rplvl = PM_LEVEL_UNKNOWN;
				continue;
			}

			/*
			 * if the driver was unable to lower cpu speed,
			 * the cpu probably got busy; set the previous
			 * cpus back to the original level
			 */
			if (speedup == 0)
				ret = ppm_revert_cpu_power(cpup, level - incr);
			return (ret);
		}
		cpup = domp->devlist;

		/*
		 * set bus resident devices at next speed level
		 */
		ret = ppm_cpu_next(domp, level);
		if (ret != 0) {
			(void) ppm_revert_cpu_power(cpup, level - incr);
			return (ret);
		}

		/*
		 * platform dependent various operations before
		 * initiating cpu speed change
		 */
		ret = ppm_cpu_pre_chng(domp, level - incr, speedup);
		if (ret != 0) {
			(void) ppm_revert_cpu_power(cpup, level - incr);
			(void) ppm_cpu_next(domp, level - incr);
			return (ret);
		}

		/*
		 * the following 1us delay is actually required for us3i only.
		 * on us3i system, entering estar mode from full requires
		 * to set mcu to single fsm state followed by 1us delay
		 * before trigger actual transition.  The mcu part is
		 * handled in us_drv, the delay is here.
		 */
		if ((oldlevel == highest) && (speedup == 0))
			drv_usecwait(1);

		/*
		 * initiate cpu speed change
		 */
		ret = ppm_cpu_go(domp, level);
		if (ret != 0) {
			(void) ppm_revert_cpu_power(cpup, level - incr);
			(void) ppm_cpu_next(domp, level - incr);
			return (ret);
		}

		/*
		 * platform dependent operations post cpu speed change
		 */
		ret = ppm_cpu_post_chng(domp, level, speedup);
		if (ret != 0)
			return (ret);

	}   /* end of looping each level */

	return (DDI_SUCCESS);
}

/*
 * This handles the power-on case where cpu power level is
 * PM_LEVEL_UNKNOWN.  Per agreement with OBP, cpus always
 * boot up at full speed.  In fact, we must not making calls
 * into tomtppm or schppm to trigger cpu speed change to a
 * different level at early boot time since some cpu may not
 * be ready, causing xc_one() to fail silently.
 *
 * Here we simply call pm_power() to get the power level updated
 * in pm and ppm. Had xc_one() failed silently inside us_power()
 * at this time we're unaffected.
 */
boolean_t
ppm_manage_early_cpus(dev_info_t *dip, int new, int *result)
{
	ppm_dev_t *ppmd = PPM_GET_PRIVATE(dip);
	int ret;

	if (ppmd->level == PM_LEVEL_UNKNOWN && new == ppmd->highest) {
		ret = pm_power(dip, 0, new);
		if (ret != DDI_SUCCESS) {
			PPMD(D_CPU, ("ppm_manage_early_cpus: pm_power() "
			    "failed to change power level to %d", new))
		} else {
			ppmd->level = new;
			ppmd->rplvl = PM_LEVEL_UNKNOWN;
		}
		*result = ret;
		return (B_TRUE);
	}
	return (B_FALSE);
}
