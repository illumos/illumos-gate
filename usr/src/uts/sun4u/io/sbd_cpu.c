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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * CPU support routines for DR
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/mem_config.h>
#include <sys/promif.h>
#include <sys/x_call.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/membar.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/spitregs.h>

#include <sys/archsystm.h>
#include <vm/hat_sfmmu.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/x_call.h>
#include <sys/cpu_module.h>
#include <sys/cheetahregs.h>

#include <sys/autoconf.h>
#include <sys/cmn_err.h>

#include <sys/sbdpriv.h>

void
sbd_cpu_set_prop(sbd_cpu_unit_t *cp, dev_info_t *dip)
{
	uint32_t	clock_freq;
	int		ecache_size = 0;
	char		*cache_str = NULL;

	/* read in the CPU speed */
	clock_freq = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "clock-frequency", 0);

	ASSERT(clock_freq != 0);

	/*
	 * The ecache property string is not the same
	 * for all CPU implementations.
	 */
	switch (cp->sbc_cpu_impl) {
	case CHEETAH_IMPL:
	case CHEETAH_PLUS_IMPL:
		cache_str = "ecache-size";
		break;
	case JAGUAR_IMPL:
		cache_str = "l2-cache-size";
		break;
	case PANTHER_IMPL:
		cache_str = "l3-cache-size";
		break;
	default:
		cmn_err(CE_WARN, "cpu implementation type "
		    "is an unknown %d value", cp->sbc_cpu_impl);
		ASSERT(0);
		break;
	}

	if (cache_str != NULL) {
		/* read in the ecache size */
		ecache_size = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, cache_str, 0);
	}

	/*
	 * In the case the size is still 0,
	 * a zero value will be displayed running non-debug.
	 */
	ASSERT(ecache_size != 0);

	/* convert to the proper units */
	cp->sbc_speed = (clock_freq + 500000) / 1000000;
	cp->sbc_ecache = ecache_size / (1024 * 1024);
}

static void
sbd_fill_cpu_stat(sbd_cpu_unit_t *cp, dev_info_t *dip, sbd_cpu_stat_t *csp)
{
	int		namelen;

	bzero((caddr_t)csp, sizeof (*csp));
	csp->cs_type = cp->sbc_cm.sbdev_type;
	csp->cs_unit = cp->sbc_cm.sbdev_unum;
	namelen = sizeof (csp->cs_name);
	(void) ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_DEVICETYPE, (caddr_t)csp->cs_name, &namelen);
	csp->cs_busy = cp->sbc_cm.sbdev_busy;
	csp->cs_time = cp->sbc_cm.sbdev_time;
	csp->cs_ostate = cp->sbc_cm.sbdev_ostate;
	csp->cs_cpuid = cp->sbc_cpu_id;
	csp->cs_suspend = 0;

	/*
	 * If we have marked the cpu's condition previously
	 * then don't rewrite it
	 */
	if (csp->cs_cond != SBD_COND_UNUSABLE)
		csp->cs_cond = sbd_get_comp_cond(dip);

	/*
	 * If the speed and ecache properties have not been
	 * cached yet, read them in from the device tree.
	 */
	if ((cp->sbc_speed == 0) || (cp->sbc_ecache == 0))
		sbd_cpu_set_prop(cp, dip);

	/* use the cached speed and ecache values */
	csp->cs_speed = cp->sbc_speed;
	csp->cs_ecache = cp->sbc_ecache;
}

static void
sbd_fill_cmp_stat(sbd_cpu_stat_t *csp, int ncores, int impl,
    sbd_cmp_stat_t *psp)
{
	int	core;

	ASSERT(csp && psp && (ncores >= 1));

	bzero((caddr_t)psp, sizeof (*psp));

	/*
	 * Fill in the common status information based
	 * on the data for the first core.
	 */
	psp->ps_type = SBD_COMP_CMP;
	psp->ps_unit = SBD_CMP_NUM(csp->cs_unit);
	(void) strncpy(psp->ps_name, csp->cs_name, sizeof (psp->ps_name));
	psp->ps_cond = csp->cs_cond;
	psp->ps_busy = csp->cs_busy;
	psp->ps_time = csp->cs_time;
	psp->ps_ostate = csp->cs_ostate;
	psp->ps_suspend = csp->cs_suspend;

	/* CMP specific status data */
	*psp->ps_cpuid = csp->cs_cpuid;
	psp->ps_ncores = 1;
	psp->ps_speed = csp->cs_speed;
	psp->ps_ecache = csp->cs_ecache;

	/*
	 * Walk through the data for the remaining cores.
	 * Make any adjustments to the common status data,
	 * or the shared CMP specific data if necessary.
	 */
	for (core = 1; core < ncores; core++) {

		/*
		 * The following properties should be the same
		 * for all the cores of the CMP.
		 */
		ASSERT(psp->ps_unit == SBD_CMP_NUM(csp[core].cs_unit));
		ASSERT(psp->ps_speed == csp[core].cs_speed);

		psp->ps_cpuid[core] = csp[core].cs_cpuid;
		psp->ps_ncores++;

		/*
		 * Jaguar has a split ecache, so the ecache
		 * for each core must be added together to
		 * get the total ecache for the whole chip.
		 */
		if (IS_JAGUAR(impl)) {
			psp->ps_ecache += csp[core].cs_ecache;
		}

		/* adjust time if necessary */
		if (csp[core].cs_time > psp->ps_time) {
			psp->ps_time = csp[core].cs_time;
		}

		psp->ps_busy |= csp[core].cs_busy;

		/*
		 * If any of the cores are configured, the
		 * entire CMP is marked as configured.
		 */
		if (csp[core].cs_ostate == SBD_STAT_CONFIGURED) {
			psp->ps_ostate = csp[core].cs_ostate;
		}
	}
}

int
sbd_cpu_flags(sbd_handle_t *hp, sbd_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		cmp;
	int		ncpu;
	sbd_board_t	*sbp;
	sbdp_handle_t	*hdp;
	sbd_cpu_stat_t	cstat[MAX_CORES_PER_CMP];

	sbp = SBDH2BD(hp->h_sbd);
	hdp = sbd_get_sbdp_handle(sbp, hp);

	/*
	 * Grab the status lock before accessing the dip as we allow
	 * concurrent status and branch unconfigure and disconnect.
	 *
	 * The disconnect thread clears the present devset first
	 * and then destroys dips. It is possible that the status
	 * thread checks the present devset before they are cleared
	 * but accesses the dip after they are destroyed causing a
	 * panic. To prevent this, the status thread should check
	 * the present devset and access dips with status lock held.
	 * Similarly disconnect thread should clear the present devset
	 * and destroy dips with status lock held.
	 */
	mutex_enter(&sbp->sb_slock);

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= SBD_DEVS_PRESENT(sbp);

	/*
	 * Treat every CPU as a CMP.  In the case where the
	 * device is not a CMP, treat it as a CMP with only
	 * one core.
	 */
	for (cmp = ncpu = 0; cmp < MAX_CMP_UNITS_PER_BOARD; cmp++) {

		int		ncores;
		int		core;
		dev_info_t	*dip;
		sbd_cpu_unit_t	*cp;
		sbd_cmp_stat_t	*psp;

		if (DEVSET_IN_SET(devset, SBD_COMP_CMP, cmp) == 0)
			continue;

		ncores = 0;

		for (core = 0; core < MAX_CORES_PER_CMP; core++) {
			int	unit;

			unit = sbdp_portid_to_cpu_unit(cmp, core);

			/*
			 * Check to make sure the cpu is in a state
			 * where its fully initialized.
			 */
			if (SBD_DEVICE_STATE(sbp, SBD_COMP_CPU, unit) ==
			    SBD_STATE_EMPTY)
				continue;

			dip = sbp->sb_devlist[NIX(SBD_COMP_CMP)][unit];
			if (dip == NULL)
				continue;

			cp = SBD_GET_BOARD_CPUUNIT(sbp, unit);

			sbd_fill_cpu_stat(cp, dip, &cstat[ncores++]);
		}

		if (ncores == 0)
			continue;

		/*
		 * Store the data to the outgoing array. If the
		 * device is a CMP, combine all the data for the
		 * cores into a single stat structure.
		 *
		 * The check for a CMP device uses the last core
		 * found, assuming that all cores will have the
		 * same implementation.
		 */
		if (CPU_IMPL_IS_CMP(cp->sbc_cpu_impl)) {
			psp = (sbd_cmp_stat_t *)dsp;
			sbd_fill_cmp_stat(cstat, ncores, cp->sbc_cpu_impl, psp);
		} else {
			ASSERT(ncores == 1);
			bcopy(cstat, dsp, sizeof (sbd_cpu_stat_t));
		}

		dsp++;
		ncpu++;
	}

	mutex_exit(&sbp->sb_slock);

	sbd_release_sbdp_handle(hdp);

	return (ncpu);
}

int
sbd_pre_release_cpu(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	int		i, rv = 0, unit;
	dev_info_t	*dip;
	processorid_t	cpuid;
	struct cpu	*cpup;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_cpu_unit_t	*cp;
	static fn_t	f = "sbd_pre_release_cpu";
	sbdp_handle_t	*hdp;

	hdp = sbd_get_sbdp_handle(sbp, hp);
	/*
	 * May have to juggle bootproc in release_component
	 */
	mutex_enter(&cpu_lock);

	for (i = 0; i < devnum; i++, devlist++) {
		dip = devlist->dv_dip;

		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
					"sbd:%s: failed to get cpuid for "
					"dip (0x%p)", f, (void *)dip);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}


		unit = sbdp_get_unit_num(hdp, dip);
		if (unit < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
			cmn_err(CE_WARN,
				"sbd:%s: failed to get unit (cpu %d)",
				f, cpuid);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}

		cp = SBD_GET_BOARD_CPUUNIT(sbp, unit);
		cp->sbc_cpu_flags = cpu[cpuid]->cpu_flags;

		if (cpu_flagged_active(cp->sbc_cpu_flags)) {
			int cpu_offline_flags = 0;

			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				cpu_offline_flags = CPU_FORCED;
			PR_CPU("%s: offlining cpuid %d unit %d", f,
				cpuid, unit);
			if (cpu_offline(cpu[cpuid], cpu_offline_flags)) {
				cmn_err(CE_WARN,
					"%s: failed to offline cpu %d",
					f, cpuid);
				rv = -1;
				SBD_SET_ERR(ep, ESBD_OFFLINE);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
				cpup = cpu_get(cpuid);
				if (cpup && disp_bound_threads(cpup, 0)) {
					cmn_err(CE_WARN, "sbd:%s: thread(s) "
						"bound to cpu %d",
						f, cpup->cpu_id);
				}
				break;
			}
		}

		if (rv == 0) {
			if (sbdp_release_component(hdp, dip)) {
				SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}

		if (rv)
			break;
	}

	mutex_exit(&cpu_lock);

	if (rv) {
		/*
		 * Need to unwind others since at this level (pre-release)
		 * the device state has not yet transitioned and failures
		 * will prevent us from reaching the "post" release
		 * function where states are normally transitioned.
		 */
		for (; i >= 0; i--, devlist--) {
			dip = devlist->dv_dip;
			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				cmn_err(CE_WARN,
					"sbd:%s: failed to get unit for "
					"dip (0x%p)", f, (void *)dip);
				break;
			}
			(void) sbd_cancel_cpu(hp, unit);
		}
	}

	SBD_INJECT_ERR(SBD_OFFLINE_CPU_PSEUDO_ERR,
		hp->h_err, EIO,
		ESBD_OFFLINE,
		sbp->sb_cpupath[devnum - 1]);

	sbd_release_sbdp_handle(hdp);

	return (rv);
}

int
sbd_pre_attach_cpu(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	int		i;
	int		unit;
	processorid_t	cpuid;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_istate_t	dstate;
	dev_info_t	*dip;
	static fn_t	f = "sbd_pre_attach_cpu";
	sbdp_handle_t	*hdp;

	PR_CPU("%s...\n", f);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (i = 0; i < devnum; i++, devlist++) {
		dip = devlist->dv_dip;

		ASSERT(sbd_is_cmp_child(dip) || e_ddi_branch_held(dip));

		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
					"sbd:%s: failed to get cpuid for "
					"dip (0x%p)", f, (void *)dip);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}

		unit = sbdp_get_unit_num(hdp, dip);
		if (unit < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
			cmn_err(CE_WARN,
				"sbd:%s: failed to get unit (cpu %d)",
				f, cpuid);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}

		PR_CPU("%s: attach cpu-unit (%d.%d)\n",
			f, sbp->sb_num, unit);

		dstate = SBD_DEVICE_STATE(sbp, SBD_COMP_CPU, unit);

		if (dstate == SBD_STATE_UNCONFIGURED) {
			/*
			 * If we're coming from the UNCONFIGURED
			 * state then the cpu's sigblock will
			 * still be mapped in.  Need to unmap it
			 * before continuing with attachment.
			 */
			PR_CPU("%s: unmapping sigblk for cpu %d\n",
				f, cpuid);
		}

	}

	mutex_enter(&cpu_lock);

	sbd_release_sbdp_handle(hdp);

	return (0);
}

int
sbd_post_attach_cpu(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	int		i;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	processorid_t	cpuid;
	struct cpu	*cp;
	dev_info_t	*dip;
	int		err = ESBD_NOERROR;
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_post_attach_cpu";
	sbd_cpu_unit_t	*cpup;
	int		unit;

	hdp = sbd_get_sbdp_handle(sbp, hp);

	/* Startup and online newly-attached CPUs */
	for (i = 0; i < devnum; i++, devlist++) {
		dip = devlist->dv_dip;
		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to get cpuid for "
				    "dip (0x%p)", f, (void *)dip);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}

		cp = cpu_get(cpuid);

		if (cp == NULL) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
				    "sbd:%s: cpu_get failed for cpu %d",
				    f, cpuid);
				continue;
			} else {
				SBD_SET_ERR(ep, ESBD_INTERNAL);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
				break;
			}
		}

		if (cpu_is_poweredoff(cp)) {
			if (cpu_poweron(cp) != 0) {
				SBD_SET_ERR(ep, ESBD_CPUSTART);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
				cmn_err(CE_WARN,
				    "%s: failed to power-on cpu %d",
				    f, cpuid);
				break;
			}
			SBD_INJECT_ERR(SBD_POWERON_CPU_PSEUDO_ERR,
			    ep, EIO,
			    ESBD_CPUSTOP,
			    sbp->sb_cpupath[i]);
			PR_CPU("%s: cpu %d powered ON\n", f, cpuid);
		}

		if (cpu_is_offline(cp)) {
			PR_CPU("%s: onlining cpu %d...\n", f, cpuid);

			if (cpu_online(cp, 0) != 0) {
				SBD_SET_ERR(ep, ESBD_ONLINE);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
				cmn_err(CE_WARN,
				    "%s: failed to online cpu %d",
				    f, cp->cpu_id);
			}
			SBD_INJECT_ERR(SBD_ONLINE_CPU_PSEUDO_ERR,
			    ep, EIO,
			    ESBD_ONLINE,
			    sbp->sb_cpupath[i]);
		}

		/*
		 * if there is no error mark the cpu as OK to use
		 */
		if (SBD_GET_ERR(ep) == 0) {
			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
					cmn_err(CE_WARN,
					    "sbd:%s: failed to get unit "
					    "(cpu %d)", f, cpuid);
					continue;
				} else {
					SBD_GET_PERR(hdp->h_err,
					    SBD_HD2ERR(hp));
					break;
				}
			}
			cpup = SBD_GET_BOARD_CPUUNIT(sbp, unit);
			cpup->sbc_cm.sbdev_cond = SBD_COND_OK;
		}
	}

	mutex_exit(&cpu_lock);

	sbd_release_sbdp_handle(hdp);

	if (err != ESBD_NOERROR) {
		return (-1);
	} else {
		return (0);
	}
}

int
sbd_pre_detach_cpu(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	int		i;
	int		unit;
	processorid_t	cpuid;
	dev_info_t	*dip;
	struct cpu	*cpu;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	static fn_t	f = "sbd_pre_detach_cpu";
	sbdp_handle_t	*hdp;
	int		rv = 0;

	PR_CPU("%s...\n", f);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	mutex_enter(&cpu_lock);

	for (i = 0; i < devnum; i++, devlist++) {
		dip = devlist->dv_dip;
		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to get cpuid for "
				    "dip (0x%p)", f, (void *)dip);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}

		cpu = cpu_get(cpuid);

		if (cpu == NULL) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to get cpu %d",
				    f, cpuid);
				continue;
			} else {
				SBD_SET_ERR(ep, ESBD_INTERNAL);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
				break;
			}
		}

		unit = sbdp_get_unit_num(hdp, dip);
		if (unit < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to get unit (cpu %d)",
				    f, cpuid);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}

		PR_CPU("%s: OS detach cpu-unit (%d.%d)\n",
		    f, sbp->sb_num, unit);

		/*
		 * CPUs were offlined during Release.
		 */
		if (cpu_is_poweredoff(cpu)) {
			PR_CPU("%s: cpu %d already powered OFF\n", f, cpuid);
			continue;
		}

		if (cpu_is_offline(cpu)) {
			int	e;

			if (e = cpu_poweroff(cpu)) {
				cmn_err(CE_WARN,
				    "%s: failed to power-off cpu %d "
				    "(errno %d)",
				    f, cpu->cpu_id, e);
				SBD_SET_ERR(ep, ESBD_CPUSTOP);
				SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);

				rv = -1;
				break;
			} else {
				PR_CPU("%s: cpu %d powered OFF\n",
					f, cpuid);
			}
		} else {
			cmn_err(CE_WARN, "%s: cpu %d still active",
				f, cpu->cpu_id);
			SBD_SET_ERR(ep, ESBD_BUSY);
			SBD_SET_ERRSTR(ep, sbp->sb_cpupath[i]);
			rv = -1;
			break;
		}
	}

	sbd_release_sbdp_handle(hdp);

	return (rv);
}

int
sbd_post_detach_cpu(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	static fn_t	f = "sbd_post_detach_cpu";
	int		i;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	processorid_t	cpuid;
	dev_info_t	*dip;
	sbdp_handle_t	*hdp;
	sbd_cpu_unit_t	*cpup;
	int		unit;

	PR_CPU("%s...\n", f);

	/*
	 * We should be holding the cpu_lock at this point,
	 * and should have blocked device tree changes.
	 */
	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < devnum; i++, devlist++) {
		dip = devlist->dv_dip;
		hdp = sbd_get_sbdp_handle(sbp, hp);
		cpuid = sbdp_get_cpuid(hdp, dip);
		if (cpuid < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
				cmn_err(CE_WARN,
					"sbd:%s: failed to get cpuid for "
					"dip (0x%p)", f, (void *)dip);
				continue;
			} else {
				SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}
		/*
		 * if there is no error mark the cpu as unusable
		 */
		if (SBD_GET_ERR(ep) == 0) {
			unit = sbdp_get_unit_num(hdp, dip);
			if (unit < 0) {
				if (hp->h_flags & SBD_IOCTL_FLAG_FORCE) {
					cmn_err(CE_WARN,
					    "sbd:%s: failed to get unit "
					    "(cpu %d)", f, cpuid);
					continue;
				} else {
					SBD_GET_PERR(hdp->h_err,
					    SBD_HD2ERR(hp));
					break;
				}
			}
			cpup = SBD_GET_BOARD_CPUUNIT(sbp, unit);
			cpup->sbc_cm.sbdev_cond = SBD_COND_UNUSABLE;
		}
		sbd_release_sbdp_handle(hdp);
	}

	mutex_exit(&cpu_lock);


	return (0);
}

/*
 * Cancel previous release operation for cpu.  For cpus this means simply
 * bringing cpus that were offline back online.  Note that they had to have been
 * online at the time they were released.  If attempting to power on or online
 * a CPU fails, SBD_CPUERR_FATAL is returned to indicate that the CPU appears to
 * be unsalvageable.  If a CPU reaches an online or nointr state but can't be
 * taken to a "lesser" state, SBD_CPUERR_RECOVERABLE is returned to indicate
 * that it was not returned to its original state but appears to be functional.
 * Note that the latter case can occur due to unexpected but non-erroneous CPU
 * manipulation (e.g. by the "psradm" command) during the DR operation.
 */
int
sbd_cancel_cpu(sbd_handle_t *hp, int unit)
{
	int		rv = SBD_CPUERR_NONE;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_cpu_unit_t	*cp;
	static fn_t	f = "sbd_cancel_cpu";
	struct cpu	*cpup;
	int		cpu_offline_flags = 0;

	PR_ALL("%s...\n", f);

	cp = SBD_GET_BOARD_CPUUNIT(sbp, unit);

	/*
	 * If CPU should remain off, nothing needs to be done.
	 */
	if (cpu_flagged_poweredoff(cp->sbc_cpu_flags))
		return (rv);

	if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
		cpu_offline_flags = CPU_FORCED;

	/*
	 * CPU had been either offline, online, or set to no-intr.  We
	 * will return a component to its original state that it was
	 * prior to the failed DR operation.  There is a possible race
	 * condition between the calls to this function and re-obtaining
	 * the cpu_lock where a cpu state could change.  Because of this
	 * we can't externally document that we are trying to roll cpus
	 * back to their original state, but we believe a best effort
	 * should be made.
	 */

	mutex_enter(&cpu_lock);
	cpup = cpu[cp->sbc_cpu_id];

	/*
	 * The following will compare the cpu's current state with a
	 * snapshot of its state taken before the failed DR operation
	 * had started.
	 */
	/* POWEROFF */
	if (cpu_is_poweredoff(cpup)) {
		if (cpu_poweron(cpup)) {
			cmn_err(CE_WARN,
			    "sbd:%s: failed to power-on cpu %d",
			    f, cp->sbc_cpu_id);
			SBD_SET_ERR(ep, ESBD_CPUSTART);
			SBD_SET_ERRSTR(ep, sbp->sb_cpupath[unit]);
			rv = SBD_CPUERR_FATAL;
			goto out;
		}
		SBD_INJECT_ERR(SBD_POWERON_CPU_PSEUDO_ERR,
		    hp->h_err, EIO,
		    ESBD_CPUSTART,
		    sbp->sb_cpupath[unit]);
	}

	/* OFFLINE */
	if (cpu_is_offline(cpup)) {
		if (cpu_flagged_offline(cp->sbc_cpu_flags)) {
			PR_CPU("%s: leaving cpu %d OFFLINE\n",
			    f, cp->sbc_cpu_id);
		} else if (cpu_online(cpup, 0)) {
			cmn_err(CE_WARN,
			    "sbd:%s: failed to online cpu %d",
			    f, cp->sbc_cpu_id);
			SBD_SET_ERR(ep, ESBD_ONLINE);
			SBD_SET_ERRSTR(ep, sbp->sb_cpupath[unit]);
			rv = SBD_CPUERR_FATAL;
			goto out;
		} else {
			SBD_INJECT_ERR(SBD_ONLINE_CPU_PSEUDO_ERR,
			    hp->h_err, EIO,
			    ESBD_ONLINE,
			    sbp->sb_cpupath[unit]);
		}
	}

	/* ONLINE */
	if (cpu_is_online(cpup)) {
		if (cpu_flagged_online(cp->sbc_cpu_flags)) {
			PR_CPU("%s: setting cpu %d ONLINE\n",
			    f, cp->sbc_cpu_id);
		} else if (cpu_flagged_offline(cp->sbc_cpu_flags)) {
			if (cpu_offline(cpup, cpu_offline_flags)) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to offline"
				    " cpu %d", f, cp->sbc_cpu_id);
				rv = SBD_CPUERR_RECOVERABLE;
				goto out;
			}
		} else if (cpu_flagged_nointr(cp->sbc_cpu_flags)) {
			if (cpu_intr_disable(cpup)) {
				cmn_err(CE_WARN, "%s: failed to "
				    "disable interrupts on cpu %d",
				    f, cp->sbc_cpu_id);
				rv = SBD_CPUERR_RECOVERABLE;
			} else {
				PR_CPU("%s: setting cpu %d to NOINTR"
				    " (was online)\n",
				    f, cp->sbc_cpu_id);
			}
			goto out;
		}
	}

	/* NOINTR */
	if (cpu_is_nointr(cpup)) {
		if (cpu_flagged_online(cp->sbc_cpu_flags)) {
			cpu_intr_enable(cpup);
			PR_CPU("%s: setting cpu %d ONLINE"
			    "(was nointr)\n",
			    f, cp->sbc_cpu_id);
		}
		if (cpu_flagged_offline(cp->sbc_cpu_flags)) {
			if (cpu_offline(cpup, cpu_offline_flags)) {
				cmn_err(CE_WARN,
				    "sbd:%s: failed to offline"
				    " cpu %d", f, cp->sbc_cpu_id);
				rv = SBD_CPUERR_RECOVERABLE;
			}
		}
	}
out:
	mutex_exit(&cpu_lock);

	return (rv);
}

int
sbd_connect_cpu(sbd_board_t *sbp, int unit)
{
	int		rv;
	processorid_t	cpuid;
	struct cpu	*cpu;
	dev_info_t	*dip;
	sbdp_handle_t	*hdp;
	extern kmutex_t	cpu_lock;
	static fn_t	f = "sbd_connect_cpu";
	sbd_handle_t	*hp = MACHBD2HD(sbp);

	/*
	 * get dip for cpu just located in tree walk
	 */
	if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_CPU, unit)) {
		dip = sbp->sb_devlist[NIX(SBD_COMP_CPU)][unit];
		if (dip == NULL) {
			cmn_err(CE_WARN,
			"sbd:%s: bad dip for cpu unit %d board %d",
			f, unit, sbp->sb_num);
			return (-1);
		}
		PR_CPU("%s...\n", f);
	} else {
		return (0);
	}

	/*
	 * if sbd has attached this cpu, no need to bring
	 * it out of reset
	 */
	if (SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_CPU, unit)) {
		return (0);
	}

	hdp = sbd_get_sbdp_handle(sbp, hp);

	cpuid = sbdp_get_cpuid(hdp, dip);
	if (cpuid == -1) {
		sbd_release_sbdp_handle(hdp);
		return (-1);
	}

	/*
	 * if the cpu is already under Solaris control,
	 * do not wake it up
	 */
	mutex_enter(&cpu_lock);
	cpu = cpu_get(cpuid);
	mutex_exit(&cpu_lock);
	if (cpu != NULL) {
		sbd_release_sbdp_handle(hdp);
		return (0);
	}

	rv = sbdp_connect_cpu(hdp, dip, cpuid);

	if (rv != 0) {
		sbp->sb_memaccess_ok = 0;
		cmn_err(CE_WARN,
			"sbd:%s: failed to wake up cpu unit %d board %d",
			f, unit, sbp->sb_num);
		sbd_release_sbdp_handle(hdp);
		return (rv);
	}
	sbd_release_sbdp_handle(hdp);

	return (rv);
}

int
sbd_disconnect_cpu(sbd_handle_t *hp, int unit)
{
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	int		rv;
	dev_info_t	*dip;
	sbdp_handle_t	*hdp;
	sbd_cpu_unit_t *cp;
	processorid_t   cpuid;
	static fn_t	f = "sbd_disconnect_cpu";

	PR_CPU("%s...\n", f);

	ASSERT((SBD_DEVICE_STATE(sbp, SBD_COMP_CPU, unit) ==
						SBD_STATE_CONNECTED) ||
		(SBD_DEVICE_STATE(sbp, SBD_COMP_CPU, unit) ==
						SBD_STATE_UNCONFIGURED));

	cp = SBD_GET_BOARD_CPUUNIT(sbp, unit);

	cpuid = cp->sbc_cpu_id;

	dip = sbp->sb_devlist[NIX(SBD_COMP_CPU)][unit];

	hdp = sbd_get_sbdp_handle(sbp, hp);

	rv = sbdp_disconnect_cpu(hdp, dip, cpuid);

	if (rv != 0) {
		SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
	}
	sbd_release_sbdp_handle(hdp);

	return (rv);
}
