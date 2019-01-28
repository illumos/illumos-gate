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

/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * CPU support routines for DR
 */

#include <sys/note.h>
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
#include <sys/cpu_impl.h>

#include <sys/autoconf.h>
#include <sys/cmn_err.h>

#include <sys/dr.h>
#include <sys/dr_util.h>

/* for the DR*INTERNAL_ERROR macros.  see sys/dr.h. */
static char *dr_ie_fmt = "dr_cpu.c %d";

int
dr_cpu_unit_is_sane(dr_board_t *bp, dr_cpu_unit_t *cp)
{
#ifdef DEBUG
	processorid_t	cpuid;

	/*
	 * cpuid and unit number should never be different
	 * than they were at discovery/connect time
	 */
	ASSERT(drmach_cpu_get_id(cp->sbc_cm.sbdev_id, &cpuid) == 0);

	ASSERT(cp->sbc_cm.sbdev_bp == bp);
	ASSERT(cp->sbc_cm.sbdev_type == SBD_COMP_CPU);
	ASSERT(cp->sbc_cpu_id == cpuid);
#else
	_NOTE(ARGUNUSED(bp))
	_NOTE(ARGUNUSED(cp))
#endif

	return (1);
}

static int
dr_errno2ecode(int error)
{
	int	rv;

	switch (error) {
	case EBUSY:
		rv = ESBD_BUSY;
		break;
	case EINVAL:
		rv = ESBD_INVAL;
		break;
	case EALREADY:
		rv = ESBD_ALREADY;
		break;
	case ENODEV:
		rv = ESBD_NODEV;
		break;
	case ENOMEM:
		rv = ESBD_NOMEM;
		break;
	default:
		rv = ESBD_INVAL;
	}

	return (rv);
}

static void
dr_cpu_set_prop(dr_cpu_unit_t *cp)
{
	sbd_error_t	*err;
	dev_info_t	*dip;
	uint64_t	clock_freq;
	int		ecache_size = 0;
	char		*cache_str = NULL;

	err = drmach_get_dip(cp->sbc_cm.sbdev_id, &dip);
	if (err) {
		DRERR_SET_C(&cp->sbc_cm.sbdev_error, &err);
		return;
	}

	if (dip == NULL) {
		DR_DEV_INTERNAL_ERROR(&cp->sbc_cm);
		return;
	}

	/* read in the CPU speed */

	/*
	 * If the property is not found in the CPU node, it has to be
	 * kept in the core or cmp node so we just keep looking.
	 */
	clock_freq = (unsigned int)ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "clock-frequency", 0);

	ASSERT(clock_freq != 0);

	/*
	 * The ecache property string is not the same
	 * for all CPU implementations.
	 */

	switch (cp->sbc_cpu_impl) {
	case BLACKBIRD_IMPL:
	case CHEETAH_IMPL:
	case CHEETAH_PLUS_IMPL:
		cache_str = "ecache-size";
		break;
	case JAGUAR_IMPL:
	case OLYMPUS_C_IMPL:
	case JUPITER_IMPL:
		cache_str = "l2-cache-size";
		break;
	case PANTHER_IMPL:
		cache_str = "l3-cache-size";
		break;
	default:
		cmn_err(CE_WARN, "Unknown cpu implementation=0x%x",
		    cp->sbc_cpu_impl);
		ASSERT(0);
		break;
	}

	if (cache_str != NULL) {
		/* read in the ecache size */
		/*
		 * If the property is not found in the CPU node,
		 * it has to be kept in the core or cmp node so
		 * we just keep looking.
		 */

		ecache_size = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    cache_str, 0);
	}

	ASSERT(ecache_size != 0);

	/* convert to the proper units */
	cp->sbc_speed = (clock_freq + 500000) / 1000000;
	cp->sbc_ecache = ecache_size / (1024 * 1024);
}

void
dr_init_cpu_unit(dr_cpu_unit_t *cp)
{
	sbd_error_t	*err;
	dr_state_t	new_state;
	int		cpuid;
	int		impl;

	if (DR_DEV_IS_ATTACHED(&cp->sbc_cm)) {
		new_state = DR_STATE_CONFIGURED;
		cp->sbc_cm.sbdev_cond = SBD_COND_OK;
	} else if (DR_DEV_IS_PRESENT(&cp->sbc_cm)) {
		new_state = DR_STATE_CONNECTED;
		cp->sbc_cm.sbdev_cond = SBD_COND_OK;
	} else {
		new_state = DR_STATE_EMPTY;
		cp->sbc_cm.sbdev_cond = SBD_COND_UNKNOWN;
	}

	if (DR_DEV_IS_PRESENT(&cp->sbc_cm)) {
		err = drmach_cpu_get_id(cp->sbc_cm.sbdev_id, &cpuid);
		if (err) {
			DRERR_SET_C(&cp->sbc_cm.sbdev_error, &err);
			new_state = DR_STATE_FATAL;
			goto done;
		}

		err = drmach_cpu_get_impl(cp->sbc_cm.sbdev_id, &impl);
		if (err) {
			DRERR_SET_C(&cp->sbc_cm.sbdev_error, &err);
			new_state = DR_STATE_FATAL;
			goto done;
		}
	} else {
		cp->sbc_cpu_id = -1;
		cp->sbc_cpu_impl = -1;
		goto done;
	}

	cp->sbc_cpu_id = cpuid;
	cp->sbc_cpu_impl = impl;

	/* if true at init time, it must always be true */
	ASSERT(dr_cpu_unit_is_sane(cp->sbc_cm.sbdev_bp, cp));

	mutex_enter(&cpu_lock);
	if ((cpuid >= 0) && cpu[cpuid])
		cp->sbc_cpu_flags = cpu[cpuid]->cpu_flags;
	else
		cp->sbc_cpu_flags = P_OFFLINE | P_POWEROFF;
	mutex_exit(&cpu_lock);

	dr_cpu_set_prop(cp);

done:
	/* delay transition until fully initialized */
	dr_device_transition(&cp->sbc_cm, new_state);
}

int
dr_pre_attach_cpu(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		i;
	int		curr_cpu;
	int		next_cpu;
	static fn_t	f = "dr_pre_attach_cpu";

	PR_CPU("%s...\n", f);

	for (next_cpu = 0, i = 0; i < devnum; i++) {
		dr_cpu_unit_t *up = (dr_cpu_unit_t *)devlist[i];

		ASSERT(dr_cpu_unit_is_sane(hp->h_bd, up));

		/*
		 * Print a console message for each attachment
		 * point. For CMP devices, this means that only
		 * one message should be printed, no matter how
		 * many cores are actually present.
		 */
		curr_cpu = DR_UNUM2SBD_UNUM(up->sbc_cm.sbdev_unum,
		    SBD_COMP_CPU);
		if (curr_cpu >= next_cpu) {
			cmn_err(CE_CONT, "OS configure %s",
			    up->sbc_cm.sbdev_path);
			next_cpu = curr_cpu + 1;
		}

		if (up->sbc_cm.sbdev_state == DR_STATE_UNCONFIGURED) {
			/*
			 * If we're coming from the UNCONFIGURED
			 * state then the cpu's sigblock will
			 * still be mapped in.  Need to unmap it
			 * before continuing with attachment.
			 */
			PR_CPU("%s: unmapping sigblk for cpu %d\n", f,
			    up->sbc_cpu_id);
		}
	}

	/*
	 * Block out status threads while creating
	 * devinfo tree branches
	 */
	dr_lock_status(hp->h_bd);
	ndi_devi_enter(ddi_root_node(), (int *)(&hp->h_ndi));
	mutex_enter(&cpu_lock);

	return (0);
}

/*ARGSUSED*/
void
dr_attach_cpu(dr_handle_t *hp, dr_common_unit_t *cp)
{
	sbd_error_t	*err;
	processorid_t	 cpuid;
	int		 rv;

	ASSERT(MUTEX_HELD(&cpu_lock));

	err = drmach_configure(cp->sbdev_id, 0);
	if (err) {
		DRERR_SET_C(&cp->sbdev_error, &err);
		return;
	}

	err = drmach_cpu_get_id(cp->sbdev_id, &cpuid);
	if (err) {
		DRERR_SET_C(&cp->sbdev_error, &err);

		err = drmach_unconfigure(cp->sbdev_id, DEVI_BRANCH_DESTROY);
		if (err)
			sbd_err_clear(&err);
	} else if ((rv = cpu_configure(cpuid)) != 0) {
		dr_dev_err(CE_WARN, cp, dr_errno2ecode(rv));
		err = drmach_unconfigure(cp->sbdev_id, DEVI_BRANCH_DESTROY);
		if (err)
			sbd_err_clear(&err);
	}
}

/*
 * dr_post_attach_cpu
 *
 * sbd error policy: Does not stop on error.  Processes all units in list.
 */
int
dr_post_attach_cpu(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		i;
	int		errflag = 0;
	static fn_t	f = "dr_post_attach_cpu";

	PR_CPU("%s...\n", f);

	/* Startup and online newly-attached CPUs */
	for (i = 0; i < devnum; i++) {
		dr_cpu_unit_t *up = (dr_cpu_unit_t *)devlist[i];
		struct cpu	*cp;

		ASSERT(dr_cpu_unit_is_sane(hp->h_bd, up));

		cp = cpu_get(up->sbc_cpu_id);
		if (cp == NULL) {
			cmn_err(CE_WARN, "%s: cpu_get failed for cpu %d",
			    f, up->sbc_cpu_id);
			continue;
		}

		if (cpu_is_poweredoff(cp)) {
			if (cpu_poweron(cp) != 0) {
				dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_CPUSTART);
				errflag = 1;
			}
			PR_CPU("%s: cpu %d powered ON\n", f, up->sbc_cpu_id);
		}

		if (cpu_is_offline(cp)) {
			PR_CPU("%s: onlining cpu %d...\n", f, up->sbc_cpu_id);

			if (cpu_online(cp) != 0) {
				dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_ONLINE);
				errflag = 1;
			}
		}

	}

	mutex_exit(&cpu_lock);
	ndi_devi_exit(ddi_root_node(), hp->h_ndi);
	dr_unlock_status(hp->h_bd);

	if (errflag)
		return (-1);
	else
		return (0);
}

/*
 * dr_pre_release_cpu
 *
 * sbd error policy: Stops on first error.
 */
int
dr_pre_release_cpu(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		c, cix, i, lastoffline = -1, rv = 0;
	processorid_t	cpuid;
	struct cpu	*cp;
	dr_cpu_unit_t	*up;
	dr_devset_t	devset;
	sbd_dev_stat_t	*ds;
	static fn_t	f = "dr_pre_release_cpu";
	int		cpu_flags = 0;

	devset = DR_DEVS_PRESENT(hp->h_bd);

	/* allocate status struct storage. */
	ds = (sbd_dev_stat_t *) kmem_zalloc(sizeof (sbd_dev_stat_t) *
	    MAX_CPU_UNITS_PER_BOARD, KM_SLEEP);

	cix = dr_cpu_status(hp, devset, ds);

	mutex_enter(&cpu_lock);

	for (i = 0; i < devnum; i++) {
		up = (dr_cpu_unit_t *)devlist[i];
		ASSERT(dr_cpu_unit_is_sane(hp->h_bd, up));

		/*
		 * The STARCAT platform borrows cpus for use by POST in
		 * iocage testing.  These cpus cannot be unconfigured
		 * while they are in use for the iocage.
		 * This check determines if a CPU is currently in use
		 * for iocage testing, and if so, returns a "Device busy"
		 * error.
		 */
		for (c = 0; c < cix; c++) {
			if (ds[c].d_cpu.cs_unit == up->sbc_cm.sbdev_unum) {
				if (ds[c].d_cpu.cs_busy) {
					dr_dev_err(CE_WARN, &up->sbc_cm,
					    ESBD_BUSY);
					rv = -1;
					break;
				}
			}
		}
		if (c < cix)
			break;
		cpuid = up->sbc_cpu_id;
		if ((cp = cpu_get(cpuid)) == NULL) {
			dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_OFFLINE);
			rv = -1;
			break;
		}

		/* used by dr_cancel_cpu during error flow */
		up->sbc_cpu_flags = cp->cpu_flags;

		if (CPU_ACTIVE(cp)) {
			if (dr_cmd_flags(hp) & SBD_FLAG_FORCE)
				cpu_flags = CPU_FORCED;

			PR_CPU("%s: offlining cpu %d\n", f, cpuid);
			if (cpu_offline(cp, cpu_flags)) {
				PR_CPU("%s: failed to offline cpu %d\n", f,
				    cpuid);
				dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_OFFLINE);
				if (disp_bound_threads(cp, 0)) {
					cmn_err(CE_WARN, "%s: thread(s) bound "
					    "to cpu %d", f, cp->cpu_id);
				}
				rv = -1;
				break;
			} else
				lastoffline = i;
		}

		if (!rv) {
			sbd_error_t *err;

			err = drmach_release(up->sbc_cm.sbdev_id);
			if (err) {
				DRERR_SET_C(&up->sbc_cm.sbdev_error, &err);
				rv = -1;
				break;
			}
		}
	}

	mutex_exit(&cpu_lock);

	if (rv) {
		/*
		 * Need to unwind others since at this level (pre-release)
		 * the device state has not yet transitioned and failures
		 * will prevent us from reaching the "post" release
		 * function where states are normally transitioned.
		 */
		for (i = lastoffline; i >= 0; i--) {
			up = (dr_cpu_unit_t *)devlist[i];
			(void) dr_cancel_cpu(up);
		}
	}

	kmem_free(ds, sizeof (sbd_dev_stat_t) * MAX_CPU_UNITS_PER_BOARD);
	return (rv);
}

/*
 * dr_pre_detach_cpu
 *
 * sbd error policy: Stops on first error.
 */
int
dr_pre_detach_cpu(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))

	int		i;
	int		curr_cpu;
	int		next_cpu;
	int		cpu_flags = 0;
	static fn_t	f = "dr_pre_detach_cpu";

	PR_CPU("%s...\n", f);

	/*
	 * Block out status threads while destroying devinfo tree
	 * branches
	 */
	dr_lock_status(hp->h_bd);
	mutex_enter(&cpu_lock);

	for (next_cpu = 0, i = 0; i < devnum; i++) {
		dr_cpu_unit_t *up = (dr_cpu_unit_t *)devlist[i];
		struct cpu	*cp;

		ASSERT(dr_cpu_unit_is_sane(hp->h_bd, up));

		cp = cpu_get(up->sbc_cpu_id);
		if (cp == NULL)
			continue;

		/*
		 * Print a console message for each attachment
		 * point. For CMP devices, this means that only
		 * one message should be printed, no matter how
		 * many cores are actually present.
		 */
		curr_cpu = DR_UNUM2SBD_UNUM(up->sbc_cm.sbdev_unum,
		    SBD_COMP_CPU);
		if (curr_cpu >= next_cpu) {
			cmn_err(CE_CONT, "OS unconfigure %s\n",
			    up->sbc_cm.sbdev_path);
			next_cpu = curr_cpu + 1;
		}

		/*
		 * CPUs were offlined during Release.
		 */
		if (cpu_is_poweredoff(cp)) {
			PR_CPU("%s: cpu %d already powered OFF\n",
			    f, up->sbc_cpu_id);
			continue;
		}

		if (!cpu_is_offline(cp)) {
			if (dr_cmd_flags(hp) & SBD_FLAG_FORCE)
				cpu_flags = CPU_FORCED;
			/* cpu was onlined after release.  Offline it again */
			PR_CPU("%s: offlining cpu %d\n", f, up->sbc_cpu_id);
			if (cpu_offline(cp, cpu_flags)) {
				PR_CPU("%s: failed to offline cpu %d\n",
				    f, up->sbc_cpu_id);
				dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_OFFLINE);
				if (disp_bound_threads(cp, 0)) {
					cmn_err(CE_WARN, "%s: thread(s) bound "
					    "to cpu %d", f, cp->cpu_id);
				}
				goto err;
			}
		}
		if (cpu_poweroff(cp) != 0) {
			dr_dev_err(CE_WARN, &up->sbc_cm, ESBD_CPUSTOP);
			goto err;
		} else {
			PR_CPU("%s: cpu %d powered OFF\n", f, up->sbc_cpu_id);
		}
	}

	return (0);

err:
	mutex_exit(&cpu_lock);
	dr_unlock_status(hp->h_bd);
	return (-1);
}

/*ARGSUSED*/
void
dr_detach_cpu(dr_handle_t *hp, dr_common_unit_t *cp)
{
	sbd_error_t	*err;
	processorid_t	 cpuid;
	int		 rv;

	ASSERT(MUTEX_HELD(&cpu_lock));

	err = drmach_cpu_get_id(cp->sbdev_id, &cpuid);
	if (err) {
		DRERR_SET_C(&cp->sbdev_error, &err);
	} else if ((rv = cpu_unconfigure(cpuid)) != 0) {
		dr_dev_err(CE_IGNORE, cp, dr_errno2ecode(rv));
	} else {
		err = drmach_unconfigure(cp->sbdev_id, DEVI_BRANCH_DESTROY);
		if (err) {
			DRERR_SET_C(&cp->sbdev_error, &err);
		}
	}
}

/*ARGSUSED1*/
int
dr_post_detach_cpu(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	static fn_t	f = "dr_post_detach_cpu";

	PR_CPU("%s...\n", f);
	hp->h_ndi = 0;

	mutex_exit(&cpu_lock);
	dr_unlock_status(hp->h_bd);

	return (0);
}

static void
dr_fill_cpu_stat(dr_cpu_unit_t *cp, drmach_status_t *pstat, sbd_cpu_stat_t *csp)
{
	ASSERT(cp && pstat && csp);

	/* Fill in the common status information */
	bzero((caddr_t)csp, sizeof (*csp));
	csp->cs_type = cp->sbc_cm.sbdev_type;
	csp->cs_unit = cp->sbc_cm.sbdev_unum;
	(void) strncpy(csp->cs_name, pstat->type, sizeof (csp->cs_name));
	csp->cs_cond = cp->sbc_cm.sbdev_cond;
	csp->cs_busy = cp->sbc_cm.sbdev_busy | pstat->busy;
	csp->cs_time = cp->sbc_cm.sbdev_time;
	csp->cs_ostate = cp->sbc_cm.sbdev_ostate;
	csp->cs_suspend = 0;

	/* CPU specific status data */
	csp->cs_cpuid = cp->sbc_cpu_id;

	/*
	 * If the speed and ecache properties have not been
	 * cached yet, read them in from the device tree.
	 */
	if ((cp->sbc_speed == 0) || (cp->sbc_ecache == 0))
		dr_cpu_set_prop(cp);

	/* use the cached speed and ecache values */
	csp->cs_speed = cp->sbc_speed;
	csp->cs_ecache = cp->sbc_ecache;

	mutex_enter(&cpu_lock);
	if (!cpu_get(csp->cs_cpuid)) {
		/* ostate must be UNCONFIGURED */
		csp->cs_cm.c_ostate = SBD_STAT_UNCONFIGURED;
	}
	mutex_exit(&cpu_lock);
}

static void
dr_fill_cmp_stat(sbd_cpu_stat_t *csp, int ncores, int impl, sbd_cmp_stat_t *psp)
{
	int	core;

	ASSERT(csp && psp && (ncores >= 1));

	bzero((caddr_t)psp, sizeof (*psp));

	/*
	 * Fill in the common status information based
	 * on the data for the first core.
	 */
	psp->ps_type = SBD_COMP_CMP;
	psp->ps_unit = DR_UNUM2SBD_UNUM(csp->cs_unit, SBD_COMP_CMP);
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
		ASSERT(psp->ps_unit == DR_UNUM2SBD_UNUM(csp[core].cs_unit,
		    SBD_COMP_CMP));
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
dr_cpu_status(dr_handle_t *hp, dr_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		cmp;
	int		core;
	int		ncpu;
	dr_board_t	*bp;
	sbd_cpu_stat_t	cstat[MAX_CORES_PER_CMP];
	int		impl;

	bp = hp->h_bd;
	ncpu = 0;

	devset &= DR_DEVS_PRESENT(bp);

	/*
	 * Treat every CPU as a CMP. In the case where the
	 * device is not a CMP, treat it as a CMP with only
	 * one core.
	 */
	for (cmp = 0; cmp < MAX_CMP_UNITS_PER_BOARD; cmp++) {

		int		ncores;
		dr_cpu_unit_t	*cp;
		drmach_status_t	pstat;
		sbd_error_t	*err;
		sbd_cmp_stat_t	*psp;

		if ((devset & DEVSET(SBD_COMP_CMP, cmp)) == 0) {
			continue;
		}

		ncores = 0;

		for (core = 0; core < MAX_CORES_PER_CMP; core++) {

			cp = dr_get_cpu_unit(bp, DR_CMP_CORE_UNUM(cmp, core));

			if (cp->sbc_cm.sbdev_state == DR_STATE_EMPTY) {
				/* present, but not fully initialized */
				continue;
			}

			ASSERT(dr_cpu_unit_is_sane(hp->h_bd, cp));

			/* skip if not present */
			if (cp->sbc_cm.sbdev_id == (drmachid_t)0) {
				continue;
			}

			/* fetch platform status */
			err = drmach_status(cp->sbc_cm.sbdev_id, &pstat);
			if (err) {
				DRERR_SET_C(&cp->sbc_cm.sbdev_error, &err);
				continue;
			}

			dr_fill_cpu_stat(cp, &pstat, &cstat[ncores++]);
			/*
			 * We should set impl here because the last core
			 * found might be EMPTY or not present.
			 */
			impl = cp->sbc_cpu_impl;
		}

		if (ncores == 0) {
			continue;
		}

		/*
		 * Store the data to the outgoing array. If the
		 * device is a CMP, combine all the data for the
		 * cores into a single stat structure.
		 *
		 * The check for a CMP device uses the last core
		 * found, assuming that all cores will have the
		 * same implementation.
		 */

		if (CPU_IMPL_IS_CMP(impl)) {
			psp = (sbd_cmp_stat_t *)dsp;
			dr_fill_cmp_stat(cstat, ncores, impl, psp);
		} else {
			ASSERT(ncores == 1);
			bcopy(cstat, dsp, sizeof (sbd_cpu_stat_t));
		}

		dsp++;
		ncpu++;
	}

	return (ncpu);
}

/*
 * Cancel previous release operation for cpu.
 * For cpus this means simply bringing cpus that
 * were offline back online.  Note that they had
 * to have been online at the time there were
 * released.
 */
int
dr_cancel_cpu(dr_cpu_unit_t *up)
{
	int		rv = 0;
	static fn_t	f = "dr_cancel_cpu";

	ASSERT(dr_cpu_unit_is_sane(up->sbc_cm.sbdev_bp, up));

	if (cpu_flagged_active(up->sbc_cpu_flags)) {
		struct cpu	*cp;

		/*
		 * CPU had been online, go ahead
		 * bring it back online.
		 */
		PR_CPU("%s: bringing cpu %d back ONLINE\n", f, up->sbc_cpu_id);

		mutex_enter(&cpu_lock);
		cp = cpu[up->sbc_cpu_id];

		if (cpu_is_poweredoff(cp)) {
			if (cpu_poweron(cp)) {
				cmn_err(CE_WARN, "%s: failed to power-on "
				    "cpu %d", f, up->sbc_cpu_id);
				rv = -1;
			}
		}

		if (cpu_is_offline(cp)) {
			if (cpu_online(cp)) {
				cmn_err(CE_WARN, "%s: failed to online cpu %d",
				    f, up->sbc_cpu_id);
				rv = -1;
			}
		}

		if (cpu_is_online(cp)) {
			if (cpu_flagged_nointr(up->sbc_cpu_flags)) {
				if (cpu_intr_disable(cp) != 0) {
					cmn_err(CE_WARN, "%s: failed to "
					    "disable interrupts on cpu %d", f,
					    up->sbc_cpu_id);
				}
			}
		}

		mutex_exit(&cpu_lock);
	}

	return (rv);
}

int
dr_disconnect_cpu(dr_cpu_unit_t *up)
{
	sbd_error_t	*err;
	static fn_t	f = "dr_disconnect_cpu";

	PR_CPU("%s...\n", f);

	ASSERT((up->sbc_cm.sbdev_state == DR_STATE_CONNECTED) ||
	    (up->sbc_cm.sbdev_state == DR_STATE_UNCONFIGURED));

	ASSERT(dr_cpu_unit_is_sane(up->sbc_cm.sbdev_bp, up));

	if (up->sbc_cm.sbdev_state == DR_STATE_CONNECTED) {
		/*
		 * Cpus were never brought in and so are still
		 * effectively disconnected, so nothing to do here.
		 */
		PR_CPU("%s: cpu %d never brought in\n", f, up->sbc_cpu_id);
		return (0);
	}

	err = drmach_cpu_disconnect(up->sbc_cm.sbdev_id);
	if (err == NULL)
		return (0);
	else {
		DRERR_SET_C(&up->sbc_cm.sbdev_error, &err);
		return (-1);
	}
	/*NOTREACHED*/
}
