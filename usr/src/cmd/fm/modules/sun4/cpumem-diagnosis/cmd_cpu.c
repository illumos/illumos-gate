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
 * Copyright (c) 2019 Peter Tribble.
 */

/*
 * Support routines for managing per-CPU state.
 */

#include <cmd_cpu.h>

#ifdef sun4u
#include <cmd_ecache.h>
#endif /* sun4u */

#include <cmd_mem.h>
#include <cmd.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <kstat.h>
#include <fm/fmd_api.h>
#include <sys/async.h>
#include <sys/fm/protocol.h>

#ifdef sun4u
#include <sys/cheetahregs.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <cmd_opl.h>
#include <cmd_Lxcache.h>
#else /* sun4u */
#include <sys/niagararegs.h>
#include <sys/fm/cpu/UltraSPARC-T1.h>
#include <cmd_hc_sun4v.h>
#endif /* sun4u */

#define	CMD_CPU_UEC_INCR	10

/* Must be in sync with cmd_cpu_type_t */
static const char *const cpu_names[] = {
	NULL,
	"ultraSPARC-III",
	"ultraSPARC-IIIplus",
	"ultraSPARC-IIIi",
	"ultraSPARC-IV",
	"ultraSPARC-IVplus",
	"ultraSPARC-IIIiplus",
	"ultraSPARC-T1",
	"SPARC64-VI",
	"SPARC64-VII",
	"ultraSPARC-T2",
	"ultraSPARC-T2plus"
};

/*
 * This needs to be in sync with cpu_family_t.
 */
static const faminfo_t fam_info_tbl[] = {
	{ CMD_CPU_FAM_UNSUPPORTED,	B_FALSE },
	{ CMD_CPU_FAM_CHEETAH,		B_TRUE },
	{ CMD_CPU_FAM_NIAGARA,		B_FALSE },
	{ CMD_CPU_FAM_SPARC64,		B_FALSE }
};

static cmd_cpu_t *cpu_lookup_by_cpuid(uint32_t, uint8_t);
static cmd_cpu_t *cpu_create(fmd_hdl_t *, nvlist_t *, uint32_t,
    uint8_t, cmd_cpu_type_t);
static void cpu_buf_write(fmd_hdl_t *, cmd_cpu_t *);

const char *
cmd_cpu_type2name(fmd_hdl_t *hdl, cmd_cpu_type_t type)
{
	if (type < 1 || type > sizeof (cpu_names) / sizeof (char *))
		fmd_hdl_abort(hdl, "illegal CPU type %d\n", type);

	return (cpu_names[type]);
}

static cmd_cpu_type_t
cpu_nname2type(fmd_hdl_t *hdl, const char *name, size_t n)
{
	int i;

	for (i = 1; i < sizeof (cpu_names) / sizeof (char *); i++) {
		if (strlen(cpu_names[i]) == n &&
		    strncmp(cpu_names[i], name, n) == 0)
			return (i);
	}

	fmd_hdl_abort(hdl, "illegal CPU name %*.*s\n", n, n, name);
	/*NOTREACHED*/
	return (0);
}

const char *fmd_fmri_get_platform();
#define	is_serengeti	(strcmp(fmd_fmri_get_platform(), \
"SUNW,Sun-Fire") == 0)

static void
core2cpus(uint32_t core, cmd_cpu_type_t type, uint8_t level,
    uint32_t *cpuinit, uint32_t *cpufinal, uint32_t *cpustep)
{
	switch (type) {
#ifdef sun4u

#define	US4P_SGTI_CPUS_PER_CORE		2
#define	US4P_SGTI_CPU_CORE_STEP		512
#define	US4P_DAKC_CPUS_PER_CORE		2
#define	US4P_DAKC_CPU_CORE_STEP		16

	case CPU_ULTRASPARC_IVplus:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			if (is_serengeti)
				*cpustep = US4P_SGTI_CPU_CORE_STEP;
			else
				*cpustep = US4P_DAKC_CPU_CORE_STEP;
			*cpuinit = core;
			*cpufinal = *cpuinit + *cpustep;
			return;
		default:
			*cpuinit = *cpufinal = core;
			*cpustep = 1;
			return;
		}
#else /* i.e. sun4v */

#define	UST1_CPUS_PER_CORE		4
#define	UST1_CPU_CORE_STEP		1
#define	UST1_CPUS_PER_CHIP		32
#define	UST1_CPU_CHIP_STEP		1
#define	UST2_CPUS_PER_CORE		8
#define	UST2_CPU_CORE_STEP		1
#define	UST2_CPUS_PER_CHIP		64
#define	UST2_CPU_CHIP_STEP		1

	case CPU_ULTRASPARC_T1:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			*cpuinit = core * UST1_CPUS_PER_CORE;
			*cpufinal = *cpuinit + UST1_CPUS_PER_CORE - 1;
			*cpustep = UST1_CPU_CORE_STEP;
			return;
		case CMD_CPU_LEVEL_CHIP:
			*cpuinit = core * UST1_CPUS_PER_CHIP;
			*cpufinal = *cpuinit + UST1_CPUS_PER_CHIP - 1;
			*cpustep = UST1_CPU_CHIP_STEP;
			return;
		default:
			*cpuinit = *cpufinal = core;
			*cpustep = 1;
			return;
		}
	case CPU_ULTRASPARC_T2:
	case CPU_ULTRASPARC_T2plus:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			*cpuinit = core * UST2_CPUS_PER_CORE;
			*cpufinal = *cpuinit + UST2_CPUS_PER_CORE - 1;
			*cpustep = UST2_CPU_CORE_STEP;
			return;
		case CMD_CPU_LEVEL_CHIP:
			*cpuinit = core * UST2_CPUS_PER_CHIP;
			*cpufinal = *cpuinit + UST2_CPUS_PER_CHIP - 1;
			*cpustep = UST2_CPU_CHIP_STEP;
			return;
		default:
			*cpuinit = *cpufinal = core;
			*cpustep = 1;
			return;
		}

#endif /* sun4u */
	default:
		*cpuinit = *cpufinal = core;
		*cpustep = 1;
		return;
	}
}

uint32_t
cmd_cpu2core(uint32_t cpuid, cmd_cpu_type_t type, uint8_t level)
{
	switch (type) {
#ifdef sun4u

	case CPU_ULTRASPARC_IVplus:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			if (is_serengeti)
				return (cpuid % US4P_SGTI_CPU_CORE_STEP);
			else
				return (cpuid % US4P_DAKC_CPU_CORE_STEP);
		default:
			return (cpuid);
		}
#else /* i.e. sun4v */
	case CPU_ULTRASPARC_T1:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			return (cpuid/UST1_CPUS_PER_CORE);
		case CMD_CPU_LEVEL_CHIP:
			return (cpuid/UST1_CPUS_PER_CHIP);
		default:
			return (cpuid);
		}
	case CPU_ULTRASPARC_T2:
	case CPU_ULTRASPARC_T2plus:
		switch (level) {
		case CMD_CPU_LEVEL_CORE:
			return (cpuid/UST2_CPUS_PER_CORE);
		case CMD_CPU_LEVEL_CHIP:
			return (cpuid/UST2_CPUS_PER_CHIP);
		default:
			return (cpuid);
		}

#endif /* sun4u */
	default:
		return (cpuid);
	}
}

#ifdef sun4u
static void
cpu_uec_write(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_cpu_uec_t *uec)
{
	/*
	 * The UE cache may change size.  fmd expects statically-sized buffers,
	 * so we must delete and re-create it if the size has changed from the
	 * last time it was written.
	 */
	if (fmd_buf_size(hdl, NULL, uec->uec_bufname) != sizeof (uint64_t) *
	    uec->uec_nent)
		fmd_buf_destroy(hdl, NULL, uec->uec_bufname);

	if (uec->uec_cache != NULL) {
		fmd_buf_write(hdl, NULL, uec->uec_bufname, uec->uec_cache,
		    sizeof (uint64_t) * uec->uec_nent);
	}

	cpu_buf_write(hdl, cpu);
}

static void
cpu_uec_create(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_cpu_uec_t *uec,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cmd_vbufname(uec->uec_bufname, sizeof (uec->uec_bufname), fmt, ap);
	va_end(ap);

	cpu_uec_write(hdl, cpu, uec);
}

static void
cpu_uec_restore(fmd_hdl_t *hdl, cmd_cpu_uec_t *uec)
{
	if (uec->uec_cache != NULL) {
		uec->uec_cache = cmd_buf_read(hdl, NULL, uec->uec_bufname,
		    sizeof (uint64_t) * uec->uec_nent);
	}
}

static void
cpu_uec_free(fmd_hdl_t *hdl, cmd_cpu_uec_t *uec, int destroy)
{
	if (uec->uec_cache == NULL)
		return;

	if (destroy)
		fmd_buf_destroy(hdl, NULL, uec->uec_bufname);

	fmd_hdl_free(hdl, uec->uec_cache, sizeof (uint64_t) * uec->uec_nent);
}

static void
cpu_uec_flush_finish(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	fmd_hdl_debug(hdl, "completing UE cache flush\n");
	if (cpu->cpu_olduec.uec_cache != NULL) {
		fmd_hdl_free(hdl, cpu->cpu_olduec.uec_cache, sizeof (uint64_t) *
		    cpu->cpu_olduec.uec_nent);

		cpu->cpu_olduec.uec_cache = NULL;
		cpu->cpu_olduec.uec_nent = 0;
		cpu->cpu_olduec.uec_flags = 0;
		cpu_uec_write(hdl, cpu, &cpu->cpu_olduec);
	}

	cpu->cpu_uec_flush = 0;
	cpu_buf_write(hdl, cpu);
}

static void
cpu_uec_flush(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	if (cpu->cpu_uec.uec_cache == NULL && !cpu->cpu_uec.uec_flags)
		return; /* nothing to flush */

	fmd_hdl_debug(hdl, "flushing UE cache for CPU %d\n", cpu->cpu_cpuid);

	if (cmd_ecache_flush(cpu->cpu_cpuid) < 0) {
		fmd_hdl_debug(hdl, "failed to flush E$ for CPU %d\n",
		    cpu->cpu_cpuid);
		return; /* don't flush the UE cache unless we can flush E$ */
	}

	if (cpu->cpu_olduec.uec_cache != NULL) {
		/*
		 * If there's already an old UE cache, we're racing with another
		 * flush.  For safety, we'll add the current contents of the
		 * cache to the existing old cache.
		 */
		size_t nent = cpu->cpu_olduec.uec_nent + cpu->cpu_uec.uec_nent;
		uint64_t *new = fmd_hdl_alloc(hdl, sizeof (uint64_t) * nent,
		    FMD_SLEEP);

		bcopy(cpu->cpu_olduec.uec_cache, new,
		    sizeof (uint64_t) * cpu->cpu_olduec.uec_nent);
		bcopy(cpu->cpu_uec.uec_cache, new + cpu->cpu_olduec.uec_nent,
		    sizeof (uint64_t) * cpu->cpu_uec.uec_nent);

		fmd_hdl_free(hdl, cpu->cpu_olduec.uec_cache,
		    sizeof (uint64_t) * cpu->cpu_olduec.uec_nent);
		fmd_hdl_free(hdl, cpu->cpu_uec.uec_cache,
		    sizeof (uint64_t) * cpu->cpu_uec.uec_nent);

		cpu->cpu_olduec.uec_cache = new;
		cpu->cpu_olduec.uec_nent = nent;
		cpu->cpu_olduec.uec_flags |= cpu->cpu_uec.uec_flags;
	} else {
		cpu->cpu_olduec.uec_cache = cpu->cpu_uec.uec_cache;
		cpu->cpu_olduec.uec_nent = cpu->cpu_uec.uec_nent;
		cpu->cpu_olduec.uec_flags = cpu->cpu_uec.uec_flags;
	}
	cpu_uec_write(hdl, cpu, &cpu->cpu_olduec);

	cpu->cpu_uec.uec_cache = NULL;
	cpu->cpu_uec.uec_nent = 0;
	cpu->cpu_uec.uec_flags = 0;
	cpu_uec_write(hdl, cpu, &cpu->cpu_uec);

	if (cpu->cpu_uec_flush != 0)
		fmd_timer_remove(hdl, cpu->cpu_uec_flush);

	cpu->cpu_uec_flush = fmd_timer_install(hdl,
	    (void *)CMD_TIMERTYPE_CPU_UEC_FLUSH, NULL, NANOSEC);
	cpu_buf_write(hdl, cpu);
}

void
cmd_cpu_uec_add(fmd_hdl_t *hdl, cmd_cpu_t *cpu, uint64_t pa)
{
	cmd_cpu_uec_t *uec = &cpu->cpu_uec;
	uint64_t *new, *tgt = NULL;
	int i;

	pa = pa & cmd.cmd_pagemask;

	fmd_hdl_debug(hdl, "adding 0x%llx to CPU %d's UE cache\n",
	    (u_longlong_t)pa, cpu->cpu_cpuid);

	if (uec->uec_cache != NULL) {
		for (tgt = NULL, i = 0; i < uec->uec_nent; i++) {
			if (tgt == NULL && uec->uec_cache[i] == 0)
				tgt = &uec->uec_cache[i];

			if (uec->uec_cache[i] == pa)
				return; /* already there */
		}
	}

	if (tgt == NULL) {
		/* no space - resize the cache */
		new = fmd_hdl_zalloc(hdl, sizeof (uint64_t) *
		    (uec->uec_nent + CMD_CPU_UEC_INCR), FMD_SLEEP);

		if (uec->uec_cache != NULL) {
			bcopy(uec->uec_cache, new, sizeof (uint64_t) *
			    uec->uec_nent);
			fmd_hdl_free(hdl, uec->uec_cache, sizeof (uint64_t) *
			    uec->uec_nent);
		}

		uec->uec_cache = new;
		tgt = &uec->uec_cache[uec->uec_nent];
		uec->uec_nent += CMD_CPU_UEC_INCR;
	}

	*tgt = pa;
	cpu_uec_write(hdl, cpu, uec);
}

void
cmd_cpu_uec_set_allmatch(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	fmd_hdl_debug(hdl, "setting cpu %d's uec to allmatch\n",
	    cpu->cpu_cpuid);

	cpu->cpu_uec.uec_flags |= CPU_UEC_F_ALLMATCH;
	cpu_uec_write(hdl, cpu, &cpu->cpu_uec);

	if (++cpu->cpu_uec_nflushes <= CPU_UEC_FLUSH_MAX)
		cpu_uec_flush(hdl, cpu);
}

int
cmd_cpu_uec_match(cmd_cpu_t *cpu, uint64_t pa)
{
	int i;

	/*
	 * The UE cache works as long as we are able to add an entry for every
	 * UE seen by a given CPU.  If we see a UE with a non-valid AFAR, we
	 * can't guarantee our ability to filter a corresponding xxU, and must,
	 * for safety, assume that every subsequent xxU (until the E$ and UE
	 * cache are flushed) has a matching UE.
	 */
	if ((cpu->cpu_uec.uec_flags & CPU_UEC_F_ALLMATCH) ||
	    (cpu->cpu_olduec.uec_flags & CPU_UEC_F_ALLMATCH))
		return (1);

	pa = pa & cmd.cmd_pagemask;

	for (i = 0; i < cpu->cpu_uec.uec_nent; i++) {
		if (cpu->cpu_uec.uec_cache[i] == pa)
			return (1);
	}

	for (i = 0; i < cpu->cpu_olduec.uec_nent; i++) {
		if (cpu->cpu_olduec.uec_cache[i] == pa)
			return (1);
	}

	return (0);
}
#endif /* sun4u */

void
cmd_xr_write(fmd_hdl_t *hdl, cmd_xr_t *xr)
{
	fmd_hdl_debug(hdl, "writing redelivery clcode %llx for case %s\n",
	    xr->xr_clcode, fmd_case_uuid(hdl, xr->xr_case));

	fmd_buf_write(hdl, xr->xr_case, "redelivery", xr,
	    sizeof (cmd_xr_t));
}

static cmd_xr_hdlr_f *
cmd_xr_id2hdlr(fmd_hdl_t *hdl, uint_t id)
{
	switch (id) {
	case CMD_XR_HDLR_XXC:
		return (cmd_xxc_resolve);
	case CMD_XR_HDLR_XXU:
		return (cmd_xxu_resolve);
	case CMD_XR_HDLR_NOP:
		return (cmd_nop_resolve);
	default:
		fmd_hdl_abort(hdl, "cmd_xr_id2hdlr called with bad hdlrid %x\n",
		    id);
	}

	return (NULL);
}

cmd_xr_t *
cmd_xr_create(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    cmd_cpu_t *cpu, cmd_errcl_t clcode)
{
	cmd_xr_t *xr = fmd_hdl_zalloc(hdl, sizeof (cmd_xr_t),
	    FMD_SLEEP);
	nvlist_t *rsrc = NULL;
	const char *uuid;
	int err = 0;

	err |= nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &xr->xr_ena);

	err |= cmd_xr_fill(hdl, nvl, xr, clcode);
#ifdef sun4u
	err |= cmd_xr_pn_cache_fill(hdl, nvl, xr, cpu, clcode);
#endif
	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
	    &rsrc);

	if (err != 0) {
		fmd_hdl_free(hdl, xr, sizeof (cmd_xr_t));
		return (NULL);
	}

	xr->xr_cpu = cpu;
	xr->xr_cpuid = cpu->cpu_cpuid;
	xr->xr_clcode = clcode;
	xr->xr_case = cmd_case_create(hdl, &cpu->cpu_header,
	    CMD_PTR_CPU_XR_RETRY, &uuid);
	fmd_case_setprincipal(hdl, xr->xr_case, ep);

	if (rsrc != NULL) {
		cmd_fmri_init(hdl, &xr->xr_rsrc, rsrc, "%s_rsrc",
		    fmd_case_uuid(hdl, xr->xr_case));
	}

	cmd_xr_write(hdl, xr);
	return (xr);
}

cmd_evdisp_t
cmd_xr_reschedule(fmd_hdl_t *hdl, cmd_xr_t *xr, uint_t hdlrid)
{

	fmd_hdl_debug(hdl, "scheduling redelivery of %llx with xr %p\n",
	    xr->xr_clcode, xr);

	xr->xr_hdlrid = hdlrid;
	xr->xr_hdlr = cmd_xr_id2hdlr(hdl, hdlrid);

	xr->xr_id = fmd_timer_install(hdl, (void *)CMD_TIMERTYPE_CPU_XR_WAITER,
	    NULL, cmd.cmd_xxcu_trdelay);

	if (xr->xr_ref++ == 0)
		cmd_list_append(&cmd.cmd_xxcu_redelivs, xr);

	cmd_xr_write(hdl, xr);
	return (CMD_EVD_OK);
}

static void
cmd_xr_destroy(fmd_hdl_t *hdl, cmd_xr_t *xr)
{
	fmd_hdl_debug(hdl, "destroying xr (clcode %llx) at %p\n",
	    xr->xr_clcode, xr);

	fmd_case_reset(hdl, xr->xr_case);
	cmd_case_fini(hdl, xr->xr_case, FMD_B_TRUE);

	if (xr->xr_rsrc_nvl != NULL)
		cmd_fmri_fini(hdl, &xr->xr_rsrc, FMD_B_TRUE);

	fmd_buf_destroy(hdl, xr->xr_case, "redelivery");
	fmd_hdl_free(hdl, xr, sizeof (cmd_xr_t));
}

void
cmd_xr_deref(fmd_hdl_t *hdl, cmd_xr_t *xr)
{
	if (xr->xr_ref == 0)
		fmd_hdl_abort(hdl, "attempt to deref xr with zero ref\n");

	fmd_hdl_debug(hdl, "deref xr %p [%d]\n", xr, xr->xr_ref);

	if (--xr->xr_ref == 0) {
		cmd_list_delete(&cmd.cmd_xxcu_redelivs, xr);
		cmd_xr_destroy(hdl, xr);
	}
}

static void
cmd_xr_restore(fmd_hdl_t *hdl, cmd_cpu_t *cpu, fmd_case_t *cp)
{
	cmd_xr_t *xr;

	if ((xr = cmd_buf_read(hdl, cp, "redelivery", sizeof (cmd_xr_t))) ==
	    NULL) {
		fmd_hdl_abort(hdl, "failed to find redelivery for case %s\n",
		    fmd_case_uuid(hdl, cp));
	}

	xr->xr_case = cp;
	xr->xr_hdlr = cmd_xr_id2hdlr(hdl, xr->xr_hdlrid);
	if (xr->xr_rsrc_nvl != NULL)
		cmd_fmri_restore(hdl, &xr->xr_rsrc);
	xr->xr_cpu = cpu;

	/*
	 * fmd is still in the process of starting up.  If we reschedule this
	 * event with the normal redelivery timeout, it'll get redelivered
	 * before initialization has completed, we'll potentially fail to
	 * match the train, deref() the waiter (causing any subsequent side-
	 * effects to miss the waiter), and use this ereport to blame the CPU.
	 * The other side-effects will blame the CPU too, since we'll have
	 * deref()'d the waiter out of existence.  We can get up to three
	 * additions to the SERD engine this way, which is bad.  To keep that
	 * from happening, we're going to schedule an arbitrarily long timeout,
	 * which *should* be long enough.  It's pretty bad, but there's no
	 * real way to keep the other side-effects from taking out the CPU.
	 */
	xr->xr_id = fmd_timer_install(hdl, (void *)CMD_TIMERTYPE_CPU_XR_WAITER,
	    NULL, fmd_prop_get_int64(hdl, "xxcu_restart_delay"));

	cmd_list_append(&cmd.cmd_xxcu_redelivs, xr);

	fmd_hdl_debug(hdl, "revived xr for class %llx\n", xr->xr_clcode);
}

typedef struct cmd_xxcu_train {
	cmd_errcl_t tr_mask;	/* errors we must see to match this train */
	cmd_errcl_t tr_cause;	/* the error at the root of this train */
} cmd_xxcu_train_t;

#define	CMD_TRAIN(cause, side_effects)	{ (cause) | (side_effects), (cause) }

static const cmd_xxcu_train_t cmd_xxcu_trains[] = {
#ifdef sun4u
	/* UCC: WDC */
	CMD_TRAIN(CMD_ERRCL_UCC,	CMD_ERRCL_WDC),

	/* UCU: WDU, WDU+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_UCU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_UCU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),

	/* EDC: WDC */
	CMD_TRAIN(CMD_ERRCL_EDC,	CMD_ERRCL_WDC),

	/* EDU: WDU, WDU+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_EDU_ST,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_BL,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_ST,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_BL,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),

	/* CPC: WDC, EDC+WDC, UCC+WDC, EDC+UCC+WDC */
	CMD_TRAIN(CMD_ERRCL_CPC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_CPC,	CMD_ERRCL_EDC | CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_CPC,	CMD_ERRCL_UCC | CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_CPC,	CMD_ERRCL_EDC | CMD_ERRCL_UCC |
	    CMD_ERRCL_WDC),

	/* CPU: WDU, WDU+L3_WDU, UCU+WDU, UCU+WDU+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_UCU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU |
	    CMD_ERRCL_WDU),

	/* CPU: EDU+WDU, EDU+WDU+L3_WDU, EDU+UCU+WDU,  EDU+UCU+WDU+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_BL | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU |
	    CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU |
	    CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU |
	    CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU |
	    CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),

	/* WDU: L3_WDU */
	CMD_TRAIN(CMD_ERRCL_WDU,	CMD_ERRCL_L3_WDU),

	/* L3_UCC: WDC+(zero or more of EDC, CPC, UCC) */
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_CPC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_CPC | CMD_ERRCL_UCC),

	/* L3_UCU: WDU+(zero or more of EDU, CPU, UCU) */
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),

	/* L3_UCU: WDU+(zero or more of EDU, CPU, UCU)+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),

	/* L3_EDC: WDC+(zero or more of EDC, CPC, UCC) */
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_CPC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC | CMD_ERRCL_EDC |
	    CMD_ERRCL_CPC | CMD_ERRCL_UCC),

	/* L3_EDU: WDU+(zero or more of EDU, CPU, UCU) */
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),

	/* L3_EDU: WDU+(zero or more of EDU, CPU, UCU)+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),

	/* L3_CPC: L3_WDC */
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_WDC),

	/* L3_CPC: L3_EDC+ WDC+(zero or more of EDC, CPC, UCC) */
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_CPC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_EDC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_CPC | CMD_ERRCL_UCC),

	/* L3_CPC: L3_UCC+WDC+(zero or more of EDC, CPC, UCC) */
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_CPC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_CPC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_UCC | CMD_ERRCL_WDC |
	    CMD_ERRCL_EDC | CMD_ERRCL_CPC | CMD_ERRCL_UCC),

	/* L3_CPU: L3_WDU */
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_WDU),

	/* L3_CPU: L3_EDU+WDU+(zero or more of EDU, CPU, UCU) */
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),

	/* L3_CPU: L3_UCU+WDU+(zero or more of EDU, CPU, UCU) */
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST |CMD_ERRCL_EDU_BL),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU),

	/* L3_CPU: L3_EDU+WDU+(zero or more of EDU, CPU, UCU)+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_BL |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_EDU_ST |
	    CMD_ERRCL_L3_EDU_BL | CMD_ERRCL_WDU | CMD_ERRCL_EDU_ST |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),

	/* L3_CPU: L3_UCU+WDU+(zero or more of EDU, CPU, UCU)+L3_WDU */
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU
	    | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST |CMD_ERRCL_EDU_BL | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_CPU | CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU | CMD_ERRCL_UCU |
	    CMD_ERRCL_L3_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_UCU | CMD_ERRCL_WDU |
	    CMD_ERRCL_EDU_ST | CMD_ERRCL_EDU_BL | CMD_ERRCL_CPU |
	    CMD_ERRCL_UCU | CMD_ERRCL_L3_WDU),
#else /* sun4u */
	CMD_TRAIN(CMD_ERRCL_LDAC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDRC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDSC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_CBCE,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDAU,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_LDAU,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_LDAU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_LDRU,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_LDRU,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_LDRU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_LDSU,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_LDSU,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_LDSU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_SBDLC,	CMD_ERRCL_SBDPC),
	CMD_TRAIN(CMD_ERRCL_TCCP,	CMD_ERRCL_TCCD),
	CMD_TRAIN(CMD_ERRCL_TCCD,	CMD_ERRCL_TCCD),
	CMD_TRAIN(CMD_ERRCL_DBU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_DBU,	CMD_ERRCL_ICDP),
	CMD_TRAIN(CMD_ERRCL_FBU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_FBU,	CMD_ERRCL_ICDP),
	CMD_TRAIN(CMD_ERRCL_DAU,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_DAU,	CMD_ERRCL_ICDP),
	/*
	 * sun4v also has the following trains, but the train
	 * algorithm does an exhaustive search and compare
	 * all pairs in the train mask, so we don't need
	 * to define these trains
	 *		dl2nd->ldwu (wbue), dcdp
	 *		il2nd->ldwu (wbue), icdp
	 *		dxl2u->ldwu (wbue), dcdp
	 *		ixl2u->ldwu (wbue), icdp
	 */
	CMD_TRAIN(CMD_ERRCL_DL2ND,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_DL2ND,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_DL2ND,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_IL2ND,	CMD_ERRCL_ICDP),
	CMD_TRAIN(CMD_ERRCL_IL2ND,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_IL2ND,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_L2ND,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_L2ND,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_DL2U,	CMD_ERRCL_DCDP),
	CMD_TRAIN(CMD_ERRCL_DL2U,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_DL2U,	CMD_ERRCL_WBUE),
	CMD_TRAIN(CMD_ERRCL_IL2U,	CMD_ERRCL_ICDP),
	CMD_TRAIN(CMD_ERRCL_IL2U,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_IL2U,	CMD_ERRCL_WBUE),
#endif /* sun4u */
	CMD_TRAIN(0, 0)
};

cmd_errcl_t
cmd_xxcu_train_match(cmd_errcl_t mask)
{
	int i;

	for (i = 0; cmd_xxcu_trains[i].tr_mask != 0; i++) {
		if (cmd_xxcu_trains[i].tr_mask == mask)
			return (cmd_xxcu_trains[i].tr_cause);
	}

	return (0);
}

cmd_xxcu_trw_t *
cmd_trw_alloc(uint64_t ena, uint64_t afar)
{
	int i;

	for (i = 0; i < cmd.cmd_xxcu_ntrw; i++) {
		cmd_xxcu_trw_t *trw = &cmd.cmd_xxcu_trw[i];
		if (trw->trw_ena == NULL) {
			trw->trw_ena = ena;
			trw->trw_afar = afar;
			return (trw);
		}
	}

	return (NULL);
}

void
cmd_trw_write(fmd_hdl_t *hdl)
{
	fmd_buf_write(hdl, NULL, "waiters", cmd.cmd_xxcu_trw,
	    cmd.cmd_xxcu_ntrw * sizeof (cmd_xxcu_trw_t));
}

/*ARGSUSED*/
void
cmd_trw_ref(fmd_hdl_t *hdl, cmd_xxcu_trw_t *trw, cmd_errcl_t clcode)
{
	trw->trw_ref++;
	trw->trw_mask |= clcode;
	cmd_trw_write(hdl);
}

void
cmd_trw_deref(fmd_hdl_t *hdl, cmd_xxcu_trw_t *trw)
{
	if (trw->trw_ref == 0)
		fmd_hdl_abort(hdl, "attempt to deref trw with zero ref\n");

	if (--trw->trw_ref == 0)
		bzero(trw, sizeof (cmd_xxcu_trw_t));

	cmd_trw_write(hdl);
}

void
cmd_trw_restore(fmd_hdl_t *hdl)
{
	size_t sz = fmd_buf_size(hdl, NULL, "waiters");
	if (sz == cmd.cmd_xxcu_ntrw * sizeof (cmd_xxcu_trw_t)) {
		/*
		 * Previous size == current size.  In absence of
		 * versioning, assume that the structure and # of elements
		 * have not changed.
		 */
		fmd_buf_read(hdl, NULL, "waiters", cmd.cmd_xxcu_trw,
		    cmd.cmd_xxcu_ntrw * sizeof (cmd_xxcu_trw_t));
	} else {
		/*
		 * Previous size != current size.  Something has changed;
		 * hence we cannot rely on the contents of this buffer.
		 * Delete the buffer and start fresh.
		 */
		fmd_buf_destroy(hdl, NULL, "waiters");
		fmd_buf_write(hdl, NULL, "waiters", cmd.cmd_xxcu_trw,
		    cmd.cmd_xxcu_ntrw * sizeof (cmd_xxcu_trw_t));
	}
}

char *
cmd_cpu_serdnm_create(fmd_hdl_t *hdl, cmd_cpu_t *cpu, const char *serdbase)
{
	char *nm;
	const char *fmt;
	size_t sz;
	if (cpu->cpu_level == CMD_CPU_LEVEL_THREAD) {
		fmt = "cpu_%d_%s_serd";
		sz = snprintf(NULL, 0, fmt, cpu->cpu_cpuid, serdbase) + 1;
		nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
		(void) snprintf(nm, sz, fmt, cpu->cpu_cpuid, serdbase);
	} else {
		fmt = "cpu_%d_%d_%s_serd";
		sz = snprintf(NULL, 0, fmt, cpu->cpu_cpuid, cpu->cpu_level,
		    serdbase) + 1;
		nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
		(void) snprintf(nm, sz, fmt, cpu->cpu_cpuid, cpu->cpu_level,
		    serdbase);
	}

	return (nm);
}

/*
 * cmd_cpu_create_faultlist is a combination of the former cmd_cpu_create_fault
 * and fmd_case_add_suspect.  If a 'cpu' structure represents a set of threads
 * (level > CMD_CPU_LEVEL_THREAD), then we must add multiple faults to
 * this case, under loop control.  Use call to cmd_cpu_create_faultlist to
 * replace the sequence
 *
 *	flt = cmd_cpu_create_fault(...);
 *	fmd_case_add_suspect(hdl, cc->cp, flt);
 */

void
cmd_cpu_create_faultlist(fmd_hdl_t *hdl, fmd_case_t *casep, cmd_cpu_t *cpu,
    const char *type, nvlist_t *rsrc, uint_t cert)
{
	char fltnm[64];
	uint32_t cpuinit, cpufinal, cpustep, i;
	nvlist_t *flt;
#ifdef sun4v
	char *loc;
	nvlist_t *mb_rsrc;
#endif

	(void) snprintf(fltnm, sizeof (fltnm), "fault.cpu.%s.%s",
	    cmd_cpu_type2name(hdl, cpu->cpu_type), type);

	cpu->cpu_faulting = FMD_B_TRUE;
	cpu_buf_write(hdl, cpu);
#ifdef sun4v

	loc = cmd_getfru_loc(hdl, cpu->cpu_asru_nvl);

	/*
	 * Add motherboard fault to t5440 lfu suspect.list.
	 */
	if ((strstr(loc, CPUBOARD) != NULL) && (strstr(fltnm, "lfu") != NULL)) {
		/* get mb fmri from libtopo */
		mb_rsrc = init_mb(hdl);
		if (mb_rsrc != NULL) {
			fmd_hdl_debug(hdl, "cmd_cpu: create MB fault\n");
			cert = BK_LFUFAULT_CERT;
			flt = cmd_boardfru_create_fault(hdl, mb_rsrc, fltnm,
			    cert, "MB");
			fmd_case_add_suspect(hdl, casep, flt);
			nvlist_free(mb_rsrc);
		}
	}
#endif

	if (cpu->cpu_level > CMD_CPU_LEVEL_THREAD) {
		core2cpus(cpu->cpu_cpuid, cpu->cpu_type, cpu->cpu_level,
		    &cpuinit, &cpufinal, &cpustep);
		for (i = cpuinit; i <= cpufinal; i += cpustep) {
			cmd_cpu_t *cpui = cpu_lookup_by_cpuid(i,
			    CMD_CPU_LEVEL_THREAD);
			if (cpui == NULL) {
				nvlist_t *asru;
				if (nvlist_dup(cpu->cpu_asru_nvl,
				    &asru, 0) != 0) {
					fmd_hdl_abort(hdl, "unable to alloc"
					    "ASRU for thread in core\n");
				}
				(void) nvlist_remove_all(asru,
				    FM_FMRI_CPU_ID);
				if (nvlist_add_uint32(asru,
				    FM_FMRI_CPU_ID, i) != 0) {
					fmd_hdl_abort(hdl,
					    "unable to create thread struct\n");
				}
				cpui = cpu_create(hdl, asru, i,
				    CMD_CPU_LEVEL_THREAD, cpu->cpu_type);
				nvlist_free(asru);
			}
			if (!fmd_nvl_fmri_present(hdl, cpui->cpu_asru_nvl))
				continue;
			cpui->cpu_faulting = FMD_B_TRUE;
			cpu_buf_write(hdl, cpui);
			flt = cmd_nvl_create_fault(hdl, fltnm, cert,
			    cpui->cpu_asru_nvl, cpu->cpu_fru_nvl, rsrc);
#ifdef sun4v
			flt = cmd_fault_add_location(hdl, flt, loc);
#endif /* sun4v */
			fmd_case_add_suspect(hdl, casep, flt);
		}
	} else {
		flt = cmd_nvl_create_fault(hdl, fltnm, cert,
		    cpu->cpu_asru_nvl, cpu->cpu_fru_nvl, rsrc);
#ifdef sun4v
		flt = cmd_fault_add_location(hdl, flt, loc);

#endif /* sun4v */
		fmd_case_add_suspect(hdl, casep, flt);
	}
#ifdef sun4v
	if (loc != NULL)
		fmd_hdl_strfree(hdl, loc);
#endif
}

static void
cmd_cpu_free(fmd_hdl_t *hdl, cmd_cpu_t *cpu, int destroy)
{
	int i;
#ifdef sun4u
	cmd_Lxcache_t *Lxcache;
#endif

	for (i = 0; i < sizeof (cmd_cpu_cases_t) / sizeof (cmd_case_t); i++) {
		cmd_case_t *cc = &(((cmd_case_t *)&cpu->cpu_cases)[i]);

		if (cc->cc_cp != NULL) {
			cmd_case_fini(hdl, cc->cc_cp, destroy);
			if (cc->cc_serdnm != NULL) {
				if (fmd_serd_exists(hdl, cc->cc_serdnm) &&
				    destroy)
					fmd_serd_destroy(hdl, cc->cc_serdnm);
				fmd_hdl_strfree(hdl, cc->cc_serdnm);
			}
		}
	}

#ifdef sun4u
	/*
	 * free Lxcache also.
	 */

	for (Lxcache = cmd_list_next(&cpu->cpu_Lxcaches); Lxcache != NULL;
	    Lxcache = cmd_list_next(&cpu->cpu_Lxcaches)) {
		(void) cmd_Lxcache_free(hdl, cpu, Lxcache, destroy);
	}
	cpu_uec_free(hdl, &cpu->cpu_uec, destroy);
	cpu_uec_free(hdl, &cpu->cpu_olduec, destroy);
#endif /* sun4u */

	cmd_fmri_fini(hdl, &cpu->cpu_asru, destroy);
	cmd_fmri_fini(hdl, &cpu->cpu_fru, destroy);

	cmd_list_delete(&cmd.cmd_cpus, cpu);

	if (destroy)
		fmd_buf_destroy(hdl, NULL, cpu->cpu_bufname);
	fmd_hdl_free(hdl, cpu, sizeof (cmd_cpu_t));
}

void
cmd_cpu_destroy(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	cmd_cpu_free(hdl, cpu, FMD_B_TRUE);
}

static cmd_cpu_t *
cpu_lookup_by_cpuid(uint32_t cpuid, uint8_t level)
{
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if ((cpu->cpu_cpuid == cpuid) &&
		    (cpu->cpu_level == level))
			return (cpu);
	}

	return (NULL);
}

static nvlist_t *
cpu_getfru(fmd_hdl_t *hdl, cmd_cpu_t *cp)
{
	char *frustr, *partstr, *serialstr;
	nvlist_t *nvlp;

	if ((frustr = cmd_cpu_getfrustr(hdl, cp)) == NULL) {
		return (NULL);
	}
	partstr = cmd_cpu_getpartstr(hdl, cp);
	serialstr = cmd_cpu_getserialstr(hdl, cp);
	nvlp = cmd_cpu_mkfru(hdl, frustr, serialstr, partstr);
	fmd_hdl_strfree(hdl, frustr);
	fmd_hdl_strfree(hdl, partstr);
	fmd_hdl_strfree(hdl, serialstr);

	return (nvlp);
}

static void
cpu_buf_write(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	if (fmd_buf_size(hdl, NULL, cpu->cpu_bufname) !=
	    sizeof (cmd_cpu_pers_t))
		fmd_buf_destroy(hdl, NULL, cpu->cpu_bufname);

	fmd_buf_write(hdl, NULL, cpu->cpu_bufname, &cpu->cpu_pers,
	    sizeof (cmd_cpu_pers_t));
}

static void
cpu_buf_create(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	size_t sz;

	/*
	 * We need to be tolerant of leaked CPU buffers, as their effects can
	 * be severe.  Consider the following scenario: we create a version 0
	 * cmd_cpu_t in response to some error, commit it to a persistent
	 * buffer, and then leak it.  We then upgrade, and restart the DE using
	 * version 1 cmd_cpu_t's.  Another error comes along, for the same CPU
	 * whose struct was leaked.  Not knowing about the leaked buffer, we
	 * create a new cmd_cpu_t for that CPU, and create a buffer for it.  As
	 * the v1 cmd_cpu_t is smaller than the v0 cmd_cpu_t, fmd will use the
	 * pre-existing (leaked) buffer.  We'll therefore have an x-byte, v1
	 * cmd_cpu_t in a y-byte buffer, where y > x.  Upon the next DE restart,
	 * we'll attempt to restore the cmd_cpu_t, but will do version
	 * validation using the size of the buffer (y).  This won't match what
	 * we're expecting (x), and the DE will abort.
	 *
	 * To protect against such a scenario, we're going to check for and
	 * remove the pre-existing cmd_cpu_t for this CPU, if one exists.  While
	 * this won't fix the leak, it'll allow us to continue functioning
	 * properly in spite of it.
	 */
	if ((sz = fmd_buf_size(hdl, NULL, cpu->cpu_bufname)) != 0 &&
	    sz != sizeof (cmd_cpu_pers_t)) {
		fmd_hdl_debug(hdl, "removing unexpected pre-existing cpu "
		    "buffer %s (size %u bytes)\n", cpu->cpu_bufname, sz);
		fmd_buf_destroy(hdl, NULL, cpu->cpu_bufname);
	}

	cpu_buf_write(hdl, cpu);
}

static cmd_cpu_t *
cpu_create(fmd_hdl_t *hdl, nvlist_t *asru, uint32_t cpuid, uint8_t level,
    cmd_cpu_type_t type)
{
	cmd_cpu_t *cpu;
	nvlist_t *fru;

	/*
	 * No CPU state matches the CPU described in the ereport.  Create a new
	 * one, add it to the list, and pass it back.
	 */
	fmd_hdl_debug(hdl, "cpu_lookup: creating new cpuid %u\n", cpuid);
	CMD_STAT_BUMP(cpu_creat);

	cpu = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);
	cpu->cpu_nodetype = CMD_NT_CPU;
	cpu->cpu_cpuid = cpuid;
	cpu->cpu_level = level;
	cpu->cpu_type = type;
	cpu->cpu_version = CMD_CPU_VERSION;

	if (cpu->cpu_level == CMD_CPU_LEVEL_THREAD) {
		cmd_bufname(cpu->cpu_bufname, sizeof (cpu->cpu_bufname),
		    "cpu_%d", cpu->cpu_cpuid);
	} else {
		cmd_bufname(cpu->cpu_bufname, sizeof (cpu->cpu_bufname),
		    "cpu_%d_%d", cpu->cpu_cpuid, cpu->cpu_level);
	}

#ifdef sun4u
	cpu_uec_create(hdl, cpu, &cpu->cpu_uec, "cpu_uec_%d", cpu->cpu_cpuid);
	cpu_uec_create(hdl, cpu, &cpu->cpu_olduec, "cpu_olduec_%d",
	    cpu->cpu_cpuid);
#endif /* sun4u */

	if (cpu->cpu_level == CMD_CPU_LEVEL_THREAD) {
		cmd_fmri_init(hdl, &cpu->cpu_asru, asru, "cpu_asru_%d",
		    cpu->cpu_cpuid);
	} else {
		cmd_fmri_init(hdl, &cpu->cpu_asru, asru, "cpu_asru_%d_%d",
		    cpu->cpu_cpuid, cpu->cpu_level);
	}

	if ((fru = cpu_getfru(hdl, cpu)) != NULL) {
		if (cpu->cpu_level == CMD_CPU_LEVEL_THREAD) {
			cmd_fmri_init(hdl, &cpu->cpu_fru, fru, "cpu_fru_%d",
			    cpu->cpu_cpuid);
		} else {
			cmd_fmri_init(hdl, &cpu->cpu_fru, fru, "cpu_fru_%d_%d",
			    cpu->cpu_cpuid, cpu->cpu_level);
		}
		nvlist_free(fru);
	} else {
		if (cpu->cpu_level == CMD_CPU_LEVEL_THREAD) {
			cmd_fmri_init(hdl, &cpu->cpu_fru, asru, "cpu_fru_%d",
			    cpu->cpu_cpuid);
		} else {
			cmd_fmri_init(hdl, &cpu->cpu_fru, asru, "cpu_fru_%d_%d",
			    cpu->cpu_cpuid, cpu->cpu_level);
		}
	}

	cpu_buf_create(hdl, cpu);

	cmd_list_append(&cmd.cmd_cpus, cpu);

	return (cpu);
}

/*
 * As its name implies, 'cpu_all_threads_invalid' determines if all cpu
 * threads (level 0) contained within the cpu structure are invalid.
 * This is done by checking all the (level 0) threads which may be
 * contained within this chip, core, or thread; if all are invalid, return
 * FMD_B_TRUE; if any are valid, return FMD_B_FALSE.
 */

int
cpu_all_threads_invalid(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	nvlist_t *asru;
	uint32_t cpuinit, cpufinal, cpustep, i;

	core2cpus(cpu->cpu_cpuid, cpu->cpu_type, cpu->cpu_level,
	    &cpuinit, &cpufinal, &cpustep);

	if (cpuinit == cpufinal) {
		if (fmd_nvl_fmri_present(hdl, cpu->cpu_asru_nvl) &&
		    !fmd_nvl_fmri_unusable(hdl, cpu->cpu_asru_nvl))
			return (FMD_B_FALSE);
		else return (FMD_B_TRUE);
	} else {

		if (nvlist_dup(cpu->cpu_asru_nvl, &asru, 0) != 0)
			fmd_hdl_abort(hdl, "cannot copy asru\n");
		for (i = cpuinit; i <= cpufinal; i += cpustep) {
			(void) nvlist_remove_all(asru, FM_FMRI_CPU_ID);
			if (nvlist_add_uint32(asru, FM_FMRI_CPU_ID, i) != 0) {
				fmd_hdl_abort(hdl, "cpu_all_threads_invalid: ",
				    "cannot add thread %d to asru\n", i);
			}
			if (fmd_nvl_fmri_present(hdl, asru) &&
			    !fmd_nvl_fmri_unusable(hdl, asru)) {
				nvlist_free(asru);
				return (FMD_B_FALSE);
			}
		}
	}
	nvlist_free(asru);
	return (FMD_B_TRUE);
}

/*
 * Locate the state structure for this CPU, creating a new one if one doesn't
 * already exist.  Before passing it back, we also need to validate it against
 * the current state of the world, checking to ensure that the CPU described by
 * the ereport, the CPU indicated in the cmd_cpu_t, and the CPU currently
 * residing at the indicated cpuid are the same.  We do this by comparing the
 * serial IDs from the three entities.
 */
cmd_cpu_t *
cmd_cpu_lookup(fmd_hdl_t *hdl, nvlist_t *asru, const char *class,
    uint8_t level)
{
	cmd_cpu_t *cpu;
	uint8_t vers;
	const char *scheme, *cpuname;
	uint32_t cpuid;
	cmd_cpu_type_t ct;

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		CMD_STAT_BUMP(bad_cpu_asru);
		return (NULL);
	}

	if (nvlist_lookup_pairs(asru, 0,
	    FM_VERSION, DATA_TYPE_UINT8, &vers,
	    FM_FMRI_SCHEME, DATA_TYPE_STRING, &scheme,
	    FM_FMRI_CPU_ID, DATA_TYPE_UINT32, &cpuid,
	    NULL) != 0 || (vers != CPU_SCHEME_VERSION0 &&
	    vers != CPU_SCHEME_VERSION1) ||
	    strcmp(scheme, FM_FMRI_SCHEME_CPU) != 0) {
		CMD_STAT_BUMP(bad_cpu_asru);
		return (NULL);
	}

	/*
	 * 'cpuid' at this point refers to a thread, because it
	 * was extracted from a detector FMRI
	 */

	cpuname = class + sizeof ("ereport.cpu");
	ct = cpu_nname2type(hdl, cpuname,
	    (size_t)(strchr(cpuname, '.') - cpuname));

	cpu = cpu_lookup_by_cpuid(cmd_cpu2core(cpuid, ct, level), level);

	if (cpu != NULL &&
	    cpu_all_threads_invalid(hdl, cpu) == FMD_B_TRUE) {
		fmd_hdl_debug(hdl, "cpu_lookup: discarding old state\n");
		cmd_cpu_destroy(hdl, cpu);
		cpu = NULL;
	}

	/*
	 * Check to see if the CPU described by the ereport has been removed
	 * from the system.  If it has, return to the caller without a CPU.
	 */
	if (!fmd_nvl_fmri_present(hdl, asru) ||
	    fmd_nvl_fmri_unusable(hdl, asru)) {
		fmd_hdl_debug(hdl, "cpu_lookup: discarding old ereport\n");
		return (NULL);
	}

	if (cpu == NULL) {
		cpu = cpu_create(hdl, asru,
		    cmd_cpu2core(cpuid, ct, level), level, ct);
	}

	return (cpu);
}

cmd_cpu_t *
cmd_cpu_lookup_from_detector(fmd_hdl_t *hdl, nvlist_t *nvl, const char *class,
    uint8_t level)
{
	nvlist_t *det;

	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det);

	return (cmd_cpu_lookup(hdl, det, class, level));
}

static cmd_cpu_t *
cpu_v0tov3(fmd_hdl_t *hdl, cmd_cpu_0_t *old, size_t oldsz)
{
	cmd_cpu_t *new;

	if (oldsz != sizeof (cmd_cpu_0_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (cmd_cpu_0_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);
	new->cpu_header = old->cpu0_header;
	new->cpu_version = CMD_CPU_VERSION;
	new->cpu_cpuid = old->cpu0_cpuid;
	new->cpu_type = old->cpu0_type;
	new->cpu_faulting = old->cpu0_faulting;
	new->cpu_level = CMD_CPU_LEVEL_THREAD;
	new->cpu_asru = old->cpu0_asru;
	new->cpu_fru = old->cpu0_fru;
	new->cpu_uec = old->cpu0_uec;
	new->cpu_olduec = old->cpu0_olduec;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_cpu_t *
cpu_v1tov3(fmd_hdl_t *hdl, cmd_cpu_1_t *old, size_t oldsz)
{
	cmd_cpu_t *new;

	if (oldsz != sizeof (cmd_cpu_1_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 1 state (%u bytes).\n", sizeof (cmd_cpu_1_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);
	new->cpu_header = old->cpu1_header;
	new->cpu_version = CMD_CPU_VERSION;
	new->cpu_cpuid = old->cpu1_cpuid;
	new->cpu_type = old->cpu1_type;
	new->cpu_faulting = old->cpu1_faulting;
	new->cpu_level = CMD_CPU_LEVEL_THREAD;
	new->cpu_asru = old->cpu1_asru;
	new->cpu_fru = old->cpu1_fru;
	new->cpu_uec = old->cpu1_uec;
	new->cpu_olduec = old->cpu1_olduec;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_cpu_t *
cpu_v2tov3(fmd_hdl_t *hdl, cmd_cpu_2_t *old, size_t oldsz)
{
	cmd_cpu_t *new;

	if (oldsz != sizeof (cmd_cpu_2_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 2 state (%u bytes).\n", sizeof (cmd_cpu_2_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);

	new->cpu_header = old->cpu2_header;
	new->cpu_cpuid = old->cpu2_cpuid;
	new->cpu_type = old->cpu2_type;
	new->cpu_faulting = old->cpu2_faulting;
	new->cpu_asru = old->cpu2_asru;
	new->cpu_fru = old->cpu2_fru;
	new->cpu_uec = old->cpu2_uec;
	new->cpu_olduec = old->cpu2_olduec;
	new->cpu_version = CMD_CPU_VERSION;
	new->cpu_level = CMD_CPU_LEVEL_THREAD;
	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_cpu_t *
cpu_wrapv3(fmd_hdl_t *hdl, cmd_cpu_pers_t *pers, size_t psz)
{
	cmd_cpu_t *cpu;

	if (psz != sizeof (cmd_cpu_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 3 state (%u bytes).\n", sizeof (cmd_cpu_pers_t));
	}

	cpu = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);
	bcopy(pers, cpu, sizeof (cmd_cpu_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (cpu);
}

static void
cpu_case_restore(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_case_t *cc, fmd_case_t *cp,
    const char *serdbase)
{
	cmd_case_restore(hdl, cc, cp, cmd_cpu_serdnm_create(hdl, cpu,
	    serdbase));
}

cmd_cpu_t *
cmd_restore_cpu_only(fmd_hdl_t *hdl, fmd_case_t *cp, char *cpu_hdr_bufname)
{
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (strcmp(cpu->cpu_bufname, cpu_hdr_bufname) == 0)
			break;
	}

	if (cpu == NULL) {
		int migrated = 0;
		size_t cpusz;

		fmd_hdl_debug(hdl, "restoring cpu from %s\n", cpu_hdr_bufname);

		if ((cpusz = fmd_buf_size(hdl, NULL, cpu_hdr_bufname)) == 0) {
			if (fmd_case_solved(hdl, cp) ||
			    fmd_case_closed(hdl, cp)) {
				fmd_hdl_debug(hdl, "cpu buffer %s from case %s "
				    "not found. Case is already solved or "
				    "closed\n",
				    cpu_hdr_bufname, fmd_case_uuid(hdl, cp));
				return (NULL);
			} else {
				fmd_hdl_abort(hdl, "cpu referenced by case %s "
				    "does not exist in saved state\n",
				    fmd_case_uuid(hdl, cp));
			}
		} else if (cpusz > CMD_CPU_MAXSIZE || cpusz < CMD_CPU_MINSIZE) {
			fmd_hdl_abort(hdl, "cpu buffer referenced by case %s "
			    "is out of bounds (is %u bytes)\n",
			    fmd_case_uuid(hdl, cp), cpusz);
		}

		if ((cpu = cmd_buf_read(hdl, NULL, cpu_hdr_bufname,
		    cpusz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read buf %s",
			    cpu_hdr_bufname);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    cpu->cpu_version);

		if (CMD_CPU_VERSIONED(cpu)) {
			switch (cpu->cpu_version) {
			case CMD_CPU_VERSION_1:
				cpu = cpu_v1tov3(hdl, (cmd_cpu_1_t *)cpu,
				    cpusz);
				migrated = 1;
				break;
			case CMD_CPU_VERSION_2:
				cpu = cpu_v2tov3(hdl, (cmd_cpu_2_t *)cpu,
				    cpusz);
				migrated = 1;
				break;
			case CMD_CPU_VERSION_3:
				cpu = cpu_wrapv3(hdl, (cmd_cpu_pers_t *)cpu,
				    cpusz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				    "for cpu state referenced by case %s.\n",
				    cpu->cpu_version, fmd_case_uuid(hdl, cp));
				break;
			}
		} else {
			cpu = cpu_v0tov3(hdl, (cmd_cpu_0_t *)cpu, cpusz);
			migrated = 1;
		}

		if (migrated) {
			CMD_STAT_BUMP(cpu_migrat);
			cpu_buf_write(hdl, cpu);
		}

		cmd_fmri_restore(hdl, &cpu->cpu_asru);
		cmd_fmri_restore(hdl, &cpu->cpu_fru);
#ifdef sun4u
		cpu_uec_restore(hdl, &cpu->cpu_uec);
		cpu_uec_restore(hdl, &cpu->cpu_olduec);

		if (cpu->cpu_uec.uec_cache != NULL)
			cpu_uec_flush(hdl, cpu);
#endif /* sun4u */
		bzero(&cpu->cpu_xxu_retries, sizeof (cmd_list_t));

		cmd_list_append(&cmd.cmd_cpus, cpu);
	}
	return (cpu);
}

void *
cmd_cpu_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_cpu_t *cpu;

	cpu = cmd_restore_cpu_only(hdl, cp, ptr->ptr_name);
	if (cpu == NULL)
		return (NULL);

	switch (ptr->ptr_subtype) {
	case CMD_PTR_CPU_ICACHE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_icache, cp, "icache");
		break;
	case CMD_PTR_CPU_DCACHE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_dcache, cp, "dcache");
		break;
	case CMD_PTR_CPU_PCACHE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_pcache, cp, "pcache");
		break;
	case CMD_PTR_CPU_ITLB:
		cpu_case_restore(hdl, cpu, &cpu->cpu_itlb, cp, "itlb");
		break;
	case CMD_PTR_CPU_DTLB:
		cpu_case_restore(hdl, cpu, &cpu->cpu_dtlb, cp, "dtlb");
		break;
	case CMD_PTR_CPU_L2DATA:
		cpu_case_restore(hdl, cpu, &cpu->cpu_l2data, cp,
		    cmd.cmd_l2data_serd.cs_name);
		break;
	case CMD_PTR_CPU_L2DATA_UERETRY:
		/* No longer used -- discard */
		break;
	case CMD_PTR_CPU_L2TAG:
		cpu_case_restore(hdl, cpu, &cpu->cpu_l2tag, cp, "l2tag");
		break;
	case CMD_PTR_CPU_L3DATA:
		cpu_case_restore(hdl, cpu, &cpu->cpu_l3data, cp,
		    cmd.cmd_l3data_serd.cs_name);
		break;
	case CMD_PTR_CPU_L3DATA_UERETRY:
		/* No longer used -- discard */
		break;
	case CMD_PTR_CPU_L3TAG:
		cpu_case_restore(hdl, cpu, &cpu->cpu_l3tag, cp, "l3tag");
		break;
	case CMD_PTR_CPU_FPU:
		cpu_case_restore(hdl, cpu, &cpu->cpu_fpu, cp, "fpu");
		break;
	case CMD_PTR_CPU_XR_RETRY:
		cmd_xr_restore(hdl, cpu, cp);
		break;
	case CMD_PTR_CPU_IREG:
		cpu_case_restore(hdl, cpu, &cpu->cpu_ireg, cp, "ireg");
		break;
	case CMD_PTR_CPU_FREG:
		cpu_case_restore(hdl, cpu, &cpu->cpu_freg, cp, "freg");
		break;
	case CMD_PTR_CPU_MAU:
		cpu_case_restore(hdl, cpu, &cpu->cpu_mau, cp, "mau");
		break;
	case CMD_PTR_CPU_L2CTL:
		cpu_case_restore(hdl, cpu, &cpu->cpu_l2ctl, cp, "l2ctl");
		break;
	case CMD_PTR_CPU_MISC_REGS:
		cpu_case_restore(hdl, cpu, &cpu->cpu_misc_regs, cp,
		    "misc_regs");
		break;
	case CMD_PTR_CPU_LFU:
		cpu_case_restore(hdl, cpu, &cpu->cpu_lfu, cp, "lfu");
		break;
#ifdef sun4u
	case CMD_PTR_CPU_INV_SFSR:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_invsfsr, cp,
		    "opl_invsfsr");
		break;
	case CMD_PTR_CPU_UE_DET_CPU:
		cpu_case_restore(hdl, cpu, &cpu->cpu_oplue_detcpu, cp,
		    "oplue_detcpu");
		break;
	case CMD_PTR_CPU_UE_DET_IO:
		cpu_case_restore(hdl, cpu, &cpu->cpu_oplue_detio, cp,
		    "oplue_detio");
		break;
	case CMD_PTR_CPU_MTLB:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_mtlb, cp,
		    "opl_mtlb");
		break;
	case CMD_PTR_CPU_TLBP:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_tlbp, cp,
		    "opl_tlbp");
		break;
	case CMD_PTR_CPU_UGESR_INV_URG:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_inv_urg, cp,
		    "opl_inv_urg");
		break;
	case CMD_PTR_CPU_UGESR_CRE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_cre, cp,
		    "opl_cre");
		break;
	case CMD_PTR_CPU_UGESR_TSB_CTX:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_tsb_ctx, cp,
		    "opl_tsb_ctx");
		break;
	case CMD_PTR_CPU_UGESR_TSBP:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_tsbp, cp,
		    "opl_tsbp");
		break;
	case CMD_PTR_CPU_UGESR_PSTATE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_pstate, cp,
		    "opl_pstate");
		break;
	case CMD_PTR_CPU_UGESR_TSTATE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_tstate, cp,
		    "opl_tstate");
		break;
	case CMD_PTR_CPU_UGESR_IUG_F:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_iug_f, cp,
		    "opl_iug_f");
		break;
	case CMD_PTR_CPU_UGESR_IUG_R:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_iug_r, cp,
		    "opl_iug_r");
		break;
	case CMD_PTR_CPU_UGESR_SDC:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_sdc, cp,
		    "opl_sdc");
		break;
	case CMD_PTR_CPU_UGESR_WDT:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_wdt, cp,
		    "opl_wdt");
		break;
	case CMD_PTR_CPU_UGESR_DTLB:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_dtlb, cp,
		    "opl_dtlb");
		break;
	case CMD_PTR_CPU_UGESR_ITLB:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_itlb, cp,
		    "opl_itlb");
		break;
	case CMD_PTR_CPU_UGESR_CORE_ERR:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_core_err, cp,
		    "opl_core_err");
		break;
	case CMD_PTR_CPU_UGESR_DAE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_dae, cp,
		    "opl_dae");
		break;
	case CMD_PTR_CPU_UGESR_IAE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_iae, cp,
		    "opl_iae");
		break;
	case CMD_PTR_CPU_UGESR_UGE:
		cpu_case_restore(hdl, cpu, &cpu->cpu_opl_uge, cp,
		    "opl_uge");
		break;
#endif	/* sun4u */
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (cpu);
}

void
cmd_cpu_validate(fmd_hdl_t *hdl)
{
	cmd_xr_t *xr, *xrn;
	cmd_cpu_t *cpu, *cpun;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (cpu_all_threads_invalid(hdl, cpu) == FMD_B_TRUE)
			cpu->cpu_flags |= CMD_CPU_F_DELETING;
	}

	for (xr = cmd_list_next(&cmd.cmd_xxcu_redelivs); xr != NULL; xr = xrn) {
		xrn = cmd_list_next(xr);

		if (xr->xr_cpu->cpu_flags & CMD_CPU_F_DELETING)
			cmd_xr_destroy(hdl, xr);
	}

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL; cpu = cpun) {
		cpun = cmd_list_next(cpu);

		if (cpu->cpu_flags & CMD_CPU_F_DELETING)
			cmd_cpu_destroy(hdl, cpu);
	}
}

static void
cmd_xxcu_timeout(fmd_hdl_t *hdl, id_t id)
{
	cmd_xr_t *xr;

	for (xr = cmd_list_next(&cmd.cmd_xxcu_redelivs); xr != NULL;
	    xr = cmd_list_next(xr)) {
		if (xr->xr_id == id) {
			fmd_event_t *ep = fmd_case_getprincipal(hdl,
			    xr->xr_case);
			xr->xr_hdlr(hdl, xr, ep);
			cmd_xr_deref(hdl, xr);
			return;
		}
	}
}

/*ARGSUSED*/
static void
cmd_xxu_flush_timeout(fmd_hdl_t *hdl, id_t id)
{
#ifdef sun4u
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (cpu->cpu_uec_flush == id) {
			cpu_uec_flush_finish(hdl, cpu);
			return;
		}
	}
#else /* sun4u */
	return;
#endif /* sun4u */
}

void
cmd_cpu_timeout(fmd_hdl_t *hdl, id_t id, void *type)
{
	switch ((uintptr_t)type) {
	case (uintptr_t)CMD_TIMERTYPE_CPU_UEC_FLUSH:
		cmd_xxu_flush_timeout(hdl, id);
		break;
	case (uintptr_t)CMD_TIMERTYPE_CPU_XR_WAITER:
		cmd_xxcu_timeout(hdl, id);
		break;
	}
}

static int
cpu_gc_keep_one(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	int i;

	if (cpu_all_threads_invalid(hdl, cpu) == FMD_B_TRUE) {
		fmd_hdl_debug(hdl, "GC of CPU %d: no longer working\n",
		    cpu->cpu_cpuid);
		return (0);
	}

	for (i = 0; i < sizeof (cmd_cpu_cases_t) / sizeof (cmd_case_t); i++) {
		cmd_case_t *cp = &((cmd_case_t *)&cpu->cpu_cases)[i];

		if (cp->cc_cp == NULL || cp->cc_serdnm == NULL)
			continue;

		if (fmd_serd_exists(hdl, cp->cc_serdnm) &&
		    !fmd_serd_empty(hdl, cp->cc_serdnm))
			return (1);
	}

	if (cmd_list_next(&cpu->cpu_xxu_retries) != NULL)
		return (1);

	if (cpu->cpu_uec.uec_cache != NULL ||
	    cpu->cpu_olduec.uec_cache != NULL)
		return (1);

	return (0);
}

/*ARGSUSED*/
void
cmd_cpu_gc(fmd_hdl_t *hdl)
{
	cmd_cpu_t *cpu, *next;

	fmd_hdl_debug(hdl, "GC of CPUs\n");

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL; cpu = next) {
		next = cmd_list_next(cpu);

		if (!cpu_gc_keep_one(hdl, cpu)) {
			fmd_hdl_debug(hdl, "GC of CPU %d: destroying\n",
			    cpu->cpu_cpuid);
			continue;
		}
#ifdef sun4u
		if (cpu->cpu_uec.uec_cache != NULL)
			cpu_uec_flush(hdl, cpu);
#endif /* sun4u */
		cpu->cpu_uec_nflushes = 0;
	}
}

void
cmd_cpu_fini(fmd_hdl_t *hdl)
{
	cmd_cpu_t *cpu;

	while ((cpu = cmd_list_next(&cmd.cmd_cpus)) != NULL)
		cmd_cpu_free(hdl, cpu, FMD_B_FALSE);
}

typedef struct {
    const char *fam_name;
    cpu_family_t fam_value;
} famdata_t;

static famdata_t famdata_tbl[] = {
	{"UltraSPARC-III",	CMD_CPU_FAM_CHEETAH},
	{"UltraSPARC-IV",	CMD_CPU_FAM_CHEETAH},
	{"UltraSPARC-T",	CMD_CPU_FAM_NIAGARA},
	{"SPARC64-VI",		CMD_CPU_FAM_SPARC64},
	{"SPARC64-VII",		CMD_CPU_FAM_SPARC64}
};

cpu_family_t
cpu_family(char *knsp)
{
	int j;

	for (j = 0; j < sizeof (famdata_tbl)/sizeof (famdata_t); j++) {
		if (strncmp(knsp, famdata_tbl[j].fam_name,
		    strlen(famdata_tbl[j].fam_name)) == 0) {
			return (famdata_tbl[j].fam_value);
		}
	}
	return (CMD_CPU_FAM_UNSUPPORTED);
}

/*
 * Determine which CPU family this diagnosis is being run on.
 * This assumes that ereports are being generated by this system.
 */

cpu_family_t
cmd_cpu_check_support(void)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL)
		return (CMD_CPU_FAM_UNSUPPORTED);

	for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_info") != 0)
			continue;

		if (kstat_read(kc, ksp, NULL) == -1) {
			(void) kstat_close(kc);
			return (CMD_CPU_FAM_UNSUPPORTED);
		}

		for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
			cpu_family_t family;
			if (strcmp(kn->name, "implementation") != 0)
				continue;
			family = cpu_family(KSTAT_NAMED_STR_PTR(kn));
			(void) kstat_close(kc);
			return (family);
		}
	}
	(void) kstat_close(kc);
	return (CMD_CPU_FAM_UNSUPPORTED);
}

boolean_t
cmd_cpu_ecache_support(void)
{
	cpu_family_t value;

	value = cmd_cpu_check_support();
	return (fam_info_tbl[value].ecache_flush_needed);
}

/*
 * This function builds the fmri of the
 * given cpuid based on the cpu scheme.
 */
nvlist_t *
cmd_cpu_fmri_create(uint32_t cpuid, uint8_t cpumask)
{
	nvlist_t *fmri;

	if ((errno = nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0)) != 0)
		return (NULL);

	if (nvlist_add_uint8(fmri, FM_VERSION,
	    FM_CPU_SCHEME_VERSION) != 0 || nvlist_add_string(fmri,
	    FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU) != 0 ||
	    nvlist_add_uint32(fmri, FM_FMRI_CPU_ID, cpuid) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_CPU_MASK, cpumask) != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	return (fmri);
}
