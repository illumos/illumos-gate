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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#define	CMD_CPU_UEC_INCR	10
#define	CPU_FRU_FMRI		FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"="

/* Must be in sync with cmd_cpu_type_t */
static const char *const cpu_names[] = {
	NULL,
	"ultraSPARC-III",
	"ultraSPARC-IIIplus",
	"ultraSPARC-IIIi",
	"ultraSPARC-IV",
	"ultraSPARC-IVplus",
	"ultraSPARC-IIIiplus",
	"ultraSPARC-T1"
};

static cmd_cpu_t *cpu_lookup_by_cpuid(uint32_t);
static void cpu_buf_write(fmd_hdl_t *, cmd_cpu_t *);

static const char *
cpu_type2name(fmd_hdl_t *hdl, cmd_cpu_type_t type)
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

		bcopy(cpu->cpu_olduec.uec_cache, new, sizeof (uint64_t) *
		    cpu->cpu_olduec.uec_nent);
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
	CMD_TRAIN(CMD_ERRCL_UCC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_UCU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_UCU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_EDU_ST,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_BL,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_ST,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_EDU_BL,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_CPU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_UCC,	CMD_ERRCL_WDC | CMD_ERRCL_UCC),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU |
	    CMD_ERRCL_UCU),
	CMD_TRAIN(CMD_ERRCL_L3_UCU,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDC,	CMD_ERRCL_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_ST,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_EDU_BL,	CMD_ERRCL_L3_WDU | CMD_ERRCL_WDU),
	CMD_TRAIN(CMD_ERRCL_L3_CPC,	CMD_ERRCL_L3_WDC),
	CMD_TRAIN(CMD_ERRCL_L3_CPU,	CMD_ERRCL_L3_WDU),
#else /* sun4u */
	CMD_TRAIN(CMD_ERRCL_LDAC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDRC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDSC,	CMD_ERRCL_LDWC),
	CMD_TRAIN(CMD_ERRCL_LDAU,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_LDRU,	CMD_ERRCL_LDWU),
	CMD_TRAIN(CMD_ERRCL_LDSU,	CMD_ERRCL_LDWU),
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
cmd_trw_lookup(uint64_t ena)
{
	int i;

	for (i = 0; i < cmd.cmd_xxcu_ntrw; i++) {
		if (cmd.cmd_xxcu_trw[i].trw_ena == ena)
			return (&cmd.cmd_xxcu_trw[i]);
	}

	return (NULL);
}

cmd_xxcu_trw_t *
cmd_trw_alloc(uint64_t ena)
{
	int i;

	for (i = 0; i < cmd.cmd_xxcu_ntrw; i++) {
		cmd_xxcu_trw_t *trw = &cmd.cmd_xxcu_trw[i];
		if (trw->trw_ena == NULL) {
			trw->trw_ena = ena;
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
	size_t sz;

	if ((sz = fmd_buf_size(hdl, NULL, "waiters")) != 0) {
		uint_t ntrw = sz / sizeof (cmd_xxcu_trw_t);

		if (sz % sizeof (cmd_xxcu_trw_t) != 0) {
			fmd_hdl_abort(hdl, "waiters array isn't of "
			    "correct size\n");
		}

		/*
		 * If the existing buffer is larger than our tuned size,
		 * we'll only read as many as will fit.
		 */
		if (ntrw > cmd.cmd_xxcu_ntrw)
			ntrw = cmd.cmd_xxcu_ntrw;

		fmd_buf_read(hdl, NULL, "waiters", cmd.cmd_xxcu_trw,
		    ntrw * sizeof (cmd_xxcu_trw_t));

		if (ntrw * sizeof (cmd_xxcu_trw_t) != sz) {
			fmd_buf_destroy(hdl, NULL, "waiters");
			fmd_buf_write(hdl, NULL, "waiters", cmd.cmd_xxcu_trw,
			    ntrw * sizeof (cmd_xxcu_trw_t));
		}
	}
}

char *
cmd_cpu_serdnm_create(fmd_hdl_t *hdl, cmd_cpu_t *cpu, const char *serdbase)
{
	const char *fmt = "cpu_%d_%s_serd";
	size_t sz = snprintf(NULL, 0, fmt, cpu->cpu_cpuid, serdbase) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, cpu->cpu_cpuid, serdbase);

	return (nm);
}

nvlist_t *
cmd_cpu_create_fault(fmd_hdl_t *hdl, cmd_cpu_t *cpu, const char *type,
    nvlist_t *rsrc, uint_t cert)
{
	char fltnm[64];

	(void) snprintf(fltnm, sizeof (fltnm), "fault.cpu.%s.%s",
	    cpu_type2name(hdl, cpu->cpu_type), type);

	cpu->cpu_faulting = FMD_B_TRUE;
	cpu_buf_write(hdl, cpu);

	return (fmd_nvl_create_fault(hdl, fltnm, cert, cpu->cpu_asru_nvl,
	    cpu->cpu_fru_nvl, rsrc));
}

static void
cmd_cpu_free(fmd_hdl_t *hdl, cmd_cpu_t *cpu, int destroy)
{
	int i;

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
cpu_lookup_by_cpuid(uint32_t cpuid)
{
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (cpu->cpu_cpuid == cpuid)
			return (cpu);
	}

	return (NULL);
}

static char *
cpu_getfrustr(fmd_hdl_t *hdl, uint32_t cpuid)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL)
		return (NULL); /* errno is set for us */

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL ||
	    kstat_read(kc, ksp, NULL) == -1) {
		int oserr = errno;
		(void) kstat_close(kc);
		(void) cmd_set_errno(oserr);
		return (NULL);
	}

	for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
		if (strcmp(kn->name, "cpu_fru") == 0) {
			char *str = fmd_hdl_strdup(hdl,
			    KSTAT_NAMED_STR_PTR(kn), FMD_SLEEP);
			(void) kstat_close(kc);
			return (str);
		}
	}

	(void) kstat_close(kc);
	(void) cmd_set_errno(ENOENT);
	return (NULL);
}

static nvlist_t *
cpu_mkfru(char *frustr)
{
	char *comp;
	nvlist_t *fru, *hcelem;

	if (strncmp(frustr, CPU_FRU_FMRI, sizeof (CPU_FRU_FMRI) - 1) != 0)
		return (NULL);

	comp = frustr + sizeof (CPU_FRU_FMRI) - 1;

	if (nvlist_alloc(&hcelem, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	if (nvlist_add_string(hcelem, FM_FMRI_HC_NAME,
	    FM_FMRI_LEGACY_HC) != 0 ||
	    nvlist_add_string(hcelem, FM_FMRI_HC_ID, comp) != 0) {
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(hcelem);
		return (NULL);
	}

	if (nvlist_add_uint8(fru, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_HC) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_HC_ROOT, "") != 0 ||
	    nvlist_add_uint32(fru, FM_FMRI_HC_LIST_SZ, 1) != 0 ||
	    nvlist_add_nvlist_array(fru, FM_FMRI_HC_LIST, &hcelem, 1) != 0) {
		nvlist_free(hcelem);
		nvlist_free(fru);
		return (NULL);
	}

	nvlist_free(hcelem);
	return (fru);
}

static nvlist_t *
cpu_getfru(fmd_hdl_t *hdl, uint32_t cpuid)
{
	char *frustr;
	nvlist_t *nvlp;

	if ((frustr = cpu_getfrustr(hdl, cpuid)) == NULL) {
		fmd_hdl_abort(hdl, "failed to retrieve FRU string for CPU %d",
		    cpuid);
	}
	nvlp = cpu_mkfru(frustr);
	fmd_hdl_strfree(hdl, frustr);
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
cpu_create(fmd_hdl_t *hdl, nvlist_t *asru, uint32_t cpuid, cmd_cpu_type_t type)
{
	cmd_cpu_t *cpu;
	nvlist_t *fru;
	char *frustr;

	/*
	 * No CPU state matches the CPU described in the ereport.  Create a new
	 * one, add it to the list, and pass it back.
	 */
	fmd_hdl_debug(hdl, "cpu_lookup: creating new cpuid %u\n", cpuid);
	CMD_STAT_BUMP(cpu_creat);

	cpu = fmd_hdl_zalloc(hdl, sizeof (cmd_cpu_t), FMD_SLEEP);
	cpu->cpu_nodetype = CMD_NT_CPU;
	cpu->cpu_cpuid = cpuid;
	cpu->cpu_type = type;
	cpu->cpu_version = CMD_CPU_VERSION;

	cmd_bufname(cpu->cpu_bufname, sizeof (cpu->cpu_bufname),
	    "cpu_%d", cpu->cpu_cpuid);

#ifdef sun4u
	cpu_uec_create(hdl, cpu, &cpu->cpu_uec, "cpu_uec_%d", cpu->cpu_cpuid);
	cpu_uec_create(hdl, cpu, &cpu->cpu_olduec, "cpu_olduec_%d",
	    cpu->cpu_cpuid);
#endif /* sun4u */

	cmd_fmri_init(hdl, &cpu->cpu_asru, asru, "cpu_asru_%d", cpu->cpu_cpuid);

	/*
	 * If this ereport contains a 'cpufru' element, use it to construct
	 * the FRU FMRI instead of going to kstats.
	 *
	 * Unfortunately, the string associated with 'cpufru' is
	 * not in precisely the right form -- so the following code is
	 * written to adjust.
	 */
	if (nvlist_lookup_string(asru, FM_FMRI_CPU_CPUFRU, &frustr) == 0) {
		char *s1, *s2;
		size_t frustrlen = strlen(frustr) + sizeof (CPU_FRU_FMRI) + 1;

		s1 = fmd_hdl_zalloc(hdl, frustrlen, FMD_SLEEP);
		s2 = strrchr(frustr, '/') + 1;
		if (s2 == NULL)
			s2 = "MB";

		(void) snprintf(s1, frustrlen, "%s%s",
		    CPU_FRU_FMRI, s2);

		if ((fru = cpu_mkfru(s1)) != NULL) {
			cmd_fmri_init(hdl, &cpu->cpu_fru, fru, "cpu_fru_%d",
			    cpu->cpu_cpuid);
			nvlist_free(fru);
		}
		fmd_hdl_free(hdl, s1, frustrlen);

	} else if ((fru = cpu_getfru(hdl, cpuid)) != NULL) {
		cmd_fmri_init(hdl, &cpu->cpu_fru, fru, "cpu_fru_%d",
		    cpu->cpu_cpuid);
		nvlist_free(fru);
	} else {
		cmd_fmri_init(hdl, &cpu->cpu_fru, asru, "cpu_fru_%d",
		    cpu->cpu_cpuid);
	}

	cpu_buf_create(hdl, cpu);

	cmd_list_append(&cmd.cmd_cpus, cpu);

	return (cpu);
}


/*
 * Locate the state structure for this CPU, creating a new one if one doesn't
 * already exist.  Before passing it back, we also need to validate it against
 * the current state of the world, checking to ensure that the CPU described by
 * the ereport, the CPU indicated in the cmd_cpu_t, and the CPU currently
 * residing at the indicated cpuid are the same.  We do this by comparing the
 * serial IDs from the three entities.
 */
static cmd_cpu_t *
cmd_cpu_lookup(fmd_hdl_t *hdl, nvlist_t *asru, const char *class)
{
	cmd_cpu_t *cpu;
	uint8_t vers;
	const char *scheme;
	uint32_t cpuid;

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

	cpu = cpu_lookup_by_cpuid(cpuid);

	if (cpu != NULL && (!fmd_nvl_fmri_present(hdl, cpu->cpu_asru_nvl) ||
	    fmd_nvl_fmri_unusable(hdl, cpu->cpu_asru_nvl))) {
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
		const char *cpuname = class + sizeof ("ereport.cpu");

		cpu = cpu_create(hdl, asru, cpuid, cpu_nname2type(hdl, cpuname,
		    (size_t)(strchr(cpuname, '.') - cpuname)));
	}

	return (cpu);
}

cmd_cpu_t *
cmd_cpu_lookup_from_detector(fmd_hdl_t *hdl, nvlist_t *nvl, const char *class)
{
	nvlist_t *det;

	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det);

	return (cmd_cpu_lookup(hdl, det, class));
}

static cmd_cpu_t *
cpu_v0tov2(fmd_hdl_t *hdl, cmd_cpu_0_t *old, size_t oldsz)
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
	new->cpu_asru = old->cpu0_asru;
	new->cpu_fru = old->cpu0_fru;
	new->cpu_uec = old->cpu0_uec;
	new->cpu_olduec = old->cpu0_olduec;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_cpu_t *
cpu_v1tov2(fmd_hdl_t *hdl, cmd_cpu_1_t *old, size_t oldsz)
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
	new->cpu_asru = old->cpu1_asru;
	new->cpu_fru = old->cpu1_fru;
	new->cpu_uec = old->cpu1_uec;
	new->cpu_olduec = old->cpu1_olduec;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_cpu_t *
cpu_wrapv2(fmd_hdl_t *hdl, cmd_cpu_pers_t *pers, size_t psz)
{
	cmd_cpu_t *cpu;

	if (psz != sizeof (cmd_cpu_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (cmd_cpu_pers_t));
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

void *
cmd_cpu_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (strcmp(cpu->cpu_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (cpu == NULL) {
		int migrated = 0;
		size_t cpusz;

		fmd_hdl_debug(hdl, "restoring cpu from %s\n", ptr->ptr_name);

		if ((cpusz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			fmd_hdl_abort(hdl, "cpu referenced by case %s does "
			    "not exist in saved state\n",
			    fmd_case_uuid(hdl, cp));
		} else if (cpusz > CMD_CPU_MAXSIZE || cpusz < CMD_CPU_MINSIZE) {
			fmd_hdl_abort(hdl, "cpu buffer referenced by case %s "
			    "is out of bounds (is %u bytes)\n",
			    fmd_case_uuid(hdl, cp), cpusz);
		}

		if ((cpu = cmd_buf_read(hdl, NULL, ptr->ptr_name,
		    cpusz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    cpu->cpu_version);

		if (CMD_CPU_VERSIONED(cpu)) {
			switch (cpu->cpu_version) {
			case CMD_CPU_VERSION_1:
				cpu = cpu_v1tov2(hdl, (cmd_cpu_1_t *)cpu,
				    cpusz);
				migrated = 1;
				break;
			case CMD_CPU_VERSION_2:
				cpu = cpu_wrapv2(hdl, (cmd_cpu_pers_t *)cpu,
				    cpusz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				    "for cpu state referenced by case %s.\n",
				    cpu->cpu_version, fmd_case_uuid(hdl, cp));
				break;
			}
		} else {
			cpu = cpu_v0tov2(hdl, (cmd_cpu_0_t *)cpu, cpusz);
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
		if (!fmd_nvl_fmri_present(hdl, cpu->cpu_asru_nvl) ||
		    fmd_nvl_fmri_unusable(hdl, cpu->cpu_asru_nvl))
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

	if (!fmd_nvl_fmri_present(hdl, cpu->cpu_asru_nvl) ||
	    fmd_nvl_fmri_unusable(hdl, cpu->cpu_asru_nvl)) {
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
	{"UltraSPARC-T",	CMD_CPU_FAM_NIAGARA}
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
