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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 */

/*
 * explicitly define DTRACE_ERRDEBUG to pull in definition of dtrace_errhash_t
 * explicitly define _STDARG_H to avoid stdarg.h/varargs.h u/k defn conflict
 */
#define	DTRACE_ERRDEBUG
#define	_STDARG_H

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/dtrace_impl.h>
#include <sys/vmem_impl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/kobj.h>
#include <dtrace.h>
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>

/*ARGSUSED*/
int
id2probe(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t probe = NULL;
	uintptr_t probes;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (addr == DTRACE_IDNONE || addr > UINT32_MAX)
		goto out;

	if (mdb_readvar(&probes, "dtrace_probes") == -1) {
		mdb_warn("failed to read 'dtrace_probes'");
		return (DCMD_ERR);
	}

	probes += (addr - 1) * sizeof (dtrace_probe_t *);

	if (mdb_vread(&probe, sizeof (uintptr_t), probes) == -1) {
		mdb_warn("failed to read dtrace_probes[%d]", addr - 1);
		return (DCMD_ERR);
	}

out:
	mdb_printf("%p\n", probe);
	return (DCMD_OK);
}

void
dtrace_help(void)
{

	mdb_printf("Given a dtrace_state_t structure that represents a "
	    "DTrace consumer, prints\n"
	    "dtrace(1M)-like output for in-kernel DTrace data.  (The "
	    "dtrace_state_t\n"
	    "structures for all DTrace consumers may be obtained by running "
	    "the \n"
	    "::dtrace_state dcmd.)   When data is present on multiple CPUs, "
	    "data are\n"
	    "presented in CPU order, with records within each CPU ordered "
	    "oldest to \n"
	    "youngest.  Options:\n\n"
	    "-c cpu     Only provide output for specified CPU.\n");
}

static int
dtracemdb_eprobe(dtrace_state_t *state, dtrace_eprobedesc_t *epd)
{
	dtrace_epid_t epid = epd->dtepd_epid;
	dtrace_probe_t probe;
	dtrace_ecb_t ecb;
	uintptr_t addr, paddr, ap;
	dtrace_action_t act;
	int nactions, nrecs;

	addr = (uintptr_t)state->dts_ecbs +
	    (epid - 1) * sizeof (dtrace_ecb_t *);

	if (mdb_vread(&addr, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read ecb for epid %d", epid);
		return (-1);
	}

	if (addr == NULL) {
		mdb_warn("epid %d doesn't match an ecb\n", epid);
		return (-1);
	}

	if (mdb_vread(&ecb, sizeof (ecb), addr) == -1) {
		mdb_warn("failed to read ecb at %p", addr);
		return (-1);
	}

	paddr = (uintptr_t)ecb.dte_probe;

	if (mdb_vread(&probe, sizeof (probe), paddr) == -1) {
		mdb_warn("failed to read probe for ecb %p", addr);
		return (-1);
	}

	/*
	 * This is a little painful:  in order to find the number of actions,
	 * we need to first walk through them.
	 */
	for (ap = (uintptr_t)ecb.dte_action, nactions = 0; ap != NULL; ) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on ecb %p",
			    ap, addr);
			return (-1);
		}

		if (!DTRACEACT_ISAGG(act.dta_kind) && !act.dta_intuple)
			nactions++;

		ap = (uintptr_t)act.dta_next;
	}

	nrecs = epd->dtepd_nrecs;
	epd->dtepd_nrecs = nactions;
	epd->dtepd_probeid = probe.dtpr_id;
	epd->dtepd_uarg = ecb.dte_uarg;
	epd->dtepd_size = ecb.dte_size;

	for (ap = (uintptr_t)ecb.dte_action, nactions = 0; ap != NULL; ) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on ecb %p",
			    ap, addr);
			return (-1);
		}

		if (!DTRACEACT_ISAGG(act.dta_kind) && !act.dta_intuple) {
			if (nrecs-- == 0)
				break;

			epd->dtepd_rec[nactions++] = act.dta_rec;
		}

		ap = (uintptr_t)act.dta_next;
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_probe(dtrace_state_t *state, dtrace_probedesc_t *pd)
{
	uintptr_t base, addr, paddr, praddr;
	int nprobes, i;
	dtrace_probe_t probe;
	dtrace_provider_t prov;

	if (pd->dtpd_id == DTRACE_IDNONE)
		pd->dtpd_id++;

	if (mdb_readvar(&base, "dtrace_probes") == -1) {
		mdb_warn("failed to read 'dtrace_probes'");
		return (-1);
	}

	if (mdb_readvar(&nprobes, "dtrace_nprobes") == -1) {
		mdb_warn("failed to read 'dtrace_nprobes'");
		return (-1);
	}

	for (i = pd->dtpd_id; i <= nprobes; i++) {
		addr = base + (i - 1) * sizeof (dtrace_probe_t *);

		if (mdb_vread(&paddr, sizeof (paddr), addr) == -1) {
			mdb_warn("couldn't read probe pointer at %p", addr);
			return (-1);
		}

		if (paddr != NULL)
			break;
	}

	if (paddr == NULL) {
		errno = ESRCH;
		return (-1);
	}

	if (mdb_vread(&probe, sizeof (probe), paddr) == -1) {
		mdb_warn("couldn't read probe at %p", paddr);
		return (-1);
	}

	pd->dtpd_id = probe.dtpr_id;

	if (mdb_vread(pd->dtpd_name, DTRACE_NAMELEN,
	    (uintptr_t)probe.dtpr_name) == -1) {
		mdb_warn("failed to read probe name for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_func, DTRACE_FUNCNAMELEN,
	    (uintptr_t)probe.dtpr_func) == -1) {
		mdb_warn("failed to read function name for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_mod, DTRACE_MODNAMELEN,
	    (uintptr_t)probe.dtpr_mod) == -1) {
		mdb_warn("failed to read module name for probe %p", paddr);
		return (-1);
	}

	praddr = (uintptr_t)probe.dtpr_provider;

	if (mdb_vread(&prov, sizeof (prov), praddr) == -1) {
		mdb_warn("failed to read provider for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_provider, DTRACE_PROVNAMELEN,
	    (uintptr_t)prov.dtpv_name) == -1) {
		mdb_warn("failed to read provider name for probe %p", paddr);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_aggdesc(dtrace_state_t *state, dtrace_aggdesc_t *agd)
{
	dtrace_aggid_t aggid = agd->dtagd_id;
	dtrace_aggregation_t agg;
	dtrace_ecb_t ecb;
	uintptr_t addr, eaddr, ap, last;
	dtrace_action_t act;
	dtrace_recdesc_t *lrec;
	int nactions, nrecs;

	addr = (uintptr_t)state->dts_aggregations +
	    (aggid - 1) * sizeof (dtrace_aggregation_t *);

	if (mdb_vread(&addr, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read aggregation for aggid %d", aggid);
		return (-1);
	}

	if (addr == NULL) {
		mdb_warn("aggid %d doesn't match an aggregation\n", aggid);
		return (-1);
	}

	if (mdb_vread(&agg, sizeof (agg), addr) == -1) {
		mdb_warn("failed to read aggregation at %p", addr);
		return (-1);
	}

	eaddr = (uintptr_t)agg.dtag_ecb;

	if (mdb_vread(&ecb, sizeof (ecb), eaddr) == -1) {
		mdb_warn("failed to read ecb for aggregation %p", addr);
		return (-1);
	}

	last = (uintptr_t)addr + offsetof(dtrace_aggregation_t, dtag_action);

	/*
	 * This is a little painful:  in order to find the number of actions,
	 * we need to first walk through them.
	 */
	ap = (uintptr_t)agg.dtag_first;
	nactions = 0;

	for (;;) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on aggregation %p",
			    ap, addr);
			return (-1);
		}

		nactions++;

		if (ap == last)
			break;

		ap = (uintptr_t)act.dta_next;
	}

	lrec = &act.dta_rec;
	agd->dtagd_size = lrec->dtrd_offset + lrec->dtrd_size - agg.dtag_base;

	nrecs = agd->dtagd_nrecs;
	agd->dtagd_nrecs = nactions;
	agd->dtagd_epid = ecb.dte_epid;

	ap = (uintptr_t)agg.dtag_first;
	nactions = 0;

	for (;;) {
		dtrace_recdesc_t rec;

		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on aggregation %p",
			    ap, addr);
			return (-1);
		}

		if (nrecs-- == 0)
			break;

		rec = act.dta_rec;
		rec.dtrd_offset -= agg.dtag_base;
		rec.dtrd_uarg = 0;
		agd->dtagd_rec[nactions++] = rec;

		if (ap == last)
			break;

		ap = (uintptr_t)act.dta_next;
	}

	return (0);
}

static int
dtracemdb_bufsnap(dtrace_buffer_t *which, dtrace_bufdesc_t *desc)
{
	uintptr_t addr;
	size_t bufsize;
	dtrace_buffer_t buf;
	caddr_t data = desc->dtbd_data;
	processorid_t max_cpuid, cpu = desc->dtbd_cpu;

	if (mdb_readvar(&max_cpuid, "max_cpuid") == -1) {
		mdb_warn("failed to read 'max_cpuid'");
		errno = EIO;
		return (-1);
	}

	if (cpu < 0 || cpu > max_cpuid) {
		errno = EINVAL;
		return (-1);
	}

	addr = (uintptr_t)which + cpu * sizeof (dtrace_buffer_t);

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read buffer description at %p", addr);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_tomax == NULL) {
		errno = ENOENT;
		return (-1);
	}

	if (buf.dtb_flags & DTRACEBUF_WRAPPED) {
		bufsize = buf.dtb_size;
	} else {
		bufsize = buf.dtb_offset;
	}

	if (mdb_vread(data, bufsize, (uintptr_t)buf.dtb_tomax) == -1) {
		mdb_warn("couldn't read buffer for CPU %d", cpu);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_offset > buf.dtb_size) {
		mdb_warn("buffer for CPU %d has corrupt offset\n", cpu);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_flags & DTRACEBUF_WRAPPED) {
		if (buf.dtb_xamot_offset > buf.dtb_size) {
			mdb_warn("ringbuffer for CPU %d has corrupt "
			    "wrapped offset\n", cpu);
			errno = EIO;
			return (-1);
		}

		/*
		 * If the ring buffer has wrapped, it needs to be polished.
		 * See the comment in dtrace_buffer_polish() for details.
		 */
		if (buf.dtb_offset < buf.dtb_xamot_offset) {
			bzero(data + buf.dtb_offset,
			    buf.dtb_xamot_offset - buf.dtb_offset);
		}

		if (buf.dtb_offset > buf.dtb_xamot_offset) {
			bzero(data + buf.dtb_offset,
			    buf.dtb_size - buf.dtb_offset);
			bzero(data, buf.dtb_xamot_offset);
		}

		desc->dtbd_oldest = buf.dtb_xamot_offset;
	} else {
		desc->dtbd_oldest = 0;
	}

	desc->dtbd_size = bufsize;
	desc->dtbd_drops = buf.dtb_drops;
	desc->dtbd_errors = buf.dtb_errors;

	return (0);
}

/*
 * This is essentially identical to its cousin in the kernel -- with the
 * notable exception that we automatically set DTRACEOPT_GRABANON if this
 * state is an anonymous enabling.
 */
static dof_hdr_t *
dtracemdb_dof_create(dtrace_state_t *state, int isanon)
{
	dof_hdr_t *dof;
	dof_sec_t *sec;
	dof_optdesc_t *opt;
	int i, len = sizeof (dof_hdr_t) +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)) +
	    sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	dof = mdb_zalloc(len, UM_SLEEP);
	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	dof->dofh_flags = 0;
	dof->dofh_hdrsize = sizeof (dof_hdr_t);
	dof->dofh_secsize = sizeof (dof_sec_t);
	dof->dofh_secnum = 1;	/* only DOF_SECT_OPTDESC */
	dof->dofh_secoff = sizeof (dof_hdr_t);
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;
	dof->dofh_pad = 0;

	/*
	 * Fill in the option section header...
	 */
	sec = (dof_sec_t *)((uintptr_t)dof + sizeof (dof_hdr_t));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof (uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof (dof_optdesc_t);

	opt = (dof_optdesc_t *)((uintptr_t)sec +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)));

	sec->dofs_offset = (uintptr_t)opt - (uintptr_t)dof;
	sec->dofs_size = sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		opt[i].dofo_option = i;
		opt[i].dofo_strtab = DOF_SECIDX_NONE;
		opt[i].dofo_value = state->dts_options[i];
	}

	if (isanon)
		opt[DTRACEOPT_GRABANON].dofo_value = 1;

	return (dof);
}

static int
dtracemdb_format(dtrace_state_t *state, dtrace_fmtdesc_t *desc)
{
	uintptr_t addr, faddr;
	char c;
	int len = 0;

	if (desc->dtfd_format == 0 || desc->dtfd_format > state->dts_nformats) {
		errno = EINVAL;
		return (-1);
	}

	faddr = (uintptr_t)state->dts_formats +
	    (desc->dtfd_format - 1) * sizeof (char *);

	if (mdb_vread(&addr, sizeof (addr), faddr) == -1) {
		mdb_warn("failed to read format string pointer at %p", faddr);
		return (-1);
	}

	do {
		if (mdb_vread(&c, sizeof (c), addr + len++) == -1) {
			mdb_warn("failed to read format string at %p", addr);
			return (-1);
		}
	} while (c != '\0');

	if (len > desc->dtfd_length) {
		desc->dtfd_length = len;
		return (0);
	}

	if (mdb_vread(desc->dtfd_string, len, addr) == -1) {
		mdb_warn("failed to reread format string at %p", addr);
		return (-1);
	}

	return (0);
}

static int
dtracemdb_status(dtrace_state_t *state, dtrace_status_t *status)
{
	dtrace_dstate_t *dstate;
	int i, j;
	uint64_t nerrs;
	uintptr_t addr;
	int ncpu;

	if (mdb_readvar(&ncpu, "_ncpu") == -1) {
		mdb_warn("failed to read '_ncpu'");
		return (DCMD_ERR);
	}

	bzero(status, sizeof (dtrace_status_t));

	if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
		errno = ENOENT;
		return (-1);
	}

	/*
	 * For the MDB backend, we never set dtst_exiting or dtst_filled.  This
	 * is by design:  we don't want the library to try to stop tracing,
	 * because it doesn't particularly mean anything.
	 */
	nerrs = state->dts_errors;
	dstate = &state->dts_vstate.dtvs_dynvars;

	for (i = 0; i < ncpu; i++) {
		dtrace_dstate_percpu_t dcpu;
		dtrace_buffer_t buf;

		addr = (uintptr_t)&dstate->dtds_percpu[i];

		if (mdb_vread(&dcpu, sizeof (dcpu), addr) == -1) {
			mdb_warn("failed to read per-CPU dstate at %p", addr);
			return (-1);
		}

		status->dtst_dyndrops += dcpu.dtdsc_drops;
		status->dtst_dyndrops_dirty += dcpu.dtdsc_dirty_drops;
		status->dtst_dyndrops_rinsing += dcpu.dtdsc_rinsing_drops;

		addr = (uintptr_t)&state->dts_buffer[i];

		if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
			mdb_warn("failed to read per-CPU buffer at %p", addr);
			return (-1);
		}

		nerrs += buf.dtb_errors;

		for (j = 0; j < state->dts_nspeculations; j++) {
			dtrace_speculation_t spec;

			addr = (uintptr_t)&state->dts_speculations[j];

			if (mdb_vread(&spec, sizeof (spec), addr) == -1) {
				mdb_warn("failed to read "
				    "speculation at %p", addr);
				return (-1);
			}

			addr = (uintptr_t)&spec.dtsp_buffer[i];

			if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
				mdb_warn("failed to read "
				    "speculative buffer at %p", addr);
				return (-1);
			}

			status->dtst_specdrops += buf.dtb_xamot_drops;
		}
	}

	status->dtst_specdrops_busy = state->dts_speculations_busy;
	status->dtst_specdrops_unavail = state->dts_speculations_unavail;
	status->dtst_errors = nerrs;

	return (0);
}

typedef struct dtracemdb_data {
	dtrace_state_t *dtmd_state;
	char *dtmd_symstr;
	char *dtmd_modstr;
	uintptr_t dtmd_addr;
	int dtmd_isanon;
} dtracemdb_data_t;

static int
dtracemdb_ioctl(void *varg, int cmd, void *arg)
{
	dtracemdb_data_t *data = varg;
	dtrace_state_t *state = data->dtmd_state;

	switch (cmd) {
	case DTRACEIOC_CONF: {
		dtrace_conf_t *conf = arg;

		bzero(conf, sizeof (conf));
		conf->dtc_difversion = DIF_VERSION;
		conf->dtc_difintregs = DIF_DIR_NREGS;
		conf->dtc_diftupregs = DIF_DTR_NREGS;
		conf->dtc_ctfmodel = CTF_MODEL_NATIVE;

		return (0);
	}

	case DTRACEIOC_DOFGET: {
		dof_hdr_t *hdr = arg, *dof;

		dof = dtracemdb_dof_create(state, data->dtmd_isanon);
		bcopy(dof, hdr, MIN(hdr->dofh_loadsz, dof->dofh_loadsz));
		mdb_free(dof, dof->dofh_loadsz);

		return (0);
	}

	case DTRACEIOC_BUFSNAP:
		return (dtracemdb_bufsnap(state->dts_buffer, arg));

	case DTRACEIOC_AGGSNAP:
		return (dtracemdb_bufsnap(state->dts_aggbuffer, arg));

	case DTRACEIOC_AGGDESC:
		return (dtracemdb_aggdesc(state, arg));

	case DTRACEIOC_EPROBE:
		return (dtracemdb_eprobe(state, arg));

	case DTRACEIOC_PROBES:
		return (dtracemdb_probe(state, arg));

	case DTRACEIOC_FORMAT:
		return (dtracemdb_format(state, arg));

	case DTRACEIOC_STATUS:
		return (dtracemdb_status(state, arg));

	case DTRACEIOC_GO:
		*(processorid_t *)arg = -1;
		return (0);

	case DTRACEIOC_ENABLE:
		errno = ENOTTY; /* see dt_open.c:dtrace_go() */
		return (-1);

	case DTRACEIOC_PROVIDER:
	case DTRACEIOC_PROBEMATCH:
		errno = ESRCH;
		return (-1);

	default:
		mdb_warn("unexpected ioctl 0x%x (%s)\n", cmd,
		    cmd == DTRACEIOC_PROVIDER	? "DTRACEIOC_PROVIDER" :
		    cmd == DTRACEIOC_PROBES	? "DTRACEIOC_PROBES" :
		    cmd == DTRACEIOC_BUFSNAP	? "DTRACEIOC_BUFSNAP" :
		    cmd == DTRACEIOC_PROBEMATCH	? "DTRACEIOC_PROBEMATCH" :
		    cmd == DTRACEIOC_ENABLE	? "DTRACEIOC_ENABLE" :
		    cmd == DTRACEIOC_AGGSNAP	? "DTRACEIOC_AGGSNAP" :
		    cmd == DTRACEIOC_EPROBE	? "DTRACEIOC_EPROBE" :
		    cmd == DTRACEIOC_PROBEARG	? "DTRACEIOC_PROBEARG" :
		    cmd == DTRACEIOC_CONF	? "DTRACEIOC_CONF" :
		    cmd == DTRACEIOC_STATUS	? "DTRACEIOC_STATUS" :
		    cmd == DTRACEIOC_GO		? "DTRACEIOC_GO" :
		    cmd == DTRACEIOC_STOP	? "DTRACEIOC_STOP" :
		    cmd == DTRACEIOC_AGGDESC	? "DTRACEIOC_AGGDESC" :
		    cmd == DTRACEIOC_FORMAT	? "DTRACEIOC_FORMAT" :
		    cmd == DTRACEIOC_DOFGET	? "DTRACEIOC_DOFGET" :
		    cmd == DTRACEIOC_REPLICATE	? "DTRACEIOC_REPLICATE" :
		    "???");
		errno = ENXIO;
		return (-1);
	}
}

static int
dtracemdb_modctl(uintptr_t addr, const struct modctl *m, dtracemdb_data_t *data)
{
	struct module mod;

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_vread(&mod, sizeof (mod), (uintptr_t)m->mod_mp) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	if ((uintptr_t)mod.text > data->dtmd_addr)
		return (WALK_NEXT);

	if ((uintptr_t)mod.text + mod.text_size <= data->dtmd_addr)
		return (WALK_NEXT);

	if (mdb_readstr(data->dtmd_modstr, MDB_SYM_NAMLEN,
	    (uintptr_t)m->mod_modname) == -1)
		return (WALK_ERR);

	return (WALK_DONE);
}

static int
dtracemdb_lookup_by_addr(void *varg, GElf_Addr addr, GElf_Sym *symp,
    dtrace_syminfo_t *sip)
{
	dtracemdb_data_t *data = varg;

	if (data->dtmd_symstr == NULL) {
		data->dtmd_symstr = mdb_zalloc(MDB_SYM_NAMLEN,
		    UM_SLEEP | UM_GC);
	}

	if (data->dtmd_modstr == NULL) {
		data->dtmd_modstr = mdb_zalloc(MDB_SYM_NAMLEN,
		    UM_SLEEP | UM_GC);
	}

	if (symp != NULL) {
		if (mdb_lookup_by_addr(addr, MDB_SYM_FUZZY, data->dtmd_symstr,
		    MDB_SYM_NAMLEN, symp) == -1)
			return (-1);
	}

	if (sip != NULL) {
		data->dtmd_addr = addr;

		(void) strcpy(data->dtmd_modstr, "???");

		if (mdb_walk("modctl",
		    (mdb_walk_cb_t)dtracemdb_modctl, varg) == -1) {
			mdb_warn("couldn't walk 'modctl'");
			return (-1);
		}

		sip->dts_object = data->dtmd_modstr;
		sip->dts_id = 0;
		sip->dts_name = symp != NULL ? data->dtmd_symstr : NULL;
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_stat(void *varg, processorid_t cpu)
{
	GElf_Sym sym;
	cpu_t c;
	uintptr_t caddr, addr;

	if (mdb_lookup_by_name("cpu", &sym) == -1) {
		mdb_warn("failed to find symbol for 'cpu'");
		return (-1);
	}

	if (cpu * sizeof (uintptr_t) > sym.st_size)
		return (-1);

	addr = (uintptr_t)sym.st_value + cpu * sizeof (uintptr_t);

	if (mdb_vread(&caddr, sizeof (caddr), addr) == -1) {
		mdb_warn("failed to read cpu[%d]", cpu);
		return (-1);
	}

	if (caddr == NULL)
		return (-1);

	if (mdb_vread(&c, sizeof (c), caddr) == -1) {
		mdb_warn("failed to read cpu at %p", caddr);
		return (-1);
	}

	if (c.cpu_flags & CPU_POWEROFF) {
		return (P_POWEROFF);
	} else if (c.cpu_flags & CPU_SPARE) {
		return (P_SPARE);
	} else if (c.cpu_flags & CPU_FAULTED) {
		return (P_FAULTED);
	} else if ((c.cpu_flags & (CPU_READY | CPU_OFFLINE)) != CPU_READY) {
		return (P_OFFLINE);
	} else if (c.cpu_flags & CPU_ENABLE) {
		return (P_ONLINE);
	} else {
		return (P_NOINTR);
	}
}

/*ARGSUSED*/
static long
dtracemdb_sysconf(void *varg, int name)
{
	int max_ncpus;
	processorid_t max_cpuid;

	switch (name) {
	case _SC_CPUID_MAX:
		if (mdb_readvar(&max_cpuid, "max_cpuid") == -1) {
			mdb_warn("failed to read 'max_cpuid'");
			return (-1);
		}

		return (max_cpuid);

	case _SC_NPROCESSORS_MAX:
		if (mdb_readvar(&max_ncpus, "max_ncpus") == -1) {
			mdb_warn("failed to read 'max_ncpus'");
			return (-1);
		}

		return (max_ncpus);

	default:
		mdb_warn("unexpected sysconf code %d\n", name);
		return (-1);
	}
}

const dtrace_vector_t dtrace_mdbops = {
	dtracemdb_ioctl,
	dtracemdb_lookup_by_addr,
	dtracemdb_stat,
	dtracemdb_sysconf
};

typedef struct dtrace_dcmddata {
	dtrace_hdl_t *dtdd_dtp;
	int dtdd_cpu;
	int dtdd_quiet;
	int dtdd_flowindent;
	int dtdd_heading;
	FILE *dtdd_output;
} dtrace_dcmddata_t;

/*
 * Helper to grab all the content from a file, spit it into a string, and erase
 * and reset the file.
 */
static void
print_and_truncate_file(FILE *fp)
{
	long len;
	char *out;

	/* flush, find length of file, seek to beginning, initialize buffer */
	if (fflush(fp) || (len = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET) < 0) {
		mdb_warn("couldn't prepare DTrace output file: %d\n", errno);
		return;
	}

	out = mdb_alloc(len + 1, UM_SLEEP);
	out[len] = '\0';

	/* read file into buffer, truncate file, and seek to beginning */
	if ((fread(out, len + 1, sizeof (char), fp) == 0 && ferror(fp)) ||
	    ftruncate(fileno(fp), 0) < 0 || fseek(fp, 0, SEEK_SET) < 0) {
		mdb_warn("couldn't read DTrace output file: %d\n", errno);
		mdb_free(out, len + 1);
		return;
	}

	mdb_printf("%s", out);
	mdb_free(out, len + 1);
}

/*ARGSUSED*/
static int
dtrace_dcmdrec(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, void *arg)
{
	dtrace_dcmddata_t *dd = arg;

	print_and_truncate_file(dd->dtdd_output);

	if (rec == NULL) {
		/*
		 * We have processed the final record; output the newline if
		 * we're not in quiet mode.
		 */
		if (!dd->dtdd_quiet)
			mdb_printf("\n");

		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
dtrace_dcmdprobe(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	processorid_t cpu = data->dtpda_cpu;
	dtrace_dcmddata_t *dd = arg;
	char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];

	if (dd->dtdd_cpu != -1UL && dd->dtdd_cpu != cpu)
		return (DTRACE_CONSUME_NEXT);

	if (dd->dtdd_heading == 0) {
		if (!dd->dtdd_flowindent) {
			if (!dd->dtdd_quiet) {
				mdb_printf("%3s %6s %32s\n",
				    "CPU", "ID", "FUNCTION:NAME");
			}
		} else {
			mdb_printf("%3s %-41s\n", "CPU", "FUNCTION");
		}
		dd->dtdd_heading = 1;
	}

	if (!dd->dtdd_flowindent) {
		if (!dd->dtdd_quiet) {
			(void) mdb_snprintf(name, sizeof (name), "%s:%s",
			    pd->dtpd_func, pd->dtpd_name);

			mdb_printf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
		}
	} else {
		int indent = data->dtpda_indent;

		if (data->dtpda_flow == DTRACEFLOW_NONE) {
			(void) mdb_snprintf(name, sizeof (name), "%*s%s%s:%s",
			    indent, "", data->dtpda_prefix, pd->dtpd_func,
			    pd->dtpd_name);
		} else {
			(void) mdb_snprintf(name, sizeof (name), "%*s%s%s",
			    indent, "", data->dtpda_prefix, pd->dtpd_func);
		}

		mdb_printf("%3d %-41s ", cpu, name);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
dtrace_dcmderr(const dtrace_errdata_t *data, void *arg)
{
	mdb_warn(data->dteda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
dtrace_dcmddrop(const dtrace_dropdata_t *data, void *arg)
{
	mdb_warn(data->dtdda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
dtrace_dcmdbuffered(const dtrace_bufdata_t *bufdata, void *arg)
{
	mdb_printf("%s", bufdata->dtbda_buffered);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
int
dtrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_state_t state;
	dtrace_hdl_t *dtp;
	int ncpu, err;
	uintptr_t c = -1UL;
	dtrace_dcmddata_t dd;
	dtrace_optval_t val;
	dtracemdb_data_t md;
	int rval = DCMD_ERR;
	dtrace_anon_t anon;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'c', MDB_OPT_UINTPTR, &c, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&ncpu, "_ncpu") == -1) {
		mdb_warn("failed to read '_ncpu'");
		return (DCMD_ERR);
	}

	if (mdb_vread(&state, sizeof (state), addr) == -1) {
		mdb_warn("couldn't read dtrace_state_t at %p", addr);
		return (DCMD_ERR);
	}

	if (state.dts_anon != NULL) {
		addr = (uintptr_t)state.dts_anon;

		if (mdb_vread(&state, sizeof (state), addr) == -1) {
			mdb_warn("couldn't read anonymous state at %p", addr);
			return (DCMD_ERR);
		}
	}

	bzero(&md, sizeof (md));
	md.dtmd_state = &state;

	if ((dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS, &err,
	    &dtrace_mdbops, &md)) == NULL) {
		mdb_warn("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(NULL, err));
		return (DCMD_ERR);
	}

	/*
	 * If this is the anonymous enabling, we need to set a bit indicating
	 * that DTRACEOPT_GRABANON should be set.
	 */
	if (mdb_readvar(&anon, "dtrace_anon") == -1) {
		mdb_warn("failed to read 'dtrace_anon'");
		return (DCMD_ERR);
	}

	md.dtmd_isanon = ((uintptr_t)anon.dta_state == addr);

	if (dtrace_go(dtp) != 0) {
		mdb_warn("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	bzero(&dd, sizeof (dd));
	dd.dtdd_dtp = dtp;
	dd.dtdd_cpu = c;

	if (dtrace_getopt(dtp, "flowindent", &val) == -1) {
		mdb_warn("couldn't get 'flowindent' option: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	dd.dtdd_flowindent = (val != DTRACEOPT_UNSET);

	if (dtrace_getopt(dtp, "quiet", &val) == -1) {
		mdb_warn("couldn't get 'quiet' option: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	dd.dtdd_quiet = (val != DTRACEOPT_UNSET);

	if (dtrace_handle_err(dtp, dtrace_dcmderr, NULL) == -1) {
		mdb_warn("couldn't add err handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_handle_drop(dtp, dtrace_dcmddrop, NULL) == -1) {
		mdb_warn("couldn't add drop handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_handle_buffered(dtp, dtrace_dcmdbuffered, NULL) == -1) {
		mdb_warn("couldn't add buffered handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_status(dtp) == -1) {
		mdb_warn("couldn't get status: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_aggregate_snap(dtp) == -1) {
		mdb_warn("couldn't snapshot aggregation: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if ((dd.dtdd_output = tmpfile()) == NULL) {
		mdb_warn("couldn't open DTrace output file: %d\n", errno);
		goto err;
	}

	if (dtrace_consume(dtp, dd.dtdd_output,
	    dtrace_dcmdprobe, dtrace_dcmdrec, &dd) == -1) {
		mdb_warn("couldn't consume DTrace buffers: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}

	if (dtrace_aggregate_print(dtp, NULL, NULL) == -1) {
		mdb_warn("couldn't print aggregation: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	rval = DCMD_OK;
err:
	dtrace_close(dtp);
	fclose(dd.dtdd_output);
	return (rval);
}

static int
dtrace_errhash_cmp(const void *l, const void *r)
{
	uintptr_t lhs = *((uintptr_t *)l);
	uintptr_t rhs = *((uintptr_t *)r);
	dtrace_errhash_t lerr, rerr;
	char lmsg[256], rmsg[256];

	(void) mdb_vread(&lerr, sizeof (lerr), lhs);
	(void) mdb_vread(&rerr, sizeof (rerr), rhs);

	if (lerr.dter_msg == NULL)
		return (-1);

	if (rerr.dter_msg == NULL)
		return (1);

	(void) mdb_readstr(lmsg, sizeof (lmsg), (uintptr_t)lerr.dter_msg);
	(void) mdb_readstr(rmsg, sizeof (rmsg), (uintptr_t)rerr.dter_msg);

	return (strcmp(lmsg, rmsg));
}

int
dtrace_errhash_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t *hash, addr;
	int i;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_errhash walk only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("dtrace_errhash", &sym) == -1) {
		mdb_warn("couldn't find 'dtrace_errhash' (non-DEBUG kernel?)");
		return (WALK_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	hash = mdb_alloc(DTRACE_ERRHASHSZ * sizeof (uintptr_t),
	    UM_SLEEP | UM_GC);

	for (i = 0; i < DTRACE_ERRHASHSZ; i++)
		hash[i] = addr + i * sizeof (dtrace_errhash_t);

	qsort(hash, DTRACE_ERRHASHSZ, sizeof (uintptr_t), dtrace_errhash_cmp);

	wsp->walk_addr = 0;
	wsp->walk_data = hash;

	return (WALK_NEXT);
}

int
dtrace_errhash_step(mdb_walk_state_t *wsp)
{
	int ndx = (int)wsp->walk_addr;
	uintptr_t *hash = wsp->walk_data;
	dtrace_errhash_t err;
	uintptr_t addr;

	if (ndx >= DTRACE_ERRHASHSZ)
		return (WALK_DONE);

	wsp->walk_addr = ndx + 1;
	addr = hash[ndx];

	if (mdb_vread(&err, sizeof (err), addr) == -1) {
		mdb_warn("failed to read dtrace_errhash_t at %p", addr);
		return (WALK_DONE);
	}

	if (err.dter_msg == NULL)
		return (WALK_NEXT);

	return (wsp->walk_callback(addr, &err, wsp->walk_cbdata));
}

/*ARGSUSED*/
int
dtrace_errhash(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_errhash_t err;
	char msg[256];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_errhash", "dtrace_errhash",
		    argc, argv) == -1) {
			mdb_warn("can't walk 'dtrace_errhash'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%8s %s\n", "COUNT", "ERROR");

	if (mdb_vread(&err, sizeof (err), addr) == -1) {
		mdb_warn("failed to read dtrace_errhash_t at %p", addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)err.dter_msg;

	if (mdb_readstr(msg, sizeof (msg), addr) == -1) {
		mdb_warn("failed to read error msg at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%8d %s", err.dter_count, msg);

	/*
	 * Some error messages include a newline -- only print the newline
	 * if the message doesn't have one.
	 */
	if (msg[strlen(msg) - 1] != '\n')
		mdb_printf("\n");

	return (DCMD_OK);
}

int
dtrace_helptrace_init(mdb_walk_state_t *wsp)
{
	uint32_t next;
	uintptr_t buffer;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_helptrace only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&buffer, "dtrace_helptrace_buffer") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_buffer'");
		return (WALK_ERR);
	}

	if (buffer == NULL) {
		mdb_warn("helper tracing is not enabled\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&next, "dtrace_helptrace_next") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_next'");
		return (WALK_ERR);
	}

	wsp->walk_addr = next;

	return (WALK_NEXT);
}

int
dtrace_helptrace_step(mdb_walk_state_t *wsp)
{
	uint32_t next, size, nlocals, bufsize;
	uintptr_t buffer, addr;
	dtrace_helptrace_t *ht;
	int rval;

	if (mdb_readvar(&next, "dtrace_helptrace_next") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_next'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&bufsize, "dtrace_helptrace_bufsize") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_bufsize'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&buffer, "dtrace_helptrace_buffer") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_buffer'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&nlocals, "dtrace_helptrace_nlocals") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_nlocals'");
		return (WALK_ERR);
	}

	size = sizeof (dtrace_helptrace_t) +
	    nlocals * sizeof (uint64_t) - sizeof (uint64_t);

	if (wsp->walk_addr + size > bufsize) {
		if (next == 0)
			return (WALK_DONE);

		wsp->walk_addr = 0;
	}

	addr = buffer + wsp->walk_addr;
	ht = alloca(size);

	if (mdb_vread(ht, size, addr) == -1) {
		mdb_warn("couldn't read entry at %p", addr);
		return (WALK_ERR);
	}

	if (ht->dtht_helper != NULL) {
		rval = wsp->walk_callback(addr, ht, wsp->walk_cbdata);

		if (rval != WALK_NEXT)
			return (rval);
	}

	if (wsp->walk_addr < next && wsp->walk_addr + size >= next)
		return (WALK_DONE);

	wsp->walk_addr += size;
	return (WALK_NEXT);
}

int
dtrace_helptrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_helptrace_t help;
	dtrace_helper_action_t helper;
	char where[30];
	uint_t opt_v = FALSE;
	uintptr_t haddr;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_helptrace", "dtrace_helptrace",
		    argc, argv) == -1) {
			mdb_warn("can't walk 'dtrace_helptrace'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv, 'v',
	    MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(" %?s %?s %12s %s\n",
		    "ADDR", "HELPER", "WHERE", "DIFO");
	}

	if (mdb_vread(&help, sizeof (help), addr) == -1) {
		mdb_warn("failed to read dtrace_helptrace_t at %p", addr);
		return (DCMD_ERR);
	}

	switch (help.dtht_where) {
	case 0:
		(void) mdb_snprintf(where, sizeof (where), "predicate");
		break;

	case DTRACE_HELPTRACE_NEXT:
		(void) mdb_snprintf(where, sizeof (where), "next");
		break;

	case DTRACE_HELPTRACE_DONE:
		(void) mdb_snprintf(where, sizeof (where), "done");
		break;

	case DTRACE_HELPTRACE_ERR:
		(void) mdb_snprintf(where, sizeof (where), "err");
		break;

	default:
		(void) mdb_snprintf(where, sizeof (where),
		    "action #%d", help.dtht_where);
		break;
	}

	mdb_printf(" %?p %?p %12s ", addr, help.dtht_helper, where);

	haddr = (uintptr_t)help.dtht_helper;

	if (mdb_vread(&helper, sizeof (helper), haddr) == -1) {
		/*
		 * We're not going to warn in this case -- we're just not going
		 * to print anything exciting.
		 */
		mdb_printf("???\n");
	} else {
		switch (help.dtht_where) {
		case 0:
			mdb_printf("%p\n", helper.dtha_predicate);
			break;

		case DTRACE_HELPTRACE_NEXT:
		case DTRACE_HELPTRACE_DONE:
		case DTRACE_HELPTRACE_ERR:
			mdb_printf("-\n");
			break;

		default:
			haddr = (uintptr_t)helper.dtha_actions +
			    (help.dtht_where - 1) * sizeof (uintptr_t);

			if (mdb_vread(&haddr, sizeof (haddr), haddr) == -1) {
				mdb_printf("???\n");
			} else {
				mdb_printf("%p\n", haddr);
			}
		}
	}

	if (opt_v) {
		int i;

		if (help.dtht_where == DTRACE_HELPTRACE_ERR) {
			int f = help.dtht_fault;

			mdb_printf("%?s| %?s %10s |\n", "", "", "");
			mdb_printf("%?s| %?s %10s +->  fault: %s\n", "", "", "",
			    f == DTRACEFLT_BADADDR ? "BADADDR" :
			    f == DTRACEFLT_BADALIGN ? "BADALIGN" :
			    f == DTRACEFLT_ILLOP ? "ILLOP" :
			    f == DTRACEFLT_DIVZERO ? "DIVZERO" :
			    f == DTRACEFLT_NOSCRATCH ? "NOSCRATCH" :
			    f == DTRACEFLT_KPRIV ? "KPRIV" :
			    f == DTRACEFLT_UPRIV ? "UPRIV" :
			    f == DTRACEFLT_TUPOFLOW ? "TUPOFLOW" :
			    f == DTRACEFLT_BADSTACK ? "BADSTACK" :
			    "DTRACEFLT_UNKNOWN");
			mdb_printf("%?s| %?s %12s     addr: 0x%x\n", "", "", "",
			    help.dtht_illval);
			mdb_printf("%?s| %?s %12s   offset: %d\n", "", "", "",
			    help.dtht_fltoffs);
		}

		mdb_printf("%?s|\n%?s+--> %?s %4s %s\n", "", "",
		    "ADDR", "NDX", "VALUE");
		addr += sizeof (help) - sizeof (uint64_t);

		for (i = 0; i < help.dtht_nlocals; i++) {
			uint64_t val;

			if (mdb_vread(&val, sizeof (val), addr) == -1) {
				mdb_warn("couldn't read local at %p", addr);
				continue;
			}

			mdb_printf("%?s     %?p %4d %p\n", "", addr, i, val);
			addr += sizeof (uint64_t);
		}

		mdb_printf("\n");
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
dtrace_state_walk(uintptr_t addr, const vmem_seg_t *seg, minor_t *highest)
{
	if (seg->vs_end > *highest)
		*highest = seg->vs_end;

	return (WALK_NEXT);
}

typedef struct dtrace_state_walk {
	uintptr_t dtsw_softstate;
	minor_t dtsw_max;
	minor_t dtsw_current;
} dtrace_state_walk_t;

int
dtrace_state_init(mdb_walk_state_t *wsp)
{
	uintptr_t dtrace_minor;
	minor_t max = 0;
	dtrace_state_walk_t *dw;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_state only supports global walks\n");
		return (WALK_ERR);
	}

	/*
	 * Find the dtrace_minor vmem arena and walk it to get the maximum
	 * minor number.
	 */
	if (mdb_readvar(&dtrace_minor, "dtrace_minor") == -1) {
		mdb_warn("failed to read 'dtrace_minor'");
		return (WALK_ERR);
	}

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)dtrace_state_walk,
	    &max, dtrace_minor) == -1) {
		mdb_warn("couldn't walk 'vmem_alloc'");
		return (WALK_ERR);
	}

	dw = mdb_zalloc(sizeof (dtrace_state_walk_t), UM_SLEEP | UM_GC);
	dw->dtsw_current = 0;
	dw->dtsw_max = max;

	if (mdb_readvar(&dw->dtsw_softstate, "dtrace_softstate") == -1) {
		mdb_warn("failed to read 'dtrace_softstate'");
		return (DCMD_ERR);
	}

	wsp->walk_data = dw;

	return (WALK_NEXT);
}

int
dtrace_state_step(mdb_walk_state_t *wsp)
{
	dtrace_state_walk_t *dw = wsp->walk_data;
	uintptr_t statep;
	dtrace_state_t state;
	int rval;

	while (mdb_get_soft_state_byaddr(dw->dtsw_softstate, dw->dtsw_current,
	    &statep, NULL, 0) == -1) {
		if (dw->dtsw_current >= dw->dtsw_max)
			return (WALK_DONE);

		dw->dtsw_current++;
	}

	if (mdb_vread(&state, sizeof (state), statep) == -1) {
		mdb_warn("couldn't read dtrace_state_t at %p", statep);
		return (WALK_NEXT);
	}

	rval = wsp->walk_callback(statep, &state, wsp->walk_cbdata);
	dw->dtsw_current++;

	return (rval);
}

typedef struct dtrace_state_data {
	int dtsd_major;
	uintptr_t dtsd_proc;
	uintptr_t dtsd_softstate;
	uintptr_t dtsd_state;
} dtrace_state_data_t;

static int
dtrace_state_file(uintptr_t addr, struct file *f, dtrace_state_data_t *data)
{
	vnode_t vnode;
	proc_t proc;
	minor_t minor;
	uintptr_t statep;

	if (mdb_vread(&vnode, sizeof (vnode), (uintptr_t)f->f_vnode) == -1) {
		mdb_warn("couldn't read vnode at %p", (uintptr_t)f->f_vnode);
		return (WALK_NEXT);
	}

	if (getmajor(vnode.v_rdev) != data->dtsd_major)
		return (WALK_NEXT);

	minor = getminor(vnode.v_rdev);

	if (mdb_vread(&proc, sizeof (proc), data->dtsd_proc) == -1) {
		mdb_warn("failed to read proc at %p", data->dtsd_proc);
		return (WALK_NEXT);
	}

	if (mdb_get_soft_state_byaddr(data->dtsd_softstate, minor,
	    &statep, NULL, 0) == -1) {
		mdb_warn("failed to read softstate for minor %d", minor);
		return (WALK_NEXT);
	}

	if (statep != data->dtsd_state)
		return (WALK_NEXT);

	mdb_printf("%?p %5d %?p %-*s %?p\n", statep, minor,
	    data->dtsd_proc, MAXCOMLEN, proc.p_user.u_comm, addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
dtrace_state_proc(uintptr_t addr, void *ignored, dtrace_state_data_t *data)
{
	data->dtsd_proc = addr;

	if (mdb_pwalk("file",
	    (mdb_walk_cb_t)dtrace_state_file, data, addr) == -1) {
		mdb_warn("couldn't walk 'file' for proc %p", addr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

void
dtrace_state_help(void)
{
	mdb_printf("Given a dtrace_state_t structure, displays all "
	    /*CSTYLED*/
	    "consumers, or \"<anonymous>\"\nif the consumer is anonymous.  If "
	    "no state structure is provided, iterates\nover all state "
	    "structures.\n\n"
	    "Addresses in ADDR column may be provided to ::dtrace to obtain\n"
	    "dtrace(1M)-like output for in-kernel DTrace data.\n");
}

int
dtrace_state(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t devi;
	struct dev_info info;
	dtrace_state_data_t data;
	dtrace_anon_t anon;
	dtrace_state_t state;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_state",
		    "dtrace_state", argc, argv) == -1) {
			mdb_warn("can't walk dtrace_state");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%?s %5s %?s %-*s %?s\n", "ADDR", "MINOR", "PROC",
		    MAXCOMLEN, "NAME", "FILE");
	}

	/*
	 * First determine if this is anonymous state.
	 */
	if (mdb_readvar(&anon, "dtrace_anon") == -1) {
		mdb_warn("failed to read 'dtrace_anon'");
		return (DCMD_ERR);
	}

	if ((uintptr_t)anon.dta_state == addr) {
		if (mdb_vread(&state, sizeof (state), addr) == -1) {
			mdb_warn("failed to read anon at %p", addr);
			return (DCMD_ERR);
		}

		mdb_printf("%?p %5d %?s %-*s %?s\n", addr,
		    getminor(state.dts_dev), "-", MAXCOMLEN,
		    "<anonymous>", "-");

		return (DCMD_OK);
	}

	if (mdb_readvar(&devi, "dtrace_devi") == -1) {
		mdb_warn("failed to read 'dtrace_devi'");
		return (DCMD_ERR);
	}

	if (mdb_vread(&info, sizeof (struct dev_info), devi) == -1) {
		mdb_warn("failed to read 'dev_info'");
		return (DCMD_ERR);
	}

	data.dtsd_major = info.devi_major;

	if (mdb_readvar(&data.dtsd_softstate, "dtrace_softstate") == -1) {
		mdb_warn("failed to read 'dtrace_softstate'");
		return (DCMD_ERR);
	}

	data.dtsd_state = addr;

	/*
	 * Walk through all processes and all open files looking for this
	 * state.  It must be open somewhere...
	 */
	if (mdb_walk("proc", (mdb_walk_cb_t)dtrace_state_proc, &data) == -1) {
		mdb_warn("couldn't walk 'proc'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

typedef struct dtrace_aggkey_data {
	uintptr_t *dtakd_hash;
	uintptr_t dtakd_hashsize;
	uintptr_t dtakd_next;
	uintptr_t dtakd_ndx;
} dtrace_aggkey_data_t;

int
dtrace_aggkey_init(mdb_walk_state_t *wsp)
{
	dtrace_buffer_t buf;
	uintptr_t addr;
	dtrace_aggbuffer_t agb;
	dtrace_aggkey_data_t *data;
	size_t hsize;

	if ((addr = wsp->walk_addr) == NULL) {
		mdb_warn("dtrace_aggkey walk needs aggregation buffer\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read aggregation buffer at %p", addr);
		return (WALK_ERR);
	}

	addr = (uintptr_t)buf.dtb_tomax +
	    buf.dtb_size - sizeof (dtrace_aggbuffer_t);

	if (mdb_vread(&agb, sizeof (agb), addr) == -1) {
		mdb_warn("failed to read dtrace_aggbuffer_t at %p", addr);
		return (WALK_ERR);
	}

	data = mdb_zalloc(sizeof (dtrace_aggkey_data_t), UM_SLEEP);

	data->dtakd_hashsize = agb.dtagb_hashsize;
	hsize = agb.dtagb_hashsize * sizeof (dtrace_aggkey_t *);
	data->dtakd_hash = mdb_alloc(hsize, UM_SLEEP);

	if (mdb_vread(data->dtakd_hash, hsize,
	    (uintptr_t)agb.dtagb_hash) == -1) {
		mdb_warn("failed to read hash at %p",
		    (uintptr_t)agb.dtagb_hash);
		mdb_free(data->dtakd_hash, hsize);
		mdb_free(data, sizeof (dtrace_aggkey_data_t));
		return (WALK_ERR);
	}

	wsp->walk_data = data;
	return (WALK_NEXT);
}

int
dtrace_aggkey_step(mdb_walk_state_t *wsp)
{
	dtrace_aggkey_data_t *data = wsp->walk_data;
	dtrace_aggkey_t key;
	uintptr_t addr;

	while ((addr = data->dtakd_next) == NULL) {
		if (data->dtakd_ndx == data->dtakd_hashsize)
			return (WALK_DONE);

		data->dtakd_next = data->dtakd_hash[data->dtakd_ndx++];
	}

	if (mdb_vread(&key, sizeof (key), addr) == -1) {
		mdb_warn("failed to read dtrace_aggkey_t at %p", addr);
		return (WALK_ERR);
	}

	data->dtakd_next = (uintptr_t)key.dtak_next;

	return (wsp->walk_callback(addr, &key, wsp->walk_cbdata));
}

void
dtrace_aggkey_fini(mdb_walk_state_t *wsp)
{
	dtrace_aggkey_data_t *data = wsp->walk_data;
	size_t hsize;

	hsize = data->dtakd_hashsize * sizeof (dtrace_aggkey_t *);
	mdb_free(data->dtakd_hash, hsize);
	mdb_free(data, sizeof (dtrace_aggkey_data_t));
}

typedef struct dtrace_dynvar_data {
	dtrace_dynhash_t *dtdvd_hash;
	uintptr_t dtdvd_hashsize;
	uintptr_t dtdvd_next;
	uintptr_t dtdvd_ndx;
	uintptr_t dtdvd_sink;
} dtrace_dynvar_data_t;

int
dtrace_dynvar_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	dtrace_dstate_t dstate;
	dtrace_dynvar_data_t *data;
	size_t hsize;
	GElf_Sym sym;

	if ((addr = wsp->walk_addr) == NULL) {
		mdb_warn("dtrace_dynvar walk needs dtrace_dstate_t\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&dstate, sizeof (dstate), addr) == -1) {
		mdb_warn("failed to read dynamic state at %p", addr);
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("dtrace_dynhash_sink", &sym) == -1) {
		mdb_warn("couldn't find 'dtrace_dynhash_sink'");
		return (WALK_ERR);
	}

	data = mdb_zalloc(sizeof (dtrace_dynvar_data_t), UM_SLEEP);

	data->dtdvd_hashsize = dstate.dtds_hashsize;
	hsize = dstate.dtds_hashsize * sizeof (dtrace_dynhash_t);
	data->dtdvd_hash = mdb_alloc(hsize, UM_SLEEP);
	data->dtdvd_sink = (uintptr_t)sym.st_value;

	if (mdb_vread(data->dtdvd_hash, hsize,
	    (uintptr_t)dstate.dtds_hash) == -1) {
		mdb_warn("failed to read hash at %p",
		    (uintptr_t)dstate.dtds_hash);
		mdb_free(data->dtdvd_hash, hsize);
		mdb_free(data, sizeof (dtrace_dynvar_data_t));
		return (WALK_ERR);
	}

	data->dtdvd_next = (uintptr_t)data->dtdvd_hash[0].dtdh_chain;

	wsp->walk_data = data;
	return (WALK_NEXT);
}

int
dtrace_dynvar_step(mdb_walk_state_t *wsp)
{
	dtrace_dynvar_data_t *data = wsp->walk_data;
	dtrace_dynvar_t dynvar, *dvar;
	size_t dvarsize;
	uintptr_t addr;
	int nkeys;

	while ((addr = data->dtdvd_next) == data->dtdvd_sink) {
		if (data->dtdvd_ndx == data->dtdvd_hashsize)
			return (WALK_DONE);

		data->dtdvd_next =
		    (uintptr_t)data->dtdvd_hash[data->dtdvd_ndx++].dtdh_chain;
	}

	if (mdb_vread(&dynvar, sizeof (dynvar), addr) == -1) {
		mdb_warn("failed to read dtrace_dynvar_t at %p", addr);
		return (WALK_ERR);
	}

	/*
	 * Now we need to allocate the correct size.
	 */
	nkeys = dynvar.dtdv_tuple.dtt_nkeys;
	dvarsize = (uintptr_t)&dynvar.dtdv_tuple.dtt_key[nkeys] -
	    (uintptr_t)&dynvar;

	dvar = alloca(dvarsize);

	if (mdb_vread(dvar, dvarsize, addr) == -1) {
		mdb_warn("failed to read dtrace_dynvar_t at %p", addr);
		return (WALK_ERR);
	}

	data->dtdvd_next = (uintptr_t)dynvar.dtdv_next;

	return (wsp->walk_callback(addr, dvar, wsp->walk_cbdata));
}

void
dtrace_dynvar_fini(mdb_walk_state_t *wsp)
{
	dtrace_dynvar_data_t *data = wsp->walk_data;
	size_t hsize;

	hsize = data->dtdvd_hashsize * sizeof (dtrace_dynvar_t *);
	mdb_free(data->dtdvd_hash, hsize);
	mdb_free(data, sizeof (dtrace_dynvar_data_t));
}

typedef struct dtrace_hashstat_data {
	size_t *dthsd_counts;
	size_t dthsd_hashsize;
	char *dthsd_data;
	size_t dthsd_size;
	int dthsd_header;
} dtrace_hashstat_data_t;

typedef void (*dtrace_hashstat_func_t)(dtrace_hashstat_data_t *);

static void
dtrace_hashstat_additive(dtrace_hashstat_data_t *data)
{
	int i;
	int hval = 0;

	for (i = 0; i < data->dthsd_size; i++)
		hval += data->dthsd_data[i];

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_shifty(dtrace_hashstat_data_t *data)
{
	uint64_t hval = 0;
	int i;

	if (data->dthsd_size < sizeof (uint64_t)) {
		dtrace_hashstat_additive(data);
		return;
	}

	for (i = 0; i < data->dthsd_size; i += sizeof (uint64_t)) {
		/* LINTED - alignment */
		uint64_t val = *((uint64_t *)&data->dthsd_data[i]);

		hval += (val & ((1 << NBBY) - 1)) +
		    ((val >> NBBY) & ((1 << NBBY) - 1)) +
		    ((val >> (NBBY << 1)) & ((1 << NBBY) - 1)) +
		    ((val >> (NBBY << 2)) & ((1 << NBBY) - 1)) +
		    (val & USHRT_MAX) + (val >> (NBBY << 1) & USHRT_MAX);
	}

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_knuth(dtrace_hashstat_data_t *data)
{
	int i;
	int hval = data->dthsd_size;

	for (i = 0; i < data->dthsd_size; i++)
		hval = (hval << 4) ^ (hval >> 28) ^ data->dthsd_data[i];

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_oneatatime(dtrace_hashstat_data_t *data)
{
	int i;
	uint32_t hval = 0;

	for (i = 0; i < data->dthsd_size; i++) {
		hval += data->dthsd_data[i];
		hval += (hval << 10);
		hval ^= (hval >> 6);
	}

	hval += (hval << 3);
	hval ^= (hval >> 11);
	hval += (hval << 15);

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_fnv(dtrace_hashstat_data_t *data)
{
	static const uint32_t prime = 0x01000193;
	uint32_t hval = 0;
	int i;

	for (i = 0; i < data->dthsd_size; i++) {
		hval *= prime;
		hval ^= data->dthsd_data[i];
	}

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_stats(char *name, dtrace_hashstat_data_t *data)
{
	size_t nz = 0, i;
	int longest = 0;
	size_t ttl = 0;
	double sum = 0.0;
	double avg;
	uint_t util, stddev;

	if (!data->dthsd_header) {
		mdb_printf("%15s %11s %11s %11s %11s %11s\n", "NAME",
		    "HASHSIZE", "%UTIL", "LONGEST", "AVERAGE", "STDDEV");
		data->dthsd_header = 1;
	}

	for (i = 0; i < data->dthsd_hashsize; i++) {
		if (data->dthsd_counts[i] != 0) {
			nz++;

			if (data->dthsd_counts[i] > longest)
				longest = data->dthsd_counts[i];

			ttl += data->dthsd_counts[i];
		}
	}

	if (nz == 0) {
		mdb_printf("%15s %11d %11s %11s %11s %11s\n", name,
		    data->dthsd_hashsize, "-", "-", "-", "-");
		return;
	}

	avg = (double)ttl / (double)nz;

	for (i = 0; i < data->dthsd_hashsize; i++) {
		double delta = (double)data->dthsd_counts[i] - avg;

		if (data->dthsd_counts[i] == 0)
			continue;

		sum += delta * delta;
	}

	util = (nz * 1000) / data->dthsd_hashsize;
	stddev = (uint_t)sqrt(sum / (double)nz) * 10;

	mdb_printf("%15s %11d %9u.%1u %11d %11d %9u.%1u\n", name,
	    data->dthsd_hashsize, util / 10, util % 10, longest, ttl / nz,
	    stddev / 10, stddev % 10);
}

static struct dtrace_hashstat {
	char *dths_name;
	dtrace_hashstat_func_t dths_func;
} _dtrace_hashstat[] = {
	{ "<actual>", NULL },
	{ "additive", dtrace_hashstat_additive },
	{ "shifty", dtrace_hashstat_shifty },
	{ "knuth", dtrace_hashstat_knuth },
	{ "one-at-a-time", dtrace_hashstat_oneatatime },
	{ "fnv", dtrace_hashstat_fnv },
	{ NULL, 0 }
};

typedef struct dtrace_aggstat_data {
	dtrace_hashstat_data_t dtagsd_hash;
	dtrace_hashstat_func_t dtagsd_func;
} dtrace_aggstat_data_t;

static int
dtrace_aggstat_walk(uintptr_t addr, dtrace_aggkey_t *key,
    dtrace_aggstat_data_t *data)
{
	dtrace_hashstat_data_t *hdata = &data->dtagsd_hash;
	size_t size;

	if (data->dtagsd_func == NULL) {
		size_t bucket = key->dtak_hashval % hdata->dthsd_hashsize;

		hdata->dthsd_counts[bucket]++;
		return (WALK_NEXT);
	}

	/*
	 * We need to read the data.
	 */
	size = key->dtak_size - sizeof (dtrace_aggid_t);
	addr = (uintptr_t)key->dtak_data + sizeof (dtrace_aggid_t);
	hdata->dthsd_data = alloca(size);
	hdata->dthsd_size = size;

	if (mdb_vread(hdata->dthsd_data, size, addr) == -1) {
		mdb_warn("couldn't read data at %p", addr);
		return (WALK_ERR);
	}

	data->dtagsd_func(hdata);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
dtrace_aggstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_buffer_t buf;
	uintptr_t aaddr;
	dtrace_aggbuffer_t agb;
	size_t hsize, i, actual, prime, evenpow;
	dtrace_aggstat_data_t data;
	dtrace_hashstat_data_t *hdata = &data.dtagsd_hash;

	bzero(&data, sizeof (data));

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read aggregation buffer at %p", addr);
		return (DCMD_ERR);
	}

	aaddr = (uintptr_t)buf.dtb_tomax +
	    buf.dtb_size - sizeof (dtrace_aggbuffer_t);

	if (mdb_vread(&agb, sizeof (agb), aaddr) == -1) {
		mdb_warn("failed to read dtrace_aggbuffer_t at %p", aaddr);
		return (DCMD_ERR);
	}

	hsize = (actual = agb.dtagb_hashsize) * sizeof (size_t);
	hdata->dthsd_counts = mdb_alloc(hsize, UM_SLEEP | UM_GC);

	/*
	 * Now pick the largest prime smaller than the hash size.  (If the
	 * existing size is prime, we'll pick a smaller prime just for the
	 * hell of it.)
	 */
	for (prime = agb.dtagb_hashsize - 1; prime > 7; prime--) {
		size_t limit = prime / 7;

		for (i = 2; i < limit; i++) {
			if ((prime % i) == 0)
				break;
		}

		if (i == limit)
			break;
	}

	/*
	 * And now we want to pick the largest power of two smaller than the
	 * hashsize.
	 */
	for (i = 0; (1 << i) < agb.dtagb_hashsize; i++)
		continue;

	evenpow = (1 << (i - 1));

	for (i = 0; _dtrace_hashstat[i].dths_name != NULL; i++) {
		data.dtagsd_func = _dtrace_hashstat[i].dths_func;

		hdata->dthsd_hashsize = actual;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		/*
		 * If we were just printing the actual value, we won't try
		 * any of the sizing experiments.
		 */
		if (data.dtagsd_func == NULL)
			continue;

		hdata->dthsd_hashsize = prime;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		hdata->dthsd_hashsize = evenpow;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
dtrace_dynstat_walk(uintptr_t addr, dtrace_dynvar_t *dynvar,
    dtrace_aggstat_data_t *data)
{
	dtrace_hashstat_data_t *hdata = &data->dtagsd_hash;
	dtrace_tuple_t *tuple = &dynvar->dtdv_tuple;
	dtrace_key_t *key = tuple->dtt_key;
	size_t size = 0, offs = 0;
	int i, nkeys = tuple->dtt_nkeys;
	char *buf;

	if (data->dtagsd_func == NULL) {
		size_t bucket = dynvar->dtdv_hashval % hdata->dthsd_hashsize;

		hdata->dthsd_counts[bucket]++;
		return (WALK_NEXT);
	}

	/*
	 * We want to hand the hashing algorithm a contiguous buffer.  First
	 * run through the tuple and determine the size.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			size += sizeof (uint64_t);
		} else {
			size += key[i].dttk_size;
		}
	}

	buf = alloca(size);

	/*
	 * Now go back through the tuple and copy the data into the buffer.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			bcopy(&key[i].dttk_value, &buf[offs],
			    sizeof (uint64_t));
			offs += sizeof (uint64_t);
		} else {
			if (mdb_vread(&buf[offs], key[i].dttk_size,
			    key[i].dttk_value) == -1) {
				mdb_warn("couldn't read tuple data at %p",
				    key[i].dttk_value);
				return (WALK_ERR);
			}

			offs += key[i].dttk_size;
		}
	}

	hdata->dthsd_data = buf;
	hdata->dthsd_size = size;

	data->dtagsd_func(hdata);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
dtrace_dynstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_dstate_t dstate;
	size_t hsize, i, actual, prime;
	dtrace_aggstat_data_t data;
	dtrace_hashstat_data_t *hdata = &data.dtagsd_hash;

	bzero(&data, sizeof (data));

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&dstate, sizeof (dstate), addr) == -1) {
		mdb_warn("failed to read dynamic variable state at %p", addr);
		return (DCMD_ERR);
	}

	hsize = (actual = dstate.dtds_hashsize) * sizeof (size_t);
	hdata->dthsd_counts = mdb_alloc(hsize, UM_SLEEP | UM_GC);

	/*
	 * Now pick the largest prime smaller than the hash size.  (If the
	 * existing size is prime, we'll pick a smaller prime just for the
	 * hell of it.)
	 */
	for (prime = dstate.dtds_hashsize - 1; prime > 7; prime--) {
		size_t limit = prime / 7;

		for (i = 2; i < limit; i++) {
			if ((prime % i) == 0)
				break;
		}

		if (i == limit)
			break;
	}

	for (i = 0; _dtrace_hashstat[i].dths_name != NULL; i++) {
		data.dtagsd_func = _dtrace_hashstat[i].dths_func;

		hdata->dthsd_hashsize = actual;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_dynvar",
		    (mdb_walk_cb_t)dtrace_dynstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_dynvar at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		/*
		 * If we were just printing the actual value, we won't try
		 * any of the sizing experiments.
		 */
		if (data.dtagsd_func == NULL)
			continue;

		hdata->dthsd_hashsize = prime;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_dynvar",
		    (mdb_walk_cb_t)dtrace_dynstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);
	}

	return (DCMD_OK);
}

typedef struct dtrace_ecb_walk {
	dtrace_ecb_t **dtew_ecbs;
	int dtew_necbs;
	int dtew_curecb;
} dtrace_ecb_walk_t;

static int
dtrace_ecb_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	dtrace_state_t state;
	dtrace_ecb_walk_t *ecbwp;

	if ((addr = wsp->walk_addr) == NULL) {
		mdb_warn("dtrace_ecb walk needs dtrace_state_t\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&state, sizeof (state), addr) == -1) {
		mdb_warn("failed to read dtrace state pointer at %p", addr);
		return (WALK_ERR);
	}

	ecbwp = mdb_zalloc(sizeof (dtrace_ecb_walk_t), UM_SLEEP | UM_GC);

	ecbwp->dtew_ecbs = state.dts_ecbs;
	ecbwp->dtew_necbs = state.dts_necbs;
	ecbwp->dtew_curecb = 0;

	wsp->walk_data = ecbwp;

	return (WALK_NEXT);
}

static int
dtrace_ecb_step(mdb_walk_state_t *wsp)
{
	uintptr_t ecbp, addr;
	dtrace_ecb_walk_t *ecbwp = wsp->walk_data;

	addr = (uintptr_t)ecbwp->dtew_ecbs +
	    ecbwp->dtew_curecb * sizeof (dtrace_ecb_t *);

	if (ecbwp->dtew_curecb++ == ecbwp->dtew_necbs)
		return (WALK_DONE);

	if (mdb_vread(&ecbp, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read ecb at entry %d\n",
		    ecbwp->dtew_curecb);
		return (WALK_ERR);
	}

	if (ecbp == NULL)
		return (WALK_NEXT);

	return (wsp->walk_callback(ecbp, NULL, wsp->walk_cbdata));
}

static void
dtrace_options_numtostr(uint64_t num, char *buf, size_t len)
{
	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024) {
		n = (n + (1024 / 2)) / 1024; /* Round up or down */
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) mdb_snprintf(buf, len, "%llu", (u_longlong_t)n);
	} else if (n < 10 && (num & (num - 1)) != 0) {
		(void) mdb_snprintf(buf, len, "%.2f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else if (n < 100 && (num & (num - 1)) != 0) {
		(void) mdb_snprintf(buf, len, "%.1f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else {
		(void) mdb_snprintf(buf, len, "%llu%c", (u_longlong_t)n, u);
	}
}

static void
dtrace_options_numtohz(uint64_t num, char *buf, size_t len)
{
	(void) mdb_snprintf(buf, len, "%dhz", NANOSEC/num);
}

static void
dtrace_options_numtobufpolicy(uint64_t num, char *buf, size_t len)
{
	char *policy = "unknown";

	switch (num) {
		case DTRACEOPT_BUFPOLICY_RING:
			policy = "ring";
			break;

		case DTRACEOPT_BUFPOLICY_FILL:
			policy = "fill";
			break;

		case DTRACEOPT_BUFPOLICY_SWITCH:
			policy = "switch";
			break;
	}

	(void) mdb_snprintf(buf, len, "%s", policy);
}

static void
dtrace_options_numtocpu(uint64_t cpu, char *buf, size_t len)
{
	if (cpu == DTRACE_CPUALL)
		(void) mdb_snprintf(buf, len, "%7s", "unbound");
	else
		(void) mdb_snprintf(buf, len, "%d", cpu);
}

typedef void (*dtrace_options_func_t)(uint64_t, char *, size_t);

static struct dtrace_options {
	char *dtop_optstr;
	dtrace_options_func_t dtop_func;
} _dtrace_options[] = {
	{ "bufsize", dtrace_options_numtostr },
	{ "bufpolicy", dtrace_options_numtobufpolicy },
	{ "dynvarsize", dtrace_options_numtostr },
	{ "aggsize", dtrace_options_numtostr },
	{ "specsize", dtrace_options_numtostr },
	{ "nspec", dtrace_options_numtostr },
	{ "strsize", dtrace_options_numtostr },
	{ "cleanrate", dtrace_options_numtohz },
	{ "cpu", dtrace_options_numtocpu },
	{ "bufresize", dtrace_options_numtostr },
	{ "grabanon", dtrace_options_numtostr },
	{ "flowindent", dtrace_options_numtostr },
	{ "quiet", dtrace_options_numtostr },
	{ "stackframes", dtrace_options_numtostr },
	{ "ustackframes", dtrace_options_numtostr },
	{ "aggrate", dtrace_options_numtohz },
	{ "switchrate", dtrace_options_numtohz },
	{ "statusrate", dtrace_options_numtohz },
	{ "destructive", dtrace_options_numtostr },
	{ "stackindent", dtrace_options_numtostr },
	{ "rawbytes", dtrace_options_numtostr },
	{ "jstackframes", dtrace_options_numtostr },
	{ "jstackstrsize", dtrace_options_numtostr },
	{ "aggsortkey", dtrace_options_numtostr },
	{ "aggsortrev", dtrace_options_numtostr },
	{ "aggsortpos", dtrace_options_numtostr },
	{ "aggsortkeypos", dtrace_options_numtostr }
};

static void
dtrace_options_help(void)
{
	mdb_printf("Given a dtrace_state_t structure, displays the "
	    "current tunable option\nsettings.\n");
}

/*ARGSUSED*/
static int
dtrace_options(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_state_t state;
	int i = 0;
	dtrace_optval_t *options;
	char val[32];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&state, sizeof (dtrace_state_t), (uintptr_t)addr) == -1) {
		mdb_warn("failed to read state pointer at %p\n", addr);
		return (DCMD_ERR);
	}

	options = &state.dts_options[0];

	mdb_printf("%<u>%-25s %s%</u>\n", "OPTION", "VALUE");
	for (i = 0; i < DTRACEOPT_MAX; i++) {
		if (options[i] == DTRACEOPT_UNSET) {
			mdb_printf("%-25s %s\n",
			    _dtrace_options[i].dtop_optstr, "UNSET");
		} else {
			(void) _dtrace_options[i].dtop_func(options[i],
			    val, 32);
			mdb_printf("%-25s %s\n",
			    _dtrace_options[i].dtop_optstr, val);
		}
	}

	return (DCMD_OK);
}

static int
pid2state_init(mdb_walk_state_t *wsp)
{
	dtrace_state_data_t *data;
	uintptr_t devi;
	uintptr_t proc;
	struct dev_info info;
	pid_t pid = (pid_t)wsp->walk_addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("pid2state walk requires PID\n");
		return (WALK_ERR);
	}

	data = mdb_zalloc(sizeof (dtrace_state_data_t), UM_SLEEP | UM_GC);

	if (mdb_readvar(&data->dtsd_softstate, "dtrace_softstate") == -1) {
		mdb_warn("failed to read 'dtrace_softstate'");
		return (DCMD_ERR);
	}

	if ((proc = mdb_pid2proc(pid, NULL)) == 0) {
		mdb_warn("PID 0t%d not found\n", pid);
		return (DCMD_ERR);
	}

	if (mdb_readvar(&devi, "dtrace_devi") == -1) {
		mdb_warn("failed to read 'dtrace_devi'");
		return (DCMD_ERR);
	}

	if (mdb_vread(&info, sizeof (struct dev_info), devi) == -1) {
		mdb_warn("failed to read 'dev_info'");
		return (DCMD_ERR);
	}

	data->dtsd_major = info.devi_major;
	data->dtsd_proc = proc;

	wsp->walk_data = data;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
pid2state_file(uintptr_t addr, struct file *f, dtrace_state_data_t *data)
{
	vnode_t vnode;
	minor_t minor;
	uintptr_t statep;

	/* Get the vnode for this file */
	if (mdb_vread(&vnode, sizeof (vnode), (uintptr_t)f->f_vnode) == -1) {
		mdb_warn("couldn't read vnode at %p", (uintptr_t)f->f_vnode);
		return (WALK_NEXT);
	}


	/* Is this the dtrace device? */
	if (getmajor(vnode.v_rdev) != data->dtsd_major)
		return (WALK_NEXT);

	/* Get the minor number for this device entry */
	minor = getminor(vnode.v_rdev);

	if (mdb_get_soft_state_byaddr(data->dtsd_softstate, minor,
	    &statep, NULL, 0) == -1) {
		mdb_warn("failed to read softstate for minor %d", minor);
		return (WALK_NEXT);
	}

	mdb_printf("%p\n", statep);

	return (WALK_NEXT);
}

static int
pid2state_step(mdb_walk_state_t *wsp)
{
	dtrace_state_data_t *ds = wsp->walk_data;

	if (mdb_pwalk("file",
	    (mdb_walk_cb_t)pid2state_file, ds, ds->dtsd_proc) == -1) {
		mdb_warn("couldn't walk 'file' for proc %p", ds->dtsd_proc);
		return (WALK_ERR);
	}

	return (WALK_DONE);
}

/*ARGSUSED*/
static int
dtrace_probes_walk(uintptr_t addr, void *ignored, uintptr_t *target)
{
	dtrace_ecb_t ecb;
	dtrace_probe_t probe;
	dtrace_probedesc_t pd;

	if (addr == NULL)
		return (WALK_ERR);

	if (mdb_vread(&ecb, sizeof (dtrace_ecb_t), addr) == -1) {
		mdb_warn("failed to read ecb %p\n", addr);
		return (WALK_ERR);
	}

	if (ecb.dte_probe == NULL)
		return (WALK_ERR);

	if (mdb_vread(&probe, sizeof (dtrace_probe_t),
	    (uintptr_t)ecb.dte_probe) == -1) {
		mdb_warn("failed to read probe %p\n", ecb.dte_probe);
		return (WALK_ERR);
	}

	pd.dtpd_id = probe.dtpr_id;
	dtracemdb_probe(NULL, &pd);

	mdb_printf("%5d %10s %17s %33s %s\n", pd.dtpd_id, pd.dtpd_provider,
	    pd.dtpd_mod, pd.dtpd_func, pd.dtpd_name);

	return (WALK_NEXT);
}

static void
dtrace_probes_help(void)
{
	mdb_printf("Given a dtrace_state_t structure, displays all "
	    "its active enablings.  If no\nstate structure is provided, "
	    "all available probes are listed.\n");
}

/*ARGSUSED*/
static int
dtrace_probes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_probedesc_t pd;
	uintptr_t caddr, base, paddr;
	int nprobes, i;

	mdb_printf("%5s %10s %17s %33s %s\n",
	    "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * If no argument is provided just display all available
		 * probes.
		 */
		if (mdb_readvar(&base, "dtrace_probes") == -1) {
			mdb_warn("failed to read 'dtrace_probes'");
			return (-1);
		}

		if (mdb_readvar(&nprobes, "dtrace_nprobes") == -1) {
			mdb_warn("failed to read 'dtrace_nprobes'");
			return (-1);
		}

		for (i = 0; i < nprobes; i++) {
			caddr = base + i  * sizeof (dtrace_probe_t *);

			if (mdb_vread(&paddr, sizeof (paddr), caddr) == -1) {
				mdb_warn("couldn't read probe pointer at %p",
				    caddr);
				continue;
			}

			if (paddr == NULL)
				continue;

			pd.dtpd_id = i + 1;
			if (dtracemdb_probe(NULL, &pd) == 0) {
				mdb_printf("%5d %10s %17s %33s %s\n",
				    pd.dtpd_id, pd.dtpd_provider,
				    pd.dtpd_mod, pd.dtpd_func, pd.dtpd_name);
			}
		}
	} else {
		if (mdb_pwalk("dtrace_ecb", (mdb_walk_cb_t)dtrace_probes_walk,
		    NULL, addr) == -1) {
			mdb_warn("couldn't walk 'dtrace_ecb'");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

const mdb_dcmd_t kernel_dcmds[] = {
	{ "id2probe", ":", "translate a dtrace_id_t to a dtrace_probe_t",
	    id2probe },
	{ "dtrace", ":[-c cpu]", "print dtrace(1M)-like output",
	    dtrace, dtrace_help },
	{ "dtrace_errhash", ":", "print DTrace error hash", dtrace_errhash },
	{ "dtrace_helptrace", ":", "print DTrace helper trace",
	    dtrace_helptrace },
	{ "dtrace_state", ":", "print active DTrace consumers", dtrace_state,
	    dtrace_state_help },
	{ "dtrace_aggstat", ":",
	    "print DTrace aggregation hash statistics", dtrace_aggstat },
	{ "dtrace_dynstat", ":",
	    "print DTrace dynamic variable hash statistics", dtrace_dynstat },
	{ "dtrace_options", ":",
	    "print a DTrace consumer's current tuneable options",
	    dtrace_options, dtrace_options_help },
	{ "dtrace_probes", "?", "print a DTrace consumer's enabled probes",
	    dtrace_probes, dtrace_probes_help },
	{ NULL }
};

const mdb_walker_t kernel_walkers[] = {
	{ "dtrace_errhash", "walk hash of DTrace error messasges",
		dtrace_errhash_init, dtrace_errhash_step },
	{ "dtrace_helptrace", "walk DTrace helper trace entries",
		dtrace_helptrace_init, dtrace_helptrace_step },
	{ "dtrace_state", "walk DTrace per-consumer softstate",
		dtrace_state_init, dtrace_state_step },
	{ "dtrace_aggkey", "walk DTrace aggregation keys",
		dtrace_aggkey_init, dtrace_aggkey_step, dtrace_aggkey_fini },
	{ "dtrace_dynvar", "walk DTrace dynamic variables",
		dtrace_dynvar_init, dtrace_dynvar_step, dtrace_dynvar_fini },
	{ "dtrace_ecb", "walk a DTrace consumer's enabling control blocks",
		dtrace_ecb_init, dtrace_ecb_step },
	{ "pid2state", "walk a processes dtrace_state structures",
	    pid2state_init, pid2state_step },
	{ NULL }
};
