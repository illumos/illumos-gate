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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <generic_cpu/gcpu.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpu_module_ms_impl.h>

typedef struct cmi_hdl_impl {
	enum cmi_hdl_class cmih_class;		/* Handle nature */
	struct cmi_hdl_ops *cmih_ops;		/* Operations vector */
	uint_t cmih_chipid;			/* Chipid of cpu resource */
	uint_t cmih_procnodeid;			/* Nodeid of cpu resource */
	uint_t cmih_coreid;			/* Core within die */
	uint_t cmih_strandid;			/* Thread within core */
	uint_t cmih_procnodes_per_pkg;		/* Nodes in a processor */
	boolean_t cmih_mstrand;			/* cores are multithreaded */
	volatile uint32_t *cmih_refcntp;	/* Reference count pointer */
	uint64_t cmih_msrsrc;			/* MSR data source flags */
	void *cmih_hdlpriv;			/* cmi_hw.c private data */
	void *cmih_spec;			/* cmi_hdl_{set,get}_specific */
	void *cmih_cmi;				/* cpu mod control structure */
	void *cmih_cmidata;			/* cpu mod private data */
	const struct cmi_mc_ops *cmih_mcops;	/* Memory-controller ops */
	void *cmih_mcdata;			/* Memory-controller data */
	uint64_t cmih_flags;
	uint16_t cmih_smbiosid;			/* SMBIOS Type 4 struct ID */
	uint_t cmih_smb_chipid;			/* smbios chipid */
	nvlist_t *cmih_smb_bboard;		/* smbios bboard */
} cmi_hdl_impl_t;

typedef struct cmi_hdl_ent {
	volatile uint32_t cmae_refcnt;
	cmi_hdl_impl_t *cmae_hdlp;
} cmi_hdl_ent_t;

typedef struct cmi {
	struct cmi *cmi_next;
	struct cmi *cmi_prev;
	const cmi_ops_t *cmi_ops;
	struct modctl *cmi_modp;
	uint_t cmi_refcnt;
} cmi_t;

typedef struct cms {
	struct cms *cms_next;
	struct cms *cms_prev;
	const cms_ops_t *cms_ops;
	struct modctl *cms_modp;
	uint_t cms_refcnt;
} cms_t;

struct cms_ctl {
	cms_t *cs_cms;
	void *cs_cmsdata;
};

#define	CMI_MAX_CHIPID_NBITS		6	/* max chipid of 63 */

#define	CMI_MAX_CHIPID			((1 << (CMI_MAX_CHIPID_NBITS)) - 1)
#define	CMI_MAX_CORES_PER_CHIP(cbits)	(1 << (cbits))
#define	CMI_MAX_COREID(cbits)		((1 << (cbits)) - 1)
#define	CMI_MAX_STRANDS_PER_CORE(sbits)	(1 << (sbits))
#define	CMI_MAX_STRANDID(sbits)		((1 << (sbits)) - 1)
#define	CMI_MAX_STRANDS_PER_CHIP(cbits, sbits)	\
	(CMI_MAX_CORES_PER_CHIP(cbits) * CMI_MAX_STRANDS_PER_CORE(sbits))

#define	CMI_CHIPID_ARR_SZ		(1 << CMI_MAX_CHIPID_NBITS)

struct cmih_walk_state {
	int chipid, coreid, strandid;	/* currently visited cpu */
	cmi_hdl_ent_t *chip_tab[CMI_CHIPID_ARR_SZ];
	uint_t core_nbits;
	uint_t strand_nbits;
};

/*
 * Advance the <chipid,coreid,strandid> tuple to the next strand entry
 * Return true upon sucessful result. Otherwise return false if already reach
 * the highest strand.
 */
static boolean_t
cmih_ent_next(struct cmih_walk_state *wsp)
{
	uint_t carry = 0;

	/* Check for end of the table */
	if (wsp->chipid >= CMI_MAX_CHIPID &&
	    wsp->coreid >= CMI_MAX_COREID(wsp->core_nbits) &&
	    wsp->strandid >= CMI_MAX_STRANDID(wsp->strand_nbits))
		return (B_FALSE);

	/* increment the strand id */
	wsp->strandid++;
	carry =  wsp->strandid >> wsp->strand_nbits;
	wsp->strandid =  wsp->strandid & CMI_MAX_STRANDID(wsp->strand_nbits);
	if (carry == 0)
		return (B_TRUE);

	/* increment the core id */
	wsp->coreid++;
	carry = wsp->coreid >> wsp->core_nbits;
	wsp->coreid = wsp->coreid & CMI_MAX_COREID(wsp->core_nbits);
	if (carry == 0)
		return (B_TRUE);

	/* increment the chip id */
	wsp->chipid = (wsp->chipid + 1) & (CMI_MAX_CHIPID);

	return (B_TRUE);
}

/*
 * Lookup for the hdl entry of a given <chip,core,strand> tuple
 */
static cmi_hdl_ent_t *
cmih_ent_lookup(struct cmih_walk_state *wsp)
{
	if (wsp == NULL || wsp->chip_tab[wsp->chipid] == NULL)
		return (NULL);	/* chip is not present */

	return (wsp->chip_tab[wsp->chipid] +
	    (((wsp->coreid & CMI_MAX_COREID(wsp->core_nbits)) <<
	    wsp->strand_nbits) |
	    ((wsp->strandid) & CMI_MAX_STRANDID(wsp->strand_nbits))));
}

/* forward decls */
static void
cmih_walk_fini(mdb_walk_state_t *wsp);

static int
cmih_walk_init(mdb_walk_state_t *wsp)
{
	int i;
	ssize_t sz;
	struct cmih_walk_state *awsp;
	void *pg;
	cmi_hdl_ent_t *ent;

	if (wsp->walk_addr != NULL) {
		mdb_warn("cmihdl is a global walker\n");
		return (WALK_ERR);
	}

	wsp->walk_data = awsp =
	    mdb_zalloc(sizeof (struct cmih_walk_state), UM_SLEEP);

	/* read the number of core bits and strand bits */
	if (mdb_readvar(&awsp->core_nbits, "cmi_core_nbits") == -1) {
		mdb_warn("read of cmi_core_nbits failed");
		mdb_free(wsp->walk_data, sizeof (struct cmih_walk_state));
		wsp->walk_data = NULL;
		return (WALK_ERR);
	}
	if (mdb_readvar(&awsp->strand_nbits, "cmi_strand_nbits") == -1) {
		mdb_warn("read of cmi_strand_nbits failed");
		mdb_free(wsp->walk_data, sizeof (struct cmih_walk_state));
		wsp->walk_data = NULL;
		return (WALK_ERR);
	}

	/* table of chipid entries */
	if ((sz = mdb_readvar(&awsp->chip_tab, "cmi_chip_tab")) == -1) {
		mdb_warn("read of cmi_chip_tab failed");
		mdb_free(wsp->walk_data, sizeof (struct cmih_walk_state));
		wsp->walk_data = NULL;
		return (WALK_ERR);
	} else if (sz < sizeof (awsp->chip_tab)) {
		mdb_warn("Unexpected cmi_chip_tab size (exp=%ld, actual=%ld)",
		    sizeof (awsp->chip_tab), sz);
		mdb_free(wsp->walk_data, sizeof (struct cmih_walk_state));
		wsp->walk_data = NULL;
		return (WALK_ERR);
	}

	/* read the per-chip table that contains all strands of the chip */
	sz = CMI_MAX_STRANDS_PER_CHIP(awsp->core_nbits, awsp->strand_nbits) *
	    sizeof (cmi_hdl_ent_t);
	for (i = 0; i < CMI_CHIPID_ARR_SZ; i++) {
		if (awsp->chip_tab[i] == NULL)
			continue; /* this chip(i) is not present */
		pg = mdb_alloc(sz, UM_SLEEP);
		if (mdb_vread(pg, sz, (uintptr_t)awsp->chip_tab[i]) != sz) {
			mdb_warn("read of cmi_hdl(%i) array at 0x%p failed",
			    i, awsp->chip_tab[i]);
			mdb_free(pg, sz);
			cmih_walk_fini(wsp);
			return (WALK_ERR);
		}
		awsp->chip_tab[i] = pg;
	}

	/* Look up the hdl of the first strand <0,0,0> */
	wsp->walk_addr = NULL;
	if ((ent = cmih_ent_lookup(awsp)) != NULL)
		wsp->walk_addr = (uintptr_t)ent->cmae_hdlp;

	return (WALK_NEXT);
}

static int
cmih_walk_step(mdb_walk_state_t *wsp)
{
	struct cmih_walk_state *awsp = wsp->walk_data;
	uintptr_t addr = NULL;
	cmi_hdl_impl_t hdl;
	cmi_hdl_ent_t *ent;
	int rv;

	if ((ent = cmih_ent_lookup(awsp)) != NULL)
		addr = (uintptr_t)ent->cmae_hdlp;
	if (wsp->walk_addr == NULL || addr == NULL)
		return (cmih_ent_next(awsp) ? WALK_NEXT : WALK_DONE);

	if (mdb_vread(&hdl, sizeof (hdl), addr) != sizeof (hdl)) {
		mdb_warn("read of handle at 0x%p failed", addr);
		return (WALK_DONE);
	}

	if ((rv = wsp->walk_callback(addr, (void *)&hdl,
	    wsp->walk_cbdata)) != WALK_NEXT)
		return (rv);

	return (cmih_ent_next(awsp) ? WALK_NEXT : WALK_DONE);
}

static void
cmih_walk_fini(mdb_walk_state_t *wsp)
{
	struct cmih_walk_state *awsp = wsp->walk_data;

	if (awsp != NULL) {
		int i;
		int max_strands = CMI_MAX_STRANDS_PER_CHIP(awsp->core_nbits,
		    awsp->strand_nbits);
		for (i = 0; i < CMI_CHIPID_ARR_SZ; i++) {
			/* free the per-chip table */
			if (awsp->chip_tab[i] != NULL) {
				mdb_free((void *)awsp->chip_tab[i],
				    max_strands * sizeof (cmi_hdl_ent_t));
				awsp->chip_tab[i] = NULL;
			}
		}
		mdb_free(wsp->walk_data, sizeof (struct cmih_walk_state));
		wsp->walk_data = NULL;
	}
}

struct cmihdl_cb {
	int mod_cpuid;
	int mod_chipid;
	int mod_coreid;
	int mod_strandid;
	uintptr_t mod_hdladdr;
};

static int
cmihdl_cb(uintptr_t addr, const void *arg, void *data)
{
	cmi_hdl_impl_t *hdl = (cmi_hdl_impl_t *)arg;
	struct cmihdl_cb *cbp = data;
	cpu_t *cp;
	int rv;

	if (cbp->mod_cpuid != -1) {
		cp = mdb_alloc(sizeof (cpu_t), UM_SLEEP);
		if (mdb_vread(cp, sizeof (cpu_t),
		    (uintptr_t)hdl->cmih_hdlpriv) != sizeof (cpu_t)) {
			mdb_warn("Read of cpu_t at 0x%p failed",
			    hdl->cmih_hdlpriv);
			mdb_free(cp, sizeof (cpu_t));
			return (WALK_ERR);
		}

		if (cp->cpu_id == cbp->mod_cpuid) {
			cbp->mod_hdladdr = addr;
			rv = WALK_DONE;
		} else {
			rv = WALK_NEXT;
		}

		mdb_free(cp, sizeof (cpu_t));
		return (rv);
	} else {
		if (hdl->cmih_chipid == cbp->mod_chipid &&
		    hdl->cmih_coreid == cbp->mod_coreid &&
		    hdl->cmih_strandid == cbp->mod_strandid) {
			cbp->mod_hdladdr = addr;
			return (WALK_DONE);
		} else {
			return (WALK_NEXT);
		}
	}
}

static int
cmihdl_disp(uintptr_t addr, cmi_hdl_impl_t *hdl)
{
	struct cms_ctl cmsctl;			/* 16 bytes max */
	struct modctl cmimodc, cmsmodc;		/* 288 bytes max */
	cmi_t cmi;				/* 40 bytes max */
	cms_t cms;				/* 40 bytes max */
	cpu_t *cp;
	char cmimodnm[25], cmsmodnm[25];	/* 50 bytes */
	char cpuidstr[4], hwidstr[16];
	int native = hdl->cmih_class == CMI_HDL_NATIVE;
	uint32_t refcnt;

	cmimodnm[0] = cmsmodnm[0] = '-';
	cmimodnm[1] = cmsmodnm[1] = '\0';

	if (hdl->cmih_cmi != NULL) {
		if (mdb_vread(&cmi, sizeof (cmi_t),
		    (uintptr_t)hdl->cmih_cmi) != sizeof (cmi)) {
			mdb_warn("Read of cmi_t at 0x%p failed",
			    hdl->cmih_cmi);
			return (0);
		}

		if (cmi.cmi_modp != NULL) {
			if (mdb_vread(&cmimodc, sizeof (struct modctl),
			    (uintptr_t)cmi.cmi_modp) != sizeof (cmimodc)) {
				mdb_warn("Read of modctl at 0x%p failed",
				    cmi.cmi_modp);
				return (0);
			}

			if (mdb_readstr(cmimodnm, sizeof (cmimodnm),
			    (uintptr_t)cmimodc.mod_modname) == -1) {
				mdb_warn("Read of cmi module name at 0x%p "
				    "failed", cmimodc.mod_modname);
				return (0);
			}
		}
	}

	if (hdl->cmih_spec != NULL) {
		if (mdb_vread(&cmsctl, sizeof (struct cms_ctl),
		    (uintptr_t)hdl->cmih_spec) != sizeof (cmsctl)) {
			mdb_warn("Read of struct cms_ctl at 0x%p failed",
			    hdl->cmih_spec);
			return (0);
		}

		if (mdb_vread(&cms, sizeof (cms_t),
		    (uintptr_t)cmsctl.cs_cms) != sizeof (cms)) {
			mdb_warn("Read of cms_t at 0x%p failed", cmsctl.cs_cms);
			return (0);
		}

		if (cms.cms_modp != NULL) {
			if (mdb_vread(&cmsmodc, sizeof (struct modctl),
			    (uintptr_t)cms.cms_modp) != sizeof (cmsmodc)) {
				mdb_warn("Read of modctl at 0x%p failed",
				    cms.cms_modp);
				return (0);
			}

			if (mdb_readstr(cmsmodnm, sizeof (cmsmodnm),
			    (uintptr_t)cmsmodc.mod_modname) == -1) {
				mdb_warn("Read of cms module name at 0x%p "
				    "failed", cmsmodc.mod_modname);
				return (0);
			}
		}
	}

	if (mdb_vread(&refcnt, sizeof (uint32_t),
	    (uintptr_t)hdl->cmih_refcntp) != sizeof (uint32_t)) {
		mdb_warn("Read of reference count for hdl 0x%p failed", hdl);
		return (0);
	}

	if (native) {
		cp = mdb_alloc(sizeof (cpu_t), UM_SLEEP);

		if (mdb_vread(cp, sizeof (cpu_t),
		    (uintptr_t)hdl->cmih_hdlpriv) != sizeof (cpu_t)) {
			mdb_free(cp, sizeof (cpu_t));
			mdb_warn("Read of cpu_t at 0x%p failed",
			    hdl->cmih_hdlpriv);
			return (0);
		}
	}

	if (native) {
		(void) mdb_snprintf(cpuidstr, sizeof (cpuidstr), "%d",
		    cp->cpu_id);
	} else {
		(void) mdb_snprintf(cpuidstr, sizeof (cpuidstr), "-");
	}

	(void) mdb_snprintf(hwidstr, sizeof (hwidstr), "%d/%d/%d",
	    hdl->cmih_chipid, hdl->cmih_coreid, hdl->cmih_strandid);

	mdb_printf("%16lx %3d %3s %8s %3s %2s %-13s %-24s\n", addr,
	    refcnt, cpuidstr, hwidstr, hdl->cmih_mstrand ? "M" : "S",
	    hdl->cmih_mcops ? "Y" : "N", cmimodnm, cmsmodnm);

	if (native)
		mdb_free(cp, sizeof (cpu_t));

	return (1);
}

#define	HDRFMT "%-16s %3s %3s %8s %3s %2s %-13s %-24s\n"

static int
cmihdl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct cmihdl_cb cb;
	cmi_hdl_impl_t *hdl;

	/*
	 * If an address is given it must be that of a cmi handle.
	 * Otherwise if the user has specified -c <cpuid> or
	 * -c <chipid/coreid/strandid> we will lookup a matching handle.
	 * Otherwise we'll walk and callback to this dcmd.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		char *p, *buf;
		int len;

		if (argc == 0)
			return (mdb_walk_dcmd("cmihdl", "cmihdl", argc,
			    argv) == 0 ? DCMD_OK : DCMD_ERR);


		if (mdb_getopts(argc, argv,
		    'c', MDB_OPT_STR, &p,
		    NULL) != argc)
			return (DCMD_USAGE);

		if ((len = strlen(p)) == 0) {
			return (DCMD_USAGE);
		} else {
			buf = mdb_alloc(len + 1, UM_SLEEP);
			strcpy(buf, p);
		}

		cb.mod_cpuid = cb.mod_chipid = cb.mod_coreid =
		    cb.mod_strandid = -1;

		if ((p = strchr(buf, '/')) == NULL) {
			/* Native cpuid */
			cb.mod_cpuid = (int)mdb_strtoull(buf);
		} else {
			/* Comma-separated triplet chip,core,strand. */
			char *q = buf;

			*p = '\0';
			cb.mod_chipid = (int)mdb_strtoull(q);

			if ((q = p + 1) >= buf + len ||
			    (p = strchr(q, '/')) == NULL) {
				mdb_free(buf, len);
				return (DCMD_USAGE);
			}

			*p = '\0';
			cb.mod_coreid = (int)mdb_strtoull(q);

			if ((q = p + 1) >= buf + len) {
				mdb_free(buf, len);
				return (DCMD_USAGE);
			}

			cb.mod_strandid = (int)mdb_strtoull(q);
		}

		mdb_free(buf, len);

		cb.mod_hdladdr = NULL;
		if (mdb_walk("cmihdl", cmihdl_cb, &cb) == -1) {
			mdb_warn("cmi_hdl walk failed\n");
			return (DCMD_ERR);
		}

		if (cb.mod_hdladdr == NULL) {
			if (cb.mod_cpuid != -1) {
				mdb_warn("No handle found for cpuid %d\n",
				    cb.mod_cpuid);
			} else {

				mdb_warn("No handle found for chip %d "
				    "core %d strand %d\n", cb.mod_chipid,
				    cb.mod_coreid, cb.mod_strandid);
			}
			return (DCMD_ERR);
		}

		addr = cb.mod_hdladdr;
	}

	if (DCMD_HDRSPEC(flags)) {
		char ul[] = "----------------------------";
		char *p = ul + sizeof (ul) - 1;

		mdb_printf(HDRFMT HDRFMT,
		    "HANDLE", "REF", "CPU", "CH/CR/ST", "CMT", "MC",
		    "MODULE", "MODEL-SPECIFIC",
		    p - 16,  p - 3, p - 3, p - 8, p - 3, p - 2, p - 13, p - 24);
	}

	hdl = mdb_alloc(sizeof (cmi_hdl_impl_t), UM_SLEEP);

	if (mdb_vread(hdl, sizeof (cmi_hdl_impl_t), addr) !=
	    sizeof (cmi_hdl_impl_t)) {
		mdb_free(hdl, sizeof (cmi_hdl_impl_t));
		mdb_warn("Read of cmi handle at 0x%p failed", addr);
		return (DCMD_ERR);
	}

	if (!cmihdl_disp(addr, hdl)) {
		mdb_free(hdl, sizeof (cmi_hdl_impl_t));
		return (DCMD_ERR);
	}

	mdb_free(hdl, sizeof (cmi_hdl_impl_t));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
gcpu_mpt_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const char *const whatstrs[] = {
		"ntv-cyc-poll",		/* GCPU_MPT_WHAT_CYC_ERR */
		"poll-poked",		/* GCPU_MPT_WHAT_POKE_ERR */
		"unfaulting",		/* GCPU_MPT_WHAT_UNFAULTING */
		"#MC",			/* GCPU_MPT_WHAT_MC_ERR */
		"CMCI-int",		/* GCPU_MPT_WHAT_CMCI_ERR */
		"xpv-virq-nrec",	/* GCPU_MPT_WHAT_XPV_VIRQ */
		"xpv-virq-lgout",	/* GCPU_MPT_WHAT_XPV_VIRQ_LOGOUT */
	};

	gcpu_poll_trace_t mpt;
	const char *what;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&mpt, sizeof (mpt), addr) != sizeof (mpt)) {
		mdb_warn("failed to read gcpu_poll_trace_t at 0x%p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s%</u> %<u>%?s%</u> %<u>%15s%</u> "
		    "%<u>%4s%</u>\n", "ADDR", "WHEN", "WHAT", "NERR");
	}

	if (mpt.mpt_what < sizeof (whatstrs) / sizeof (char *))
		what = whatstrs[mpt.mpt_what];
	else
		what = "???";

	mdb_printf("%?p %?p %15s %4u\n", addr, mpt.mpt_when, what,
	    mpt.mpt_nerr);

	return (DCMD_OK);
}

typedef struct mptwalk_data {
	uintptr_t mw_traceaddr;
	gcpu_poll_trace_t *mw_trace;
	size_t mw_tracesz;
	uint_t mw_tracenent;
	uint_t mw_curtrace;
} mptwalk_data_t;

static int
gcpu_mptwalk_init(mdb_walk_state_t *wsp)
{
	gcpu_poll_trace_t *mpt;
	mptwalk_data_t *mw;
	GElf_Sym sym;
	uint_t nent, i;
	hrtime_t latest;

	if (wsp->walk_addr == NULL) {
		mdb_warn("the address of a poll trace array must be "
		    "specified\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("gcpu_poll_trace_nent", &sym) < 0 ||
	    sym.st_size != sizeof (uint_t) || mdb_vread(&nent, sizeof (uint_t),
	    sym.st_value) != sizeof (uint_t)) {
		mdb_warn("failed to read gcpu_poll_trace_nent from kernel");
		return (WALK_ERR);
	}

	mw = mdb_alloc(sizeof (mptwalk_data_t), UM_SLEEP);
	mw->mw_traceaddr = wsp->walk_addr;
	mw->mw_tracenent = nent;
	mw->mw_tracesz = nent * sizeof (gcpu_poll_trace_t);
	mw->mw_trace = mdb_alloc(mw->mw_tracesz, UM_SLEEP);

	if (mdb_vread(mw->mw_trace, mw->mw_tracesz, wsp->walk_addr) !=
	    mw->mw_tracesz) {
		mdb_free(mw->mw_trace, mw->mw_tracesz);
		mdb_free(mw, sizeof (mptwalk_data_t));
		mdb_warn("failed to read poll trace array from kernel");
		return (WALK_ERR);
	}

	latest = 0;
	mw->mw_curtrace = 0;
	for (mpt = mw->mw_trace, i = 0; i < mw->mw_tracenent; i++, mpt++) {
		if (mpt->mpt_when > latest) {
			latest = mpt->mpt_when;
			mw->mw_curtrace = i;
		}
	}

	if (latest == 0) {
		mdb_free(mw->mw_trace, mw->mw_tracesz);
		mdb_free(mw, sizeof (mptwalk_data_t));
		return (WALK_DONE); /* trace array is empty */
	}

	wsp->walk_data = mw;

	return (WALK_NEXT);
}

static int
gcpu_mptwalk_step(mdb_walk_state_t *wsp)
{
	mptwalk_data_t *mw = wsp->walk_data;
	gcpu_poll_trace_t *thismpt, *prevmpt;
	int prev, rv;

	thismpt = &mw->mw_trace[mw->mw_curtrace];

	rv = wsp->walk_callback(mw->mw_traceaddr + (mw->mw_curtrace *
	    sizeof (gcpu_poll_trace_t)), thismpt, wsp->walk_cbdata);

	if (rv != WALK_NEXT)
		return (rv);

	prev = (mw->mw_curtrace - 1) % mw->mw_tracenent;
	prevmpt = &mw->mw_trace[prev];

	if (prevmpt->mpt_when == 0 || prevmpt->mpt_when > thismpt->mpt_when)
		return (WALK_DONE);

	mw->mw_curtrace = prev;

	return (WALK_NEXT);
}

static void
gcpu_mptwalk_fini(mdb_walk_state_t *wsp)
{
	mptwalk_data_t *mw = wsp->walk_data;

	mdb_free(mw->mw_trace, mw->mw_tracesz);
	mdb_free(mw, sizeof (mptwalk_data_t));
}

static const mdb_dcmd_t dcmds[] = {
	{ "cmihdl", ": -c <cpuid>|<chip,core,strand> ",
	    "dump a cmi_handle_t", cmihdl },
	{ "gcpu_poll_trace", ":", "dump a poll trace buffer", gcpu_mpt_dump },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "cmihdl", "walks cpu module interface handle list",
	    cmih_walk_init, cmih_walk_step, cmih_walk_fini, NULL },
	{ "gcpu_poll_trace", "walks poll trace buffers in reverse "
	    "chronological order", gcpu_mptwalk_init, gcpu_mptwalk_step,
	    gcpu_mptwalk_fini, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
