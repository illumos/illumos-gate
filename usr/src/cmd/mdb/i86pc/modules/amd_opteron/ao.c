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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <amd_opteron/ao.h>

#define	ALLBITS	(u_longlong_t)-1

static const mdb_bitmask_t ao_nbcfg_bits[] = {
	{ "NbMcaToMstCpuEn", ALLBITS, AMD_NB_CFG_NBMCATOMSTCPUEN },
	{ "DisPciCfgCpuErrRsp", ALLBITS, AMD_NB_CFG_DISPCICFGCPUERRRSP },
	{ "IoRdDatErrEn", ALLBITS, AMD_NB_CFG_IORDDATERREN },
	{ "ChipKillEccEn", ALLBITS, AMD_NB_CFG_CHIPKILLECCEN },
	{ "EccEn", ALLBITS, AMD_NB_CFG_ECCEN },
	{ "SyncOnAnyErrEn", ALLBITS, AMD_NB_CFG_SYNCONANYERREN },
	{ "SyncOnWdogEn", ALLBITS, AMD_NB_CFG_SYNCONWDOGEN },
	{ "GenCrcErrByte1", ALLBITS, AMD_NB_CFG_GENCRCERRBYTE1 },
	{ "GenCrcErrByte0", ALLBITS, AMD_NB_CFG_GENCRCERRBYTE0 },
	/* LdtLinkSel handled separately */
	/* WdogTmrBaseSel handled separately */
	/* WdogTmrCntSel handled separately */
	/* WdogTmrDis handled separately */
	{ "IoErrDis", ALLBITS, AMD_NB_CFG_IOERRDIS },
	{ "CpuErrDis", ALLBITS, AMD_NB_CFG_CPUERRDIS },
	{ "IoMstAbortDis", ALLBITS, AMD_NB_CFG_IOMSTABORTDIS },
	{ "SyncPktPropDis", ALLBITS, AMD_NB_CFG_SYNCPKTPROPDIS },
	{ "SyncPktGenDis", ALLBITS, AMD_NB_CFG_SYNCPKTGENDIS },
	{ "SyncOnUcEccEn", ALLBITS, AMD_NB_CFG_SYNCONUCECCEN },
	{ "CpuRdDatErrEn", ALLBITS, AMD_NB_CFG_CPURDDATERREN }
};

/*ARGSUSED*/
static int
ao_nbcfg_describe(uintptr_t val, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_bitmask_t *bm;
	uintptr_t field;
	int nbits, i;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	for (nbits = 0, bm = ao_nbcfg_bits, i = 0;
	    i < sizeof (ao_nbcfg_bits) / sizeof (mdb_bitmask_t); i++, bm++) {
		if (!(val & bm->bm_bits))
			continue;

		mdb_printf("\t0x%08x  %s\n", bm->bm_bits, bm->bm_name);

		val &= ~bm->bm_bits;
		nbits++;
	}

	if ((field = (val & AMD_NB_CFG_LDTLINKSEL_MASK)) != 0) {
		mdb_printf("\tLdtLinkSel = %d", field >>
		    AMD_NB_CFG_LDTLINKSEL_SHIFT);
	}

	if (!(val & AMD_NB_CFG_WDOGTMRDIS)) {
		static const uint_t wdogcounts[] = {
			4095, 2047, 1023, 511, 255, 127, 63, 31
		};

		uintptr_t cntfld = (val & AMD_NB_CFG_WDOGTMRCNTSEL_MASK);
		uintptr_t basefld = (val & AMD_NB_CFG_WDOGTMRBASESEL_MASK);
		uintptr_t count;
		int valid = 1;
		const char *units;

		if (cntfld < sizeof (wdogcounts) / sizeof (uint_t))
			count = wdogcounts[cntfld];
		else
			valid = 0;

		switch (basefld) {
		case AMD_NB_CFG_WDOGTMRBASESEL_1MS:
			units = "ms";
			break;
		case AMD_NB_CFG_WDOGTMRBASESEL_1US:
			units = "us";
			break;
		case AMD_NB_CFG_WDOGTMRBASESEL_5NS:
			count *= 5;
			units = "ns";
			break;
		default:
			units = " (unknown units)";
			break;
		}

		if (valid) {
			mdb_printf("\tWatchdog timeout: %u%s\n", count,
			    units);
		} else {
			mdb_printf("\tInvalid Watchdog: Count %u, Base %u\n",
			    cntfld, basefld);
		}
	}

	return (DCMD_OK);
}

/*ARGSUSED3*/
static int
ao_mpt_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const char *const whatstrs[] = {
		"cyc-err", "poke-err", "unfault"
	};

	ao_mca_poll_trace_t mpt;
	const char *what;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&mpt, sizeof (mpt), addr) != sizeof (mpt)) {
		mdb_warn("failed to read ao_mca_poll_trace_t at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s%</u> %<u>%?s%</u> %<u>%9s%</u> "
		    "%<u>%4s%</u>\n", "ADDR", "WHEN", "WHAT", "NERR");
	}

	if (mpt.mpt_what < sizeof (whatstrs) / sizeof (char *))
		what = whatstrs[mpt.mpt_what];
	else
		what = "???";

	mdb_printf("%?p %?p %9s %4u\n", addr, mpt.mpt_when, what,
	    mpt.mpt_nerr);

	return (DCMD_OK);
}

typedef struct mptwalk_data {
	uintptr_t mw_traceaddr;
	ao_mca_poll_trace_t *mw_trace;
	size_t mw_tracesz;
	uint_t mw_tracenent;
	uint_t mw_curtrace;
} mptwalk_data_t;

static int
ao_mptwalk_init(mdb_walk_state_t *wsp)
{
	ao_mca_poll_trace_t *mpt;
	mptwalk_data_t *mw;
	GElf_Sym sym;
	uint_t nent, i;
	hrtime_t latest;

	if (wsp->walk_addr == NULL) {
		mdb_warn("the address of a poll trace array must be specified");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("ao_mca_poll_trace_nent", &sym) < 0 ||
	    sym.st_size != sizeof (uint_t) || mdb_vread(&nent, sizeof (uint_t),
	    sym.st_value) != sizeof (uint_t)) {
		mdb_warn("failed to read ao_mca_poll_trace_nent from kernel");
		return (WALK_ERR);
	}

	mw = mdb_alloc(sizeof (mptwalk_data_t), UM_SLEEP);
	mw->mw_traceaddr = wsp->walk_addr;
	mw->mw_tracenent = nent;
	mw->mw_tracesz = nent * sizeof (ao_mca_poll_trace_t);
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
ao_mptwalk_step(mdb_walk_state_t *wsp)
{
	mptwalk_data_t *mw = wsp->walk_data;
	ao_mca_poll_trace_t *thismpt, *prevmpt;
	int prev, rv;

	thismpt = &mw->mw_trace[mw->mw_curtrace];

	rv = wsp->walk_callback(mw->mw_traceaddr + (mw->mw_curtrace *
	    sizeof (ao_mca_poll_trace_t)), thismpt, wsp->walk_cbdata);

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
ao_mptwalk_fini(mdb_walk_state_t *wsp)
{
	mptwalk_data_t *mw = wsp->walk_data;

	mdb_free(mw->mw_trace, mw->mw_tracesz);
	mdb_free(mw, sizeof (mptwalk_data_t));
}

static const mdb_dcmd_t dcmds[] = {
	{ "ao_poll_trace", ":", "dump a poll trace buffer", ao_mpt_dump },
	{ "ao_nbcfg", ":", "decode Northbridge config bits",
	    ao_nbcfg_describe },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ao_poll_trace", "walks poll trace buffers in reverse chronological "
	    "order", ao_mptwalk_init, ao_mptwalk_step, ao_mptwalk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
