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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <amd_opteron/ao.h>

#define	ALLBITS	(u_longlong_t)-1

static const mdb_bitmask_t ao_nbcfg_bits[] = {
	{ "SyncOnDramAdrParErrEn", ALLBITS, AMD_NB_CFG_SYNCONDRAMADRPARERREN },
	{ "NbMcaToMstCpuEn", ALLBITS, AMD_NB_CFG_NBMCATOMSTCPUEN },
	{ "ReservedBit26", ALLBITS, 0x4000000 },
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

	if (val & AMD_NB_CFG_WDOGTMRDIS) {
		mdb_printf("\t0x%08x  %s\n", AMD_NB_CFG_WDOGTMRDIS,
		    "WdogTmrDis");
	} else {
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

static const char *ao_scrub_rate[] = {
	"Do not scrub",		/* 0b00000 */
	"40.0 nanosec",		/* 0b00001 */
	"80.0 nanosec",		/* 0b00010 */
	"160.0 nanosec",	/* 0b00011 */
	"320.0 nanosec",	/* 0b00100 */
	"640.0 nanosec",	/* 0b00101 */
	"1.28 microsec",	/* 0b00110 */
	"2.56 microsec",	/* 0b00111 */
	"5.12 microsec",	/* 0b01000 */
	"10.2 microsec",	/* 0b01001 */
	"20.5 microsec",	/* 0b01010 */
	"41.0 microsec",	/* 0b01011 */
	"81.9 microsec",	/* 0b01100 */
	"163.8 microsec",	/* 0b01101 */
	"327.7 microsec",	/* 0b01110 */
	"655.4 microsec",	/* 0b01111 */
	"1.31 millsec",		/* 0b10000 */
	"2.62 millsec",		/* 0b10001 */
	"5.24 millsec",		/* 0b10010 */
	"10.49 millsec",	/* 0b10011 */
	"20.97 millsec",	/* 0b10100 */
	"42.00 millsec",	/* 0b10101 */
	"84.00 millsec",	/* 0b10110 */
};

#define	SCRUBCODE(val, low) ((val) >> low & 0x1f)

#define	SCRUBSTR(val, low) \
	(SCRUBCODE(val, low) < sizeof (ao_scrub_rate) / sizeof (char *) ? \
	ao_scrub_rate[SCRUBCODE(val, low)] : "reserved value!")

/*ARGSUSED*/
static int
ao_scrubctl_describe(uintptr_t val, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	mdb_printf("\tDcacheScrub: %s\n\t    L2Scrub: %s\n\t  DramScrub: %s\n",
	    SCRUBSTR(val, 16), SCRUBSTR(val, 8), SCRUBSTR(val, 0));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
ao_sparectl_describe(uintptr_t val, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	const char *itypes[] = {
		"No Interrupt",	/* 0b00 */
		"Reserved",	/* 0b01 */
		"SMI",		/* 0b10 */
		"Reserved",	/* 0b11 */
	};

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	mdb_printf(
	    "\t  EccErrInt: %s\n"
	    "\tSwapDoneInt: %s\n"
	    "\t  BadDramCs: %d\n"
	    "\t   SwapDone: %s\n"
	    "\t     SwapEn: %s\n",
	    itypes[val >> 14 & 0x3],
	    itypes[val >> 12 & 0x3],
	    val >> 4 & 0x7,
	    val & 0x2 ? "Yes" : "No",
	    val & 0x1 ? "Yes" : "No");

	return (DCMD_OK);
}

static const char *ao_mcactl_dc[] = {
	"ECCI (Single-bit ECC Data Errors)",
	"ECCM (Multi-bit ECC Data Errors)",
	"DECC (Data Array ECC Errors)",
	"DMTP (Main Tag Array Parity Errors)",
	"DSTP (Snoop Tag Array Parity Errors)",
	"L1TP (L1 TLB Parity Errors)",
	"L2TP (L2 TLB Parity Errors)",
};

static const char *ao_mcactl_ic[] = {
	"ECCI (Single-bit ECC data errors)",
	"ECCM (Multi-bit ECC data errors)",
	"IDP (Data array parity errors)",
	"IMTP (Main tag array parity errors)",
	"ISTP (Snoop tag array parity errors)",
	"L1TP (L1 TLB Parity Errors)",
	"L2TP (L2 TLB Parity Errors)",
	NULL,	/* reserved */
	NULL,	/* reserved */
	"RDDE (Read Data Errors)",
};

static const char *ao_mcactl_bu[] = {
	"S_RDE_HP (System read data hardware prefetch)",
	"S_RDE_TLB (System read data TLB reload)",
	"S_RDE_ALL (All system read data)",
	"S_ECC1_TLB (System data 1-bit ECC TLB reload)",
	"S_ECC1_HP (System data 1-bit ECC hardware prefetch)",
	"S_ECCM_TLB (System data multi-bit ECC TLB reload)",
	"S_ECCM_HP (System data multi-bit ECC hardware prefetch)",
	"L2T_PAR_ICDC (L2 tag array parity IC or DC fetch)",
	"L2T_PAR_TLB (L2 tag array parity TLB reload)",
	"L2T_PAR_SNP (L2 tag array parity snoop)",
	"L2T_PAR_CPB (L2 tag array parity copyback)",
	"L2T_PAR_SCR (L2 tag array parity scrub)",
	"L2D_ECC1_TLB (L2 data array 1-bit ECC TLB reload)",
	"L2D_ECC1_SNP (L2 data array 1-bit ECC snoop)",
	"L2D_ECC1_CPB (L2 data array 1-bit ECC copyback)",
	"L2D_ECCM_TLB (L2 data array multi-bit ECC TLB reload)",
	"L2D_ECCM_SNP (L2 data array multi-bit ECC snoop)",
	"L2D_ECCM_CPB (L2 data array multi-bit ECC copyback)",
	"L2T_ECC1_SCR (L2 tag array 1-bit ECC Scrub)",
	"L2T_ECCM_SCR (L2 tag array multi-bit ECC Scrub)",
};

static const char *ao_mcactl_ls[] = {
	"S_RDE_L (Read Data Errors on Load)",
	"S_RDE_S (Read Data Errors on Store)",
};

static const char *ao_mcactl_nb[] = {
	"CorrEccEn (Correctable ECC Error Reporting Enable)",
	"UnCorrEccEn (Uncorrectable ECC Error Reporting Enable)",
	"CrcErr0En (HT Link 0 CRC Error Reporting Enable)",
	"CrcErr1En (HT Link 1 CRC Error Reporting Enable)",
	"CrcErr2En (HT Link 2 CRC Error Reporting Enable)",
	"SyncPkt0En (HT Link 0 Sync Packet Error Reporting Enable)",
	"SyncPkt1En (HT Link 1 Sync Packet Error Reporting Enable)",
	"SyncPkt2En (HT Link 2 Sync Packet Error Reporting Enable)",
	"MstrAbrtEn (Master Abort Error Reporting Enable)",
	"TgtAbrtEn (Target Abort Error Reporting Enable)",
	"GartTblWkEn (GART Table Walk Error Reporting Enable)",
	"AtomicRMWEn (Atomic Read-Modify-Write Error Reporting Enable)",
	"WchDogTmrEn (Watchdog Timer Error Reporting Enable)",
	NULL,	/* reserved */
	NULL,	/* reserved */
	NULL,	/* reserved */
	NULL,	/* reserved */
	NULL,	/* reserved */
	"DramParEn (DRAM Parity Error Reporting enable)",
};

static const struct ao_mcactl {
	const char *bank_name;
	const char **bank_ctlbits;
	int bank_tblsz;
} ao_mcactls[] = {
	{ "dc", &ao_mcactl_dc[0], sizeof (ao_mcactl_dc) / sizeof (char *) },
	{ "ic", &ao_mcactl_ic[0], sizeof (ao_mcactl_ic) / sizeof (char *) },
	{ "bu", &ao_mcactl_bu[0], sizeof (ao_mcactl_bu) / sizeof (char *) },
	{ "ls", &ao_mcactl_ls[0], sizeof (ao_mcactl_ls) / sizeof (char *) },
	{ "nb", &ao_mcactl_nb[0], sizeof (ao_mcactl_nb) / sizeof (char *) }
};

#define	AO_MCI_CTL	0x0
#define	AO_MCI_MASK	0x1

static int
ao_mci_ctlmask_common(uintptr_t val, uint_t flags, int argc,
    const mdb_arg_t *argv, int which)
{
	uint64_t bank;
	const char *bankname = NULL;
	int i;

	if (argc != 2 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    't', MDB_OPT_STR, &bankname, NULL) != 2)
		return (DCMD_USAGE);

	for (i = 0; i < AMD_MCA_BANK_COUNT; i++) {
		if (strncmp(bankname, ao_mcactls[i].bank_name,
		    2) == 0) {
			bank = i;
			break;
		}
	}

	if (i == AMD_MCA_BANK_COUNT) {
		mdb_warn("Valid bank names: dc, ic, bu, ls, nb\n");
		return (DCMD_ERR);
	}

	mdb_printf("Reporting %s for %s:\n", which == AO_MCI_CTL ? "enables" :
	    "masks", ao_mcactls[bank].bank_name);
	mdb_printf("%3s %4s %s\n", "Bit", "Set?", "Description");

	for (i = 0; i < 63; i++) {
		int set = val & 0x1ULL << i;
		int inrange = i < ao_mcactls[bank].bank_tblsz;
		const char *desc = ao_mcactls[bank].bank_ctlbits[i];

		if (inrange) {
			int known = desc != NULL;

			mdb_printf("%2d  %4s ", i, set ? "Yes" : "- ");
			if (known)
				mdb_printf("%s\n", desc);
			else
				mdb_printf("reserved%s\n",
				    set ? " - but set!" : "");
		} else if (set) {
				mdb_printf("%2d  %4s Reserved - but set!\n",
				    i, "Yes");
		}
	}

	return (DCMD_OK);
}

/*ARGSUSED3*/
static int
ao_mci_ctl(uintptr_t val, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ao_mci_ctlmask_common(val, flags, argc, argv, AO_MCI_CTL));
}

/*ARGSUSED3*/
static int
ao_mci_mask(uintptr_t val, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (ao_mci_ctlmask_common(val, flags, argc, argv, AO_MCI_MASK));
}

static const mdb_dcmd_t dcmds[] = {
	{ "ao_nbcfg", ":", "decode Northbridge config bits",
	    ao_nbcfg_describe },
	{ "ao_scrubctl", ":", "decode Scrub Control Register",
	    ao_scrubctl_describe },
	{ "ao_sparectl", ":", "decode Online Spare Control Register",
	    ao_sparectl_describe },
	{ "ao_mci_ctl", ":  -t <dc|ic|bu|ls|nb>",
	    "decode MCi_CTL", ao_mci_ctl },
	{ "ao_mci_mask", ":  -t <dc|ic|bu|ls|nb>",
	    "decode MCi_MASK", ao_mci_mask },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
