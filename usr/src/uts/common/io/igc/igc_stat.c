/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This implements the stat routines that interface with the hardware directly.
 */

#include "igc.h"

void
igc_stats_fini(igc_t *igc)
{
	if (igc->igc_ksp != NULL) {
		kstat_delete(igc->igc_ksp);
		igc->igc_ksp = NULL;
	}
}

/*
 * Read a pair of low and high registers to get a stat. The low register must
 * come ahead of the high.
 */
void
igc_stats_update_u64(igc_t *igc, kstat_named_t *ks, uint32_t reg)
{
	uint64_t val = igc_read32(igc, reg);
	val += (uint64_t)igc_read32(igc, reg + 4) << 32UL;
	ks->value.ui64 += val;
}

static int
igc_stats_update(kstat_t *ksp, int rw)
{
	igc_t *igc;
	igc_stats_t *stats;

	if (rw != KSTAT_READ)
		return (EACCES);

	igc = ksp->ks_private;
	stats = &igc->igc_stats;

	mutex_enter(&igc->igc_lock);

	stats->is_crcerrs.value.ui64 += igc_read32(igc, IGC_CRCERRS);
	stats->is_algnerrc.value.ui64 += igc_read32(igc, IGC_ALGNERRC);
	stats->is_mpc.value.ui64 += igc_read32(igc, IGC_MPC);
	stats->is_scc.value.ui64 += igc_read32(igc, IGC_SCC);
	stats->is_ecol.value.ui64 += igc_read32(igc, IGC_ECOL);
	stats->is_mcc.value.ui64 += igc_read32(igc, IGC_MCC);
	stats->is_latecol.value.ui64 += igc_read32(igc, IGC_LATECOL);
	stats->is_colc.value.ui64 += igc_read32(igc, IGC_COLC);
	stats->is_rerc.value.ui64 += igc_read32(igc, IGC_RERC);
	stats->is_dc.value.ui64 += igc_read32(igc, IGC_DC);
	stats->is_tncrs.value.ui64 += igc_read32(igc, IGC_TNCRS);
	stats->is_htdpmc.value.ui64 += igc_read32(igc, IGC_HTDPMC);
	stats->is_rlec.value.ui64 += igc_read32(igc, IGC_RLEC);
	stats->is_xonrxc.value.ui64 += igc_read32(igc, IGC_XONRXC);
	stats->is_xontxc.value.ui64 += igc_read32(igc, IGC_XONTXC);
	stats->is_xoffrxc.value.ui64 += igc_read32(igc, IGC_XOFFRXC);
	stats->is_xofftxc.value.ui64 += igc_read32(igc, IGC_XOFFTXC);
	stats->is_fcruc.value.ui64 += igc_read32(igc, IGC_FCRUC);
	stats->is_prc64.value.ui64 += igc_read32(igc, IGC_PRC64);
	stats->is_prc127.value.ui64 += igc_read32(igc, IGC_PRC127);
	stats->is_prc255.value.ui64 += igc_read32(igc, IGC_PRC255);
	stats->is_prc1023.value.ui64 += igc_read32(igc, IGC_PRC1023);
	stats->is_prc1522.value.ui64 += igc_read32(igc, IGC_PRC1522);
	stats->is_gprc.value.ui64 += igc_read32(igc, IGC_GPRC);
	stats->is_bprc.value.ui64 += igc_read32(igc, IGC_BPRC);
	stats->is_mprc.value.ui64 += igc_read32(igc, IGC_MPRC);
	stats->is_gptc.value.ui64 += igc_read32(igc, IGC_GPTC);
	igc_stats_update_u64(igc, &stats->is_gorc, IGC_GORCL);
	igc_stats_update_u64(igc, &stats->is_gotc, IGC_GOTCL);
	stats->is_rnbc.value.ui64 += igc_read32(igc, IGC_RNBC);
	stats->is_ruc.value.ui64 += igc_read32(igc, IGC_RUC);
	stats->is_rfc.value.ui64 += igc_read32(igc, IGC_RFC);
	stats->is_roc.value.ui64 += igc_read32(igc, IGC_ROC);
	stats->is_rjc.value.ui64 += igc_read32(igc, IGC_RJC);
	stats->is_mgtprc.value.ui64 += igc_read32(igc, IGC_MGTPRC);
	stats->is_mgtpdc.value.ui64 += igc_read32(igc, IGC_MGTPDC);
	stats->is_mgtptc.value.ui64 += igc_read32(igc, IGC_MGTPTC);
	igc_stats_update_u64(igc, &stats->is_tor, IGC_TORL);
	igc_stats_update_u64(igc, &stats->is_tot, IGC_TOTL);
	stats->is_tpr.value.ui64 += igc_read32(igc, IGC_TPR);
	stats->is_tpt.value.ui64 += igc_read32(igc, IGC_TPT);
	stats->is_ptc64.value.ui64 += igc_read32(igc, IGC_PTC64);
	stats->is_ptc127.value.ui64 += igc_read32(igc, IGC_PTC127);
	stats->is_ptc255.value.ui64 += igc_read32(igc, IGC_PTC255);
	stats->is_ptc511.value.ui64 += igc_read32(igc, IGC_PTC511);
	stats->is_ptc1023.value.ui64 += igc_read32(igc, IGC_PTC1023);
	stats->is_ptc1522.value.ui64 += igc_read32(igc, IGC_PTC1522);
	stats->is_mptc.value.ui64 += igc_read32(igc, IGC_MPTC);
	stats->is_bptc.value.ui64 += igc_read32(igc, IGC_BPTC);
	stats->is_tsctc.value.ui64 += igc_read32(igc, IGC_TSCTC);
	stats->is_iac.value.ui64 += igc_read32(igc, IGC_IAC);
	stats->is_rxdmtc.value.ui64 += igc_read32(igc, IGC_RXDMTC);
	mutex_exit(&igc->igc_lock);

	return (0);
}

bool
igc_stats_init(igc_t *igc)
{
	kstat_t *ksp;
	igc_stats_t *stats = &igc->igc_stats;

	ksp = kstat_create(IGC_MOD_NAME, ddi_get_instance(igc->igc_dip),
	    "stats", "net", KSTAT_TYPE_NAMED, sizeof (igc_stats_t) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp == NULL) {
		dev_err(igc->igc_dip, CE_WARN, "failed to create kstats");
		return (false);
	}

	igc->igc_ksp = ksp;
	ksp->ks_update = igc_stats_update;
	ksp->ks_private = igc;
	ksp->ks_data = stats;

	kstat_named_init(&stats->is_crcerrs, "crcerrs",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_algnerrc, "algnerrc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mpc, "mpc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_scc, "scc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ecol, "ecol",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mcc, "mcc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_latecol, "latecol",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_colc, "colc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rerc, "rerc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_dc, "dc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tncrs, "tncrs",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_htdpmc, "htdpmc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rlec, "rlec",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_xonrxc, "xonrxc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_xontxc, "xontxc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_xoffrxc, "xoffrxc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_xofftxc, "xofftxc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_fcruc, "fcruc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_prc64, "prc64",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_prc127, "prc127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_prc255, "prc255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_prc1023, "prc1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_prc1522, "prc1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_gprc, "gprc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_bprc, "bprc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mprc, "mprc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_gptc, "gptc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_gorc, "gorc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_gotc, "gotc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rnbc, "rnbc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ruc, "ruc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rfc, "rfc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_roc, "roc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rjc, "rjc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mgtprc, "mgtprc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mgtpdc, "mgtpdc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mgtptc, "mgtptc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tor, "tor",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tot, "tot",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tpr, "tpr",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tpt, "tpt",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc64, "ptc64",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc127, "ptc127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc255, "ptc255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc511, "ptc511",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc1023, "ptc1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_ptc1522, "ptc1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_mptc, "mptc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_bptc, "bptc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_tsctc, "tsctc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_iac, "iac",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->is_rxdmtc, "rxdmtc",
	    KSTAT_DATA_UINT64);

	kstat_install(ksp);

	return (true);
}

void
igc_rx_ring_stats_fini(igc_rx_ring_t *ring)
{
	if (ring->irr_kstat != NULL) {
		kstat_delete(ring->irr_kstat);
		ring->irr_kstat = NULL;
	}
}

bool
igc_rx_ring_stats_init(igc_t *igc, igc_rx_ring_t *ring)
{
	kstat_t *ksp;
	igc_rx_stats_t *stats = &ring->irr_stat;
	char name[32];

	(void) snprintf(name, sizeof (name), "rxring%u", ring->irr_idx);
	ksp = kstat_create(IGC_MOD_NAME, ddi_get_instance(igc->igc_dip),
	    name, "net", KSTAT_TYPE_NAMED, sizeof (igc_rx_stats_t) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp == NULL) {
		dev_err(igc->igc_dip, CE_WARN, "failed to create rx ring %u "
		    "kstats", ring->irr_idx);
		return (false);
	}

	ring->irr_kstat = ksp;
	ksp->ks_data = stats;

	kstat_named_init(&stats->irs_rbytes, "rbytes", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_ipackets, "ipackets", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_desc_error, "desc_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_copy_nomem, "copy_nomem",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_bind_nobuf, "bind_nobuf",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_bind_nomp, "bind_nomp", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_nbind, "nbind", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_ncopy, "ncopy", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_ixsm, "ixsm", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_l3cksum_err, "l3cksum_err",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_l4cksum_err, "l4cksum_err",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_hcksum_miss, "hcksum_miss",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->irs_hcksum_hit, "hcksum_hit",
	    KSTAT_DATA_UINT64);

	kstat_install(ksp);

	return (true);
}

void
igc_tx_ring_stats_fini(igc_tx_ring_t *ring)
{
	if (ring->itr_kstat != NULL) {
		kstat_delete(ring->itr_kstat);
		ring->itr_kstat = NULL;
	}
}

bool
igc_tx_ring_stats_init(igc_t *igc, igc_tx_ring_t *ring)
{
	kstat_t *ksp;
	igc_tx_stats_t *stats = &ring->itr_stat;
	char name[32];

	(void) snprintf(name, sizeof (name), "txring%u", ring->itr_idx);
	ksp = kstat_create(IGC_MOD_NAME, ddi_get_instance(igc->igc_dip),
	    name, "net", KSTAT_TYPE_NAMED, sizeof (igc_tx_stats_t) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp == NULL) {
		dev_err(igc->igc_dip, CE_WARN, "failed to create tx ring %u "
		    "kstats", ring->itr_idx);
		return (false);
	}

	ring->itr_kstat = ksp;
	ksp->ks_data = stats;

	kstat_named_init(&stats->its_obytes, "obytes", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_opackets, "opackets", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_bad_meo, "bad_meo", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_ring_full, "ring_full", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_no_tx_bufs, "no_tx_bufs",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_tx_copy, "tx_copy", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_tx_bind, "tx_bind", KSTAT_DATA_UINT64);
	kstat_named_init(&stats->its_tx_bind_fail, "tx_bind_fail",
	    KSTAT_DATA_UINT64);

	kstat_install(ksp);

	return (true);
}
