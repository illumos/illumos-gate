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
#include "ena.h"

/*
 * The ENA device provides the following hardware stats. It appears
 * that all stats are available at both a device-level and
 * queue-level. However, Linux and FreeBSD don't implement queue
 * scope. It's not clear how one would implement queue scope because
 * there is nothing in the common code describing how to determine the
 * queue index number. Both the SQ and CQ have device index values,
 * but for a given logical queue they don't always match and so it's
 * not clear what value to use for querying the stats. Therefore,
 * device-wide basic and extended stats come from the device, while
 * queue/ring stats come from driver.
 *
 * From empirical testing, these statistics appear to be cumulative.
 * However, this guarantee is not explicitly documented anywhere in
 * the common code that the author could find.
 *
 * BASIC (ENAHW_GET_STATS_TYPE_BASIC)
 *
 *     - Rx packets/bytes
 *     - Rx drops
 *     - Tx packets/bytes
 *     - Tx drops
 *
 * EXTENDED (ENAHW_GET_STATS_TYPE_EXTENDED)
 *
 *     There is no structure defined for these stats in the Linux
 *     driver. Based on the FreeBSD driver, it looks like extended
 *     stats are simply a buffer of C strings? Come back to this
 *     later.
 *
 * ENI (ENAHW_GET_STATS_TYPE_ENI)
 *
 *     - Rx Bandwidth Allowance Exceeded
 *     - Tx Bandwidth Allowance Exceeded
 *     - PPS Allowance Exceeded (presumably for combined Rx/Tx)
 *     - Connection Tracking PPS Allowance Exceeded
 *     - Link-local PPS Alloance Exceeded
 */

static int
ena_stat_device_basic_update(kstat_t *ksp, int rw)
{
	ena_t *ena = ksp->ks_private;
	ena_basic_stat_t *ebs = ksp->ks_data;
	enahw_resp_desc_t resp;
	enahw_resp_basic_stats_t *stats = &resp.erd_resp.erd_basic_stats;
	int ret = 0;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	if ((ret = ena_admin_get_basic_stats(ena, &resp)) != 0) {
		return (ret);
	}

	mutex_enter(&ena->ena_lock);

	ebs->ebs_tx_bytes.value.ui64 =
	    ((uint64_t)stats->erbs_tx_bytes_high << 32) |
	    (uint64_t)stats->erbs_tx_bytes_low;
	ebs->ebs_tx_pkts.value.ui64 =
	    ((uint64_t)stats->erbs_tx_pkts_high << 32) |
	    (uint64_t)stats->erbs_tx_pkts_low;
	ebs->ebs_tx_drops.value.ui64 =
	    ((uint64_t)stats->erbs_tx_drops_high << 32) |
	    (uint64_t)stats->erbs_tx_drops_low;

	ebs->ebs_rx_bytes.value.ui64 =
	    ((uint64_t)stats->erbs_rx_bytes_high << 32) |
	    (uint64_t)stats->erbs_rx_bytes_low;
	ebs->ebs_rx_pkts.value.ui64 =
	    ((uint64_t)stats->erbs_rx_pkts_high << 32) |
	    (uint64_t)stats->erbs_rx_pkts_low;
	ebs->ebs_rx_drops.value.ui64 =
	    ((uint64_t)stats->erbs_rx_drops_high << 32) |
	    (uint64_t)stats->erbs_rx_drops_low;

	mutex_exit(&ena->ena_lock);

	return (0);
}

void
ena_stat_device_basic_cleanup(ena_t *ena)
{
	if (ena->ena_device_basic_kstat != NULL) {
		kstat_delete(ena->ena_device_basic_kstat);
		ena->ena_device_basic_kstat = NULL;
	}
}

boolean_t
ena_stat_device_basic_init(ena_t *ena)
{
	kstat_t *ksp = kstat_create(ENA_MODULE_NAME,
	    ddi_get_instance(ena->ena_dip), "device_basic", "net",
	    KSTAT_TYPE_NAMED,
	    sizeof (ena_basic_stat_t) / sizeof (kstat_named_t), 0);
	ena_basic_stat_t *ebs = NULL;

	if (ksp == NULL) {
		ena_err(ena, "!failed to create device_basic kstats");
		return (B_FALSE);
	}

	ena->ena_device_basic_kstat = ksp;
	ebs = ksp->ks_data;
	ksp->ks_update = ena_stat_device_basic_update;
	ksp->ks_private = ena;

	kstat_named_init(&ebs->ebs_tx_bytes, "tx_bytes", KSTAT_DATA_UINT64);
	ebs->ebs_tx_bytes.value.ui64 = 0;
	kstat_named_init(&ebs->ebs_tx_pkts, "tx_packets", KSTAT_DATA_UINT64);
	ebs->ebs_tx_pkts.value.ui64 = 0;
	kstat_named_init(&ebs->ebs_tx_drops, "tx_drops", KSTAT_DATA_UINT64);
	ebs->ebs_tx_drops.value.ui64 = 0;

	kstat_named_init(&ebs->ebs_rx_bytes, "rx_bytes", KSTAT_DATA_UINT64);
	ebs->ebs_rx_bytes.value.ui64 = 0;
	kstat_named_init(&ebs->ebs_rx_pkts, "rx_packets", KSTAT_DATA_UINT64);
	ebs->ebs_rx_pkts.value.ui64 = 0;
	kstat_named_init(&ebs->ebs_rx_drops, "rx_drops", KSTAT_DATA_UINT64);
	ebs->ebs_rx_drops.value.ui64 = 0;

	kstat_install(ena->ena_device_basic_kstat);
	return (B_TRUE);
}

int
ena_stat_device_extended_update(kstat_t *ksp, int rw)
{
	ena_t *ena = ksp->ks_private;
	ena_extended_stat_t *ees = ksp->ks_data;
	enahw_resp_desc_t resp;
	enahw_resp_eni_stats_t *stats = &resp.erd_resp.erd_eni_stats;
	int ret = 0;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	if ((ret = ena_admin_get_eni_stats(ena, &resp)) != 0) {
		return (ret);
	}

	mutex_enter(&ena->ena_lock);

	ees->ees_bw_in_exceeded.value.ui64 = stats->eres_bw_in_exceeded;
	ees->ees_bw_out_exceeded.value.ui64 = stats->eres_bw_out_exceeded;
	ees->ees_pps_exceeded.value.ui64 = stats->eres_pps_exceeded;
	ees->ees_conns_exceeded.value.ui64 = stats->eres_conns_exceeded;
	ees->ees_linklocal_exceeded.value.ui64 = stats->eres_linklocal_exceeded;

	mutex_exit(&ena->ena_lock);

	return (0);
}

void
ena_stat_device_extended_cleanup(ena_t *ena)
{
	if (ena->ena_device_extended_kstat != NULL) {
		kstat_delete(ena->ena_device_extended_kstat);
		ena->ena_device_extended_kstat = NULL;
	}
}

boolean_t
ena_stat_device_extended_init(ena_t *ena)
{
	kstat_t *ksp = kstat_create(ENA_MODULE_NAME,
	    ddi_get_instance(ena->ena_dip), "device_ext", "net",
	    KSTAT_TYPE_NAMED,
	    sizeof (ena_extended_stat_t) / sizeof (kstat_named_t), 0);
	ena_extended_stat_t *ees;

	if (ksp == NULL) {
		ena_err(ena, "!failed to create device_ext kstats");
		return (B_FALSE);
	}

	ena->ena_device_extended_kstat = ksp;
	ees = ksp->ks_data;
	ksp->ks_update = ena_stat_device_extended_update;
	ksp->ks_private = ena;

	kstat_named_init(&ees->ees_bw_in_exceeded, "bw_in_exceeded",
	    KSTAT_DATA_UINT64);
	ees->ees_bw_in_exceeded.value.ui64 = 0;

	kstat_named_init(&ees->ees_bw_out_exceeded, "bw_out_exceeded",
	    KSTAT_DATA_UINT64);
	ees->ees_bw_out_exceeded.value.ui64 = 0;

	kstat_named_init(&ees->ees_pps_exceeded, "pps_exceeded",
	    KSTAT_DATA_UINT64);
	ees->ees_pps_exceeded.value.ui64 = 0;

	kstat_named_init(&ees->ees_conns_exceeded, "conns_exceeded",
	    KSTAT_DATA_UINT64);
	ees->ees_conns_exceeded.value.ui64 = 0;

	kstat_named_init(&ees->ees_linklocal_exceeded, "linklocal_exceeded",
	    KSTAT_DATA_UINT64);
	ees->ees_linklocal_exceeded.value.ui64 = 0;

	kstat_install(ena->ena_device_extended_kstat);
	return (B_TRUE);
}

void
ena_stat_aenq_cleanup(ena_t *ena)
{
	if (ena->ena_aenq_kstat != NULL) {
		kstat_delete(ena->ena_aenq_kstat);
		ena->ena_aenq_kstat = NULL;
	}
}

boolean_t
ena_stat_aenq_init(ena_t *ena)
{
	kstat_t *ksp = kstat_create(ENA_MODULE_NAME,
	    ddi_get_instance(ena->ena_dip), "aenq", "net", KSTAT_TYPE_NAMED,
	    sizeof (ena_aenq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	ena_aenq_stat_t *eas = &ena->ena_aenq_stat;

	if (ksp == NULL) {
		ena_err(ena, "!failed to create aenq kstats");
		return (B_FALSE);
	}

	ena->ena_aenq_kstat = ksp;
	ksp->ks_data = eas;

	kstat_named_init(&eas->eaes_default, "default", KSTAT_DATA_UINT64);
	eas->eaes_default.value.ui64 = 0;

	kstat_named_init(&eas->eaes_link_change, "link_change",
	    KSTAT_DATA_UINT64);
	eas->eaes_link_change.value.ui64 = 0;

	kstat_install(ena->ena_aenq_kstat);
	return (B_TRUE);
}

void
ena_stat_txq_cleanup(ena_txq_t *txq)
{
	if (txq->et_kstat != NULL) {
		kstat_delete(txq->et_kstat);
		txq->et_kstat = NULL;
	}
}

boolean_t
ena_stat_txq_init(ena_txq_t *txq)
{
	ena_t *ena = txq->et_ena;
	kstat_t *ksp;
	char buf[128];
	ena_txq_stat_t *ets = &txq->et_stat;

	(void) snprintf(buf, sizeof (buf), "txq_%d", txq->et_txqs_idx);

	ksp = kstat_create(ENA_MODULE_NAME, ddi_get_instance(ena->ena_dip), buf,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ena_txq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL) {
		ena_err(ena, "!failed to create %s kstats", buf);
		return (B_FALSE);
	}

	txq->et_kstat = ksp;
	ksp->ks_data = ets;

	kstat_named_init(&ets->ets_hck_meoifail, "meoi_fail",
	    KSTAT_DATA_UINT64);
	ets->ets_hck_meoifail.value.ui64 = 0;

	kstat_named_init(&ets->ets_blocked, "blocked", KSTAT_DATA_UINT64);
	ets->ets_blocked.value.ui64 = 0;

	kstat_named_init(&ets->ets_unblocked, "unblocked", KSTAT_DATA_UINT64);
	ets->ets_unblocked.value.ui64 = 0;

	kstat_named_init(&ets->ets_recycled, "recycled", KSTAT_DATA_UINT64);
	ets->ets_recycled.value.ui64 = 0;

	kstat_named_init(&ets->ets_bytes, "bytes", KSTAT_DATA_UINT64);
	ets->ets_bytes.value.ui64 = 0;

	kstat_named_init(&ets->ets_packets, "packets", KSTAT_DATA_UINT64);
	ets->ets_packets.value.ui64 = 0;

	kstat_install(txq->et_kstat);
	return (B_TRUE);
}

void
ena_stat_rxq_cleanup(ena_rxq_t *rxq)
{
	if (rxq->er_kstat != NULL) {
		kstat_delete(rxq->er_kstat);
		rxq->er_kstat = NULL;
	}
}

boolean_t
ena_stat_rxq_init(ena_rxq_t *rxq)
{
	ena_t *ena = rxq->er_ena;
	kstat_t *ksp;
	char buf[128];
	ena_rxq_stat_t *ers = &rxq->er_stat;

	(void) snprintf(buf, sizeof (buf), "rxq_%d", rxq->er_rxqs_idx);

	ksp = kstat_create(ENA_MODULE_NAME, ddi_get_instance(ena->ena_dip), buf,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (ena_rxq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL) {
		ena_err(ena, "!failed to create %s kstats", buf);
		return (B_FALSE);
	}

	rxq->er_kstat = ksp;
	ksp->ks_data = ers;

	kstat_named_init(&ers->ers_packets, "packets", KSTAT_DATA_UINT64);
	ers->ers_packets.value.ui64 = 0;

	kstat_named_init(&ers->ers_bytes, "bytes", KSTAT_DATA_UINT64);
	ers->ers_bytes.value.ui64 = 0;

	kstat_named_init(&ers->ers_multi_desc, "multi_desc", KSTAT_DATA_UINT64);
	ers->ers_multi_desc.value.ui64 = 0;

	kstat_named_init(&ers->ers_allocb_fail, "allocb_fail",
	    KSTAT_DATA_UINT64);
	ers->ers_allocb_fail.value.ui64 = 0;

	kstat_named_init(&ers->ers_intr_limit, "intr_limit", KSTAT_DATA_UINT64);
	ers->ers_intr_limit.value.ui64 = 0;

	kstat_named_init(&ers->ers_hck_ipv4_err, "hck_ipv4_err",
	    KSTAT_DATA_UINT64);
	ers->ers_hck_ipv4_err.value.ui64 = 0;

	kstat_named_init(&ers->ers_hck_l4_err, "hck_l4_err", KSTAT_DATA_UINT64);
	ers->ers_hck_l4_err.value.ui64 = 0;

	kstat_install(rxq->er_kstat);
	return (B_TRUE);
}

int
ena_ring_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	int ret = 0;
	ena_rxq_t *rxq = (ena_rxq_t *)rh;

	mutex_enter(&rxq->er_stat_lock);

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rxq->er_stat.ers_bytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		*val = rxq->er_stat.ers_packets.value.ui64;
		break;
	default:
		*val = 0;
		ret = ENOTSUP;
	}

	mutex_exit(&rxq->er_stat_lock);
	return (ret);
}

int
ena_ring_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	int ret = 0;
	ena_txq_t *txq = (ena_txq_t *)rh;

	mutex_enter(&txq->et_stat_lock);

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = txq->et_stat.ets_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = txq->et_stat.ets_packets.value.ui64;
		break;
	default:
		*val = 0;
		ret = ENOTSUP;
	}

	mutex_exit(&txq->et_stat_lock);
	return (ret);
}

int
ena_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ena_t *ena = arg;
	ena_basic_stat_t *ebs;
	int ret = 0;

	/*
	 * The ENA device does not provide a lot of the stats that a
	 * traditional NIC device would. Return ENOTSUP early for any we don't
	 * support, and avoid a round trip to the controller.
	 */
	switch (stat) {
	case MAC_STAT_NORCVBUF:
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		break;
	default:
		return (ENOTSUP);
	}

	ret = ena_stat_device_basic_update(ena->ena_device_basic_kstat,
	    KSTAT_READ);

	if (ret != 0) {
		return (ret);
	}

	mutex_enter(&ena->ena_lock);
	ebs = ena->ena_device_basic_kstat->ks_data;

	switch (stat) {
	case MAC_STAT_NORCVBUF:
		*val = ebs->ebs_rx_drops.value.ui64;
		break;

	case MAC_STAT_RBYTES:
		*val = ebs->ebs_rx_bytes.value.ui64;
		break;

	case MAC_STAT_IPACKETS:
		*val = ebs->ebs_rx_pkts.value.ui64;
		break;

	case MAC_STAT_OBYTES:
		*val = ebs->ebs_tx_bytes.value.ui64;
		break;

	case MAC_STAT_OPACKETS:
		*val = ebs->ebs_tx_pkts.value.ui64;
		break;

	default:
		dev_err(ena->ena_dip, CE_PANIC, "unhandled stat, 0x%x", stat);
	}

	mutex_exit(&ena->ena_lock);
	return (ret);
}
