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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#include "i40e_sw.h"

/*
 * -------------------
 * Statistics Overview
 * -------------------
 *
 * As part of managing the driver and understanding what's going on, we keep
 * track of statistics from two different sources:
 *
 *   - Statistics from the device
 *   - Statistics maintained by the driver
 *
 * Generally, the hardware provides us traditional IETF and MIB Ethernet
 * statistics, for example, the total packets in and out, various errors in
 * packets, the negotiated status etc. The driver, on the other hand, primarily
 * contains statistics around driver-specific issues, such as information about
 * checksumming on receive and transmit and the data in and out of a specific
 * ring.
 *
 * We export statistics in two different forms. The first form is the required
 * GLDv3 endpoints, specifically:
 *
 *   - The general GLDv3 mc_getstat interface
 *   - The GLDv3 ring mri_stat interface
 *
 * The second form that we export statistics is through kstats. kstats are
 * exported in different ways. Particularly we arrange the kstats to monitor the
 * layout of the device. Currently we have kstats which capture both the IEEE
 * and driver-implementation specific stats. There are kstats for each of the
 * following structures:
 *
 *   - Each physical function
 *   - Each VSI
 *   - Each Queue
 *
 * The PF's kstat is called 'pfstats' so as not to collide with other system
 * provided kstats. Thus, for instance 0, usually the first PF, the full kstat
 * would be: i40e:0:pfstats:.
 *
 * The kstat for each VSI is called vsi_%instance. So for the first PF, which is
 * instance zero and the first vsi, which has id 0, it will be named vsi_0 and
 * the full kstat would be i40e:0:vsi_0:.
 *
 * The kstat for each queue is trqpair_tx_%queue and trqpair_rx_%queue. Note
 * that these are labeled based on their local index, which may mean that
 * different instances have overlapping sets of queues. This isn't a problem as
 * the kstats will always use the instance number of the pf to distinguish it in
 * the kstat tuple.
 *
 * ---------------------
 * Hardware Arrangements
 * ---------------------
 *
 * The hardware keeps statistics at each physical function/MAC (PF) and it keeps
 * statistics on each virtual station interface (VSI). Currently we only use one
 * VSI per PF (see the i40e_main.c theory statement). The hardware has a limited
 * number of statistics units available. While every PF is guaranteed to have a
 * statistics unit, it is possible that we will run out for a given VSI. We'll
 * have to figure out an appropriate strategy here when we end up supporting
 * multiple VSIs.
 *
 * The hardware keeps these statistics as 32-bit and 48-bit counters. We are
 * required to read them and then compute the differences between them. The
 * 48-bit counters span more than one 32-bit register in the BAR. The hardware
 * suggests that to read them, we perform 64-bit reads of the lower of the two
 * registers that make up a 48-bit stat. The hardware guarantees that the reads
 * of those two registers will be atomic and we'll get a consistent value, not a
 * property it has for every read of two registers.
 *
 * For every kstat we have based on this, we have a corresponding uint64_t that
 * we keep around as a base value in a separate structure. Whenever we read a
 * value, we end up grabbing the current value, calculating a difference between
 * the previously stored value and the current one, and updating the kstat with
 * that difference. After which, we go through and update the base value that we
 * stored. This is all encapsulated in i40e_stat_get_uint32() and
 * i40e_stat_get_uint48().
 *
 * The only unfortunate thing here is that the hardware doesn't give us any kind
 * of overflow counter. It just tries to make sure that the uint32_t and
 * uint48_t counters are large enough to hopefully not overflow right away. This
 * isn't the most reassuring statement and we should investigate ways of
 * ensuring that if a system is active, but not actively measured, we don't lose
 * data.
 *
 * The pf kstats data is stored in the i40e_t`i40e_pf_kstat. It is backed by the
 * i40e_t`i40e_pf_stat structure. Similarly the VSI related kstat is in
 * i40e_t`i40e_vsi_kstat and the data is backed in the i40e_t`i40e_vsi_stat. All
 * of this data is protected by the i40e_stat_lock, which should be taken last,
 * when acquiring locks.
 */

static void
i40e_stat_get_uint48(i40e_t *i40e, uintptr_t reg, kstat_named_t *kstat,
    uint64_t *base, boolean_t init)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint64_t raw, delta;

	ASSERT(MUTEX_HELD(&i40e->i40e_stat_lock));

	raw = ddi_get64(i40e->i40e_osdep_space.ios_reg_handle,
	    (uint64_t *)((uintptr_t)hw->hw_addr + reg));

	if (init == B_TRUE) {
		*base = raw;
		return;
	}

	/*
	 * Check for wraparound, note that the counter is actually only 48-bits,
	 * even though it has two uint32_t regs present.
	 */
	if (raw >= *base) {
		delta = raw - *base;
	} else {
		delta = 0x1000000000000ULL - *base + raw;
	}

	kstat->value.ui64 += delta;
	*base = raw;
}

static void
i40e_stat_get_uint32(i40e_t *i40e, uintptr_t reg, kstat_named_t *kstat,
    uint64_t *base, boolean_t init)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint64_t raw, delta;

	ASSERT(MUTEX_HELD(&i40e->i40e_stat_lock));

	raw = ddi_get32(i40e->i40e_osdep_space.ios_reg_handle,
	    (uint32_t *)((uintptr_t)hw->hw_addr + reg));

	if (init == B_TRUE) {
		*base = raw;
		return;
	}

	/*
	 * Watch out for wraparound as we only have a 32-bit counter.
	 */
	if (raw >= *base) {
		delta = raw - *base;
	} else {
		delta = 0x100000000ULL - *base + raw;
	}

	kstat->value.ui64 += delta;
	*base = raw;

}

static void
i40e_stat_vsi_update(i40e_t *i40e, boolean_t init)
{
	i40e_vsi_stats_t *ivs;
	i40e_vsi_kstats_t *ivk;
	int id = i40e->i40e_vsi_stat_id;

	ASSERT(i40e->i40e_vsi_kstat != NULL);
	ivs = &i40e->i40e_vsi_stat;
	ivk = i40e->i40e_vsi_kstat->ks_data;

	mutex_enter(&i40e->i40e_stat_lock);

	i40e_stat_get_uint48(i40e, I40E_GLV_GORCL(id), &ivk->ivk_rx_bytes,
	    &ivs->ivs_rx_bytes, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_UPRCL(id), &ivk->ivk_rx_unicast,
	    &ivs->ivs_rx_unicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_MPRCL(id), &ivk->ivk_rx_multicast,
	    &ivs->ivs_rx_multicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_BPRCL(id), &ivk->ivk_rx_broadcast,
	    &ivs->ivs_rx_broadcast, init);

	i40e_stat_get_uint32(i40e, I40E_GLV_RDPC(id), &ivk->ivk_rx_discards,
	    &ivs->ivs_rx_discards, init);
	i40e_stat_get_uint32(i40e, I40E_GLV_RUPP(id),
	    &ivk->ivk_rx_unknown_protocol,
	    &ivs->ivs_rx_unknown_protocol,
	    init);

	i40e_stat_get_uint48(i40e, I40E_GLV_GOTCL(id), &ivk->ivk_tx_bytes,
	    &ivs->ivs_tx_bytes, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_UPTCL(id), &ivk->ivk_tx_unicast,
	    &ivs->ivs_tx_unicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_MPTCL(id), &ivk->ivk_tx_multicast,
	    &ivs->ivs_tx_multicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLV_BPTCL(id), &ivk->ivk_tx_broadcast,
	    &ivs->ivs_tx_broadcast, init);

	i40e_stat_get_uint32(i40e, I40E_GLV_TEPC(id), &ivk->ivk_tx_errors,
	    &ivs->ivs_tx_errors, init);

	mutex_exit(&i40e->i40e_stat_lock);

	/*
	 * We follow ixgbe's lead here and that if a kstat update didn't work
	 * 100% then we mark service unaffected as opposed to when fetching
	 * things for MAC directly.
	 */
	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_UNAFFECTED);
	}
}

static int
i40e_stat_vsi_kstat_update(kstat_t *ksp, int rw)
{
	i40e_t *i40e;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	i40e = ksp->ks_private;
	i40e_stat_vsi_update(i40e, B_FALSE);
	return (0);
}

void
i40e_stat_vsi_fini(i40e_t *i40e)
{
	if (i40e->i40e_vsi_kstat != NULL) {
		kstat_delete(i40e->i40e_vsi_kstat);
		i40e->i40e_vsi_kstat = NULL;
	}
}

boolean_t
i40e_stat_vsi_init(i40e_t *i40e)
{
	kstat_t *ksp;
	i40e_vsi_kstats_t *ivk;
	char buf[64];

	(void) snprintf(buf, sizeof (buf), "vsi_%d", i40e->i40e_vsi_id);

	ksp = kstat_create(I40E_MODULE_NAME, ddi_get_instance(i40e->i40e_dip),
	    buf, "net", KSTAT_TYPE_NAMED,
	    sizeof (i40e_vsi_kstats_t) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		i40e_error(i40e, "Failed to create kstats for VSI %d",
		    i40e->i40e_vsi_id);
		return (B_FALSE);
	}

	i40e->i40e_vsi_kstat = ksp;
	ivk = ksp->ks_data;
	ksp->ks_update = i40e_stat_vsi_kstat_update;
	ksp->ks_private = i40e;

	kstat_named_init(&ivk->ivk_rx_bytes, "rx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_unicast, "rx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_discards, "rx_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_unknown_protocol, "rx_unknown_protocol",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_bytes, "tx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_unicast, "tx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_errors, "tx_errors",
	    KSTAT_DATA_UINT64);

	bzero(&i40e->i40e_vsi_stat, sizeof (i40e_vsi_stats_t));
	i40e_stat_vsi_update(i40e, B_TRUE);
	kstat_install(i40e->i40e_vsi_kstat);

	return (B_TRUE);
}

static void
i40e_stat_pf_update(i40e_t *i40e, boolean_t init)
{
	i40e_pf_stats_t *ips;
	i40e_pf_kstats_t *ipk;
	int port = i40e->i40e_hw_space.port;
	int i;

	ASSERT(i40e->i40e_pf_kstat != NULL);
	ips = &i40e->i40e_pf_stat;
	ipk = i40e->i40e_pf_kstat->ks_data;

	mutex_enter(&i40e->i40e_stat_lock);

	/* 64-bit PCIe regs */
	i40e_stat_get_uint48(i40e, I40E_GLPRT_GORCL(port),
	    &ipk->ipk_rx_bytes, &ips->ips_rx_bytes, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_UPRCL(port),
	    &ipk->ipk_rx_unicast, &ips->ips_rx_unicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_MPRCL(port),
	    &ipk->ipk_rx_multicast, &ips->ips_rx_multicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_BPRCL(port),
	    &ipk->ipk_rx_broadcast, &ips->ips_rx_broadcast, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_GOTCL(port),
	    &ipk->ipk_tx_bytes, &ips->ips_tx_bytes, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_UPTCL(port),
	    &ipk->ipk_tx_unicast, &ips->ips_tx_unicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_MPTCL(port),
	    &ipk->ipk_tx_multicast, &ips->ips_tx_multicast, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_BPTCL(port),
	    &ipk->ipk_tx_broadcast, &ips->ips_tx_broadcast, init);

	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC64L(port),
	    &ipk->ipk_rx_size_64, &ips->ips_rx_size_64, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC127L(port),
	    &ipk->ipk_rx_size_127, &ips->ips_rx_size_127, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC255L(port),
	    &ipk->ipk_rx_size_255, &ips->ips_rx_size_255, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC511L(port),
	    &ipk->ipk_rx_size_511, &ips->ips_rx_size_511, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC1023L(port),
	    &ipk->ipk_rx_size_1023, &ips->ips_rx_size_1023, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC1522L(port),
	    &ipk->ipk_rx_size_1522, &ips->ips_rx_size_1522, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PRC9522L(port),
	    &ipk->ipk_rx_size_9522, &ips->ips_rx_size_9522, init);

	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC64L(port),
	    &ipk->ipk_tx_size_64, &ips->ips_tx_size_64, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC127L(port),
	    &ipk->ipk_tx_size_127, &ips->ips_tx_size_127, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC255L(port),
	    &ipk->ipk_tx_size_255, &ips->ips_tx_size_255, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC511L(port),
	    &ipk->ipk_tx_size_511, &ips->ips_tx_size_511, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC1023L(port),
	    &ipk->ipk_tx_size_1023, &ips->ips_tx_size_1023, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC1522L(port),
	    &ipk->ipk_tx_size_1522, &ips->ips_tx_size_1522, init);
	i40e_stat_get_uint48(i40e, I40E_GLPRT_PTC9522L(port),
	    &ipk->ipk_tx_size_9522, &ips->ips_tx_size_9522, init);

	/* 32-bit PCIe regs */
	i40e_stat_get_uint32(i40e, I40E_GLPRT_LXONRXC(port),
	    &ipk->ipk_link_xon_rx, &ips->ips_link_xon_rx, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_LXOFFRXC(port),
	    &ipk->ipk_link_xoff_rx, &ips->ips_link_xoff_rx, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_LXONTXC(port),
	    &ipk->ipk_link_xon_tx, &ips->ips_link_xon_tx, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_LXOFFTXC(port),
	    &ipk->ipk_link_xoff_tx, &ips->ips_link_xoff_tx, init);

	for (i = 0; i < 8; i++) {
		i40e_stat_get_uint32(i40e, I40E_GLPRT_PXONRXC(port, i),
		    &ipk->ipk_priority_xon_rx[i], &ips->ips_priority_xon_rx[i],
		    init);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_PXOFFRXC(port, i),
		    &ipk->ipk_priority_xoff_rx[i],
		    &ips->ips_priority_xoff_rx[i],
		    init);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_PXONTXC(port, i),
		    &ipk->ipk_priority_xon_tx[i], &ips->ips_priority_xon_tx[i],
		    init);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_PXOFFTXC(port, i),
		    &ipk->ipk_priority_xoff_tx[i],
		    &ips->ips_priority_xoff_tx[i],
		    init);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RXON2OFFCNT(port, i),
		    &ipk->ipk_priority_xon_2_xoff[i],
		    &ips->ips_priority_xon_2_xoff[i],
		    init);
	}

	i40e_stat_get_uint32(i40e, I40E_GLPRT_CRCERRS(port),
	    &ipk->ipk_crc_errors, &ips->ips_crc_errors, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_ILLERRC(port),
	    &ipk->ipk_illegal_bytes, &ips->ips_illegal_bytes, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_MLFC(port),
	    &ipk->ipk_mac_local_faults, &ips->ips_mac_local_faults, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_MRFC(port),
	    &ipk->ipk_mac_remote_faults, &ips->ips_mac_remote_faults, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RLEC(port),
	    &ipk->ipk_rx_length_errors, &ips->ips_rx_length_errors, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RUC(port),
	    &ipk->ipk_rx_undersize, &ips->ips_rx_undersize, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RFC(port),
	    &ipk->ipk_rx_fragments, &ips->ips_rx_fragments, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_ROC(port),
	    &ipk->ipk_rx_oversize, &ips->ips_rx_oversize, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RJC(port),
	    &ipk->ipk_rx_jabber, &ips->ips_rx_jabber, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RDPC(port),
	    &ipk->ipk_rx_discards, &ips->ips_rx_discards, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_LDPC(port),
	    &ipk->ipk_rx_vm_discards, &ips->ips_rx_vm_discards, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_MSPDC(port),
	    &ipk->ipk_rx_short_discards, &ips->ips_rx_short_discards, init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_TDOLD(port),
	    &ipk->ipk_tx_dropped_link_down, &ips->ips_tx_dropped_link_down,
	    init);
	i40e_stat_get_uint32(i40e, I40E_GLPRT_RUPP(port),
	    &ipk->ipk_rx_unknown_protocol, &ips->ips_rx_unknown_protocol, init);

	/* 64-bit */
	i40e_stat_get_uint48(i40e, I40E_GL_RXERR1_L(port), &ipk->ipk_rx_err1,
	    &ips->ips_rx_err1, init);
	i40e_stat_get_uint48(i40e, I40E_GL_RXERR2_L(port), &ipk->ipk_rx_err2,
	    &ips->ips_rx_err2, init);

	mutex_exit(&i40e->i40e_stat_lock);

	/*
	 * We follow ixgbe's lead here and that if a kstat update didn't work
	 * 100% then we mark service unaffected as opposed to when fetching
	 * things for MAC directly.
	 */
	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_UNAFFECTED);
	}
}

static int
i40e_stat_pf_kstat_update(kstat_t *ksp, int rw)
{
	i40e_t *i40e;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	i40e = ksp->ks_private;
	i40e_stat_pf_update(i40e, B_FALSE);
	return (0);
}


static boolean_t
i40e_stat_pf_init(i40e_t *i40e)
{
	kstat_t *ksp;
	i40e_pf_kstats_t *ipk;

	ksp = kstat_create(I40E_MODULE_NAME, ddi_get_instance(i40e->i40e_dip),
	    "pfstats", "net", KSTAT_TYPE_NAMED,
	    sizeof (i40e_pf_kstats_t) / sizeof (kstat_named_t), 0);
	if (ksp == NULL) {
		i40e_error(i40e, "Could not create kernel statistics.");
		return (B_FALSE);
	}

	i40e->i40e_pf_kstat = ksp;
	ipk = ksp->ks_data;
	ksp->ks_update = i40e_stat_pf_kstat_update;
	ksp->ks_private = i40e;

	kstat_named_init(&ipk->ipk_rx_bytes, "rx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_unicast, "rx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_bytes, "tx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_unicast, "tx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_rx_size_64, "rx_size_64",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_127, "rx_size_127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_255, "rx_size_255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_511, "rx_size_511",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_1023, "rx_size_1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_1522, "rx_size_1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_size_9522, "rx_size_9522",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_tx_size_64, "tx_size_64",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_127, "tx_size_127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_255, "tx_size_255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_511, "tx_size_511",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_1023, "tx_size_1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_1522, "tx_size_1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_size_9522, "tx_size_9522",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_link_xon_rx, "link_xon_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xoff_rx, "link_xoff_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xon_tx, "link_xon_tx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_link_xoff_tx, "link_xoff_tx",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[0], "priority_xon_rx[0]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[0], "priority_xoff_rx[0]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[0], "priority_xon_tx[0]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[0], "priority_xoff_tx[0]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[0],
	    "priority_xon_2_xoff[0]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[1], "priority_xon_rx[1]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[1], "priority_xoff_rx[1]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[1], "priority_xon_tx[1]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[1], "priority_xoff_tx[1]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[1],
	    "priority_xon_2_xoff[1]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[2], "priority_xon_rx[2]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[2], "priority_xoff_rx[2]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[2], "priority_xon_tx[2]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[2], "priority_xoff_tx[2]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[2],
	    "priority_xon_2_xoff[2]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[3], "priority_xon_rx[3]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[3], "priority_xoff_rx[3]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[3], "priority_xon_tx[3]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[3], "priority_xoff_tx[3]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[3],
	    "priority_xon_2_xoff[3]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[4], "priority_xon_rx[4]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[4], "priority_xoff_rx[4]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[4], "priority_xon_tx[4]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[4], "priority_xoff_tx[4]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[4],
	    "priority_xon_2_xoff[4]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[5], "priority_xon_rx[5]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[5], "priority_xoff_rx[5]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[5], "priority_xon_tx[5]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[5], "priority_xoff_tx[5]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[5],
	    "priority_xon_2_xoff[5]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[6], "priority_xon_rx[6]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[6], "priority_xoff_rx[6]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[6], "priority_xon_tx[6]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[6], "priority_xoff_tx[6]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[6],
	    "priority_xon_2_xoff[6]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_priority_xon_rx[7], "priority_xon_rx[7]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_rx[7], "priority_xoff_rx[7]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_tx[7], "priority_xon_tx[7]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xoff_tx[7], "priority_xoff_tx[7]",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_priority_xon_2_xoff[7],
	    "priority_xon_2_xoff[7]",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ipk->ipk_crc_errors, "crc_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_illegal_bytes, "illegal_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_mac_local_faults, "mac_local_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_mac_remote_faults, "mac_remote_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_length_errors, "rx_length_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_undersize, "rx_undersize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_fragments, "rx_fragments",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_oversize, "rx_oversize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_jabber, "rx_jabber",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_discards, "rx_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_vm_discards, "rx_vm_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_short_discards, "rx_short_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_tx_dropped_link_down, "tx_dropped_link_down",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_unknown_protocol, "rx_unknown_protocol",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_err1, "rx_err1",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ipk->ipk_rx_err2, "rx_err2",
	    KSTAT_DATA_UINT64);


	bzero(&i40e->i40e_pf_stat, sizeof (i40e_pf_stats_t));
	i40e_stat_pf_update(i40e, B_TRUE);

	kstat_install(i40e->i40e_pf_kstat);

	return (B_TRUE);
}

void
i40e_stats_fini(i40e_t *i40e)
{
	ASSERT(i40e->i40e_vsi_kstat == NULL);
	if (i40e->i40e_pf_kstat != NULL) {
		kstat_delete(i40e->i40e_pf_kstat);
		i40e->i40e_pf_kstat = NULL;
	}

	mutex_destroy(&i40e->i40e_stat_lock);
}

boolean_t
i40e_stats_init(i40e_t *i40e)
{
	mutex_init(&i40e->i40e_stat_lock, NULL, MUTEX_DRIVER, NULL);
	if (i40e_stat_pf_init(i40e) == B_FALSE) {
		mutex_destroy(&i40e->i40e_stat_lock);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * For Nemo/GLDv3.
 */
int
i40e_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	i40e_t *i40e = (i40e_t *)arg;
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	int port = i40e->i40e_hw_space.port;
	i40e_pf_stats_t *ips;
	i40e_pf_kstats_t *ipk;


	ASSERT(i40e->i40e_pf_kstat != NULL);
	ips = &i40e->i40e_pf_stat;
	ipk = i40e->i40e_pf_kstat->ks_data;

	/*
	 * We need both locks, as various stats are protected by different
	 * things here.
	 */
	mutex_enter(&i40e->i40e_general_lock);

	if (i40e->i40e_state & I40E_SUSPENDED) {
		mutex_exit(&i40e->i40e_general_lock);
		return (ECANCELED);
	}

	mutex_enter(&i40e->i40e_stat_lock);

	/*
	 * Unfortunately the GLDv3 conflates two rather different things here.
	 * We're combining statistics about the physical port represented by
	 * this instance with statistics that describe the properties of the
	 * logical interface. As such, we're going to use the various aspects of
	 * the port to describe these stats as they represent what the physical
	 * instance is doing, even though that that means some tools may be
	 * confused and that to see the logical traffic on the interface itself
	 * sans VNICs and the like will require more work.
	 *
	 * Stats which are not listed in this switch statement are unimplemented
	 * at this time in hardware or don't currently apply to the device.
	 */
	switch (stat) {
	/* MIB-II stats (RFC 1213 and RFC 1573) */
	case MAC_STAT_IFSPEED:
		*val = i40e->i40e_link_speed * 1000000ull;
		break;
	case MAC_STAT_MULTIRCV:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_MPRCL(port),
		    &ipk->ipk_rx_multicast, &ips->ips_rx_multicast, B_FALSE);
		*val = ipk->ipk_rx_multicast.value.ui64;
		break;
	case MAC_STAT_BRDCSTRCV:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_BPRCL(port),
		    &ipk->ipk_rx_broadcast, &ips->ips_rx_broadcast, B_FALSE);
		*val = ipk->ipk_rx_broadcast.value.ui64;
		break;
	case MAC_STAT_MULTIXMT:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_MPTCL(port),
		    &ipk->ipk_tx_multicast, &ips->ips_tx_multicast, B_FALSE);
		*val = ipk->ipk_tx_multicast.value.ui64;
		break;
	case MAC_STAT_BRDCSTXMT:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_BPTCL(port),
		    &ipk->ipk_tx_broadcast, &ips->ips_tx_broadcast, B_FALSE);
		*val = ipk->ipk_tx_broadcast.value.ui64;
		break;
	case MAC_STAT_NORCVBUF:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RDPC(port),
		    &ipk->ipk_rx_discards, &ips->ips_rx_discards, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_LDPC(port),
		    &ipk->ipk_rx_vm_discards, &ips->ips_rx_vm_discards,
		    B_FALSE);
		*val = ipk->ipk_rx_discards.value.ui64 +
		    ipk->ipk_rx_vm_discards.value.ui64;
		break;
	/*
	 * Note, that some RXERR2 stats are also duplicated by the switch filter
	 * stats; however, since we're not using those at this time, it seems
	 * reasonable to include them.
	 */
	case MAC_STAT_IERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_CRCERRS(port),
		    &ipk->ipk_crc_errors, &ips->ips_crc_errors, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_ILLERRC(port),
		    &ipk->ipk_illegal_bytes, &ips->ips_illegal_bytes, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RLEC(port),
		    &ipk->ipk_rx_length_errors, &ips->ips_rx_length_errors,
		    B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GL_RXERR1_L(port),
		    &ipk->ipk_rx_err1, &ips->ips_rx_err1, B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GL_RXERR2_L(port),
		    &ipk->ipk_rx_err2, &ips->ips_rx_err2, B_FALSE);

		*val = ipk->ipk_crc_errors.value.ui64 +
		    ipk->ipk_illegal_bytes.value.ui64 +
		    ipk->ipk_rx_length_errors.value.ui64 +
		    ipk->ipk_rx_err1.value.ui64 +
		    ipk->ipk_rx_err2.value.ui64;
		break;
	case MAC_STAT_UNKNOWNS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RUPP(port),
		    &ipk->ipk_rx_unknown_protocol,
		    &ips->ips_rx_unknown_protocol,
		    B_FALSE);
		*val = ipk->ipk_rx_unknown_protocol.value.ui64;
		break;
	case MAC_STAT_RBYTES:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_GORCL(port),
		    &ipk->ipk_rx_bytes, &ips->ips_rx_bytes, B_FALSE);
		*val = ipk->ipk_rx_bytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_UPRCL(port),
		    &ipk->ipk_rx_unicast, &ips->ips_rx_unicast, B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GLPRT_MPRCL(port),
		    &ipk->ipk_rx_multicast, &ips->ips_rx_multicast, B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GLPRT_BPRCL(port),
		    &ipk->ipk_rx_broadcast, &ips->ips_rx_broadcast, B_FALSE);
		*val = ipk->ipk_rx_unicast.value.ui64 +
		    ipk->ipk_rx_multicast.value.ui64 +
		    ipk->ipk_rx_broadcast.value.ui64;
		break;
	case MAC_STAT_OBYTES:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_GOTCL(port),
		    &ipk->ipk_tx_bytes, &ips->ips_tx_bytes, B_FALSE);
		*val = ipk->ipk_tx_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		i40e_stat_get_uint48(i40e, I40E_GLPRT_UPTCL(port),
		    &ipk->ipk_tx_unicast, &ips->ips_tx_unicast, B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GLPRT_MPTCL(port),
		    &ipk->ipk_tx_multicast, &ips->ips_tx_multicast, B_FALSE);
		i40e_stat_get_uint48(i40e, I40E_GLPRT_BPTCL(port),
		    &ipk->ipk_tx_broadcast, &ips->ips_tx_broadcast, B_FALSE);
		*val = ipk->ipk_tx_unicast.value.ui64 +
		    ipk->ipk_tx_multicast.value.ui64 +
		    ipk->ipk_tx_broadcast.value.ui64;
		break;
	case MAC_STAT_UNDERFLOWS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RUC(port),
		    &ipk->ipk_rx_undersize, &ips->ips_rx_undersize, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RFC(port),
		    &ipk->ipk_rx_fragments, &ips->ips_rx_fragments, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_MSPDC(port),
		    &ipk->ipk_rx_short_discards, &ips->ips_rx_short_discards,
		    B_FALSE);
		*val = ipk->ipk_rx_undersize.value.ui64 +
		    ipk->ipk_rx_fragments.value.ui64 +
		    ipk->ipk_rx_short_discards.value.ui64;
		break;
	case MAC_STAT_OVERFLOWS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_ROC(port),
		    &ipk->ipk_rx_oversize, &ips->ips_rx_oversize, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RJC(port),
		    &ipk->ipk_rx_jabber, &ips->ips_rx_jabber, B_FALSE);
		*val = ipk->ipk_rx_oversize.value.ui64 +
		    ipk->ipk_rx_fragments.value.ui64;
		break;

	/* RFC 1643 stats */
	case ETHER_STAT_FCS_ERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_CRCERRS(port),
		    &ipk->ipk_crc_errors, &ips->ips_crc_errors, B_FALSE);
		*val = ipk->ipk_crc_errors.value.ui64;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_ROC(port),
		    &ipk->ipk_rx_oversize, &ips->ips_rx_oversize, B_FALSE);
		*val = ipk->ipk_rx_oversize.value.ui64;
		break;
	case ETHER_STAT_MACRCV_ERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_ILLERRC(port),
		    &ipk->ipk_illegal_bytes, &ips->ips_illegal_bytes, B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RLEC(port),
		    &ipk->ipk_rx_length_errors, &ips->ips_rx_length_errors,
		    B_FALSE);
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RFC(port),
		    &ipk->ipk_rx_fragments, &ips->ips_rx_fragments, B_FALSE);
		*val = ipk->ipk_illegal_bytes.value.ui64 +
		    ipk->ipk_rx_length_errors.value.ui64 +
		    ipk->ipk_rx_fragments.value.ui64;
		break;
	/* MII/GMII stats */

	/*
	 * The receiver address is apparently the same as the port number.
	 */
	case ETHER_STAT_XCVR_ADDR:
		/* The Receiver address is apparently the same as the port */
		*val = i40e->i40e_hw_space.port;
		break;
	case ETHER_STAT_XCVR_ID:
		switch (hw->phy.media_type) {
		case I40E_MEDIA_TYPE_BASET:
			/*
			 * Transform the data here into the ID. Note, generally
			 * the revision is left out.
			 */
			*val = i40e->i40e_phy.phy_id[3] << 24 |
			    i40e->i40e_phy.phy_id[2] << 16 |
			    i40e->i40e_phy.phy_id[1] << 8;
			break;
		case I40E_MEDIA_TYPE_FIBER:
		case I40E_MEDIA_TYPE_BACKPLANE:
		case I40E_MEDIA_TYPE_CX4:
		case I40E_MEDIA_TYPE_DA:
		case I40E_MEDIA_TYPE_VIRTUAL:
			*val = i40e->i40e_phy.phy_id[0] |
			    i40e->i40e_phy.phy_id[1] << 8 |
			    i40e->i40e_phy.phy_id[2] << 16;
			break;
		case I40E_MEDIA_TYPE_UNKNOWN:
		default:
			goto unimpl;
		}
		break;
	case ETHER_STAT_XCVR_INUSE:
		switch (hw->phy.link_info.phy_type) {
		case I40E_PHY_TYPE_100BASE_TX:
			*val = XCVR_100T2;
			break;
		case I40E_PHY_TYPE_1000BASE_T:
			*val = XCVR_1000T;
			break;
		default:
			*val = XCVR_UNDEFINED;
			break;
		}
		break;

	/*
	 * This group answers the question of do we support a given speed in
	 * theory.
	 */
	case ETHER_STAT_CAP_100FDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_100MB) != 0;
		break;
	case ETHER_STAT_CAP_1000FDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_1GB) != 0;
		break;
	case ETHER_STAT_CAP_10GFDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_10GB) != 0;
		break;
	case ETHER_STAT_CAP_40GFDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_40GB) != 0;
		break;

	/*
	 * These ask are we currently advertising these speeds and abilities.
	 * Until we support setting these because we're working with a copper
	 * PHY, then the only things we advertise are based on the link PHY
	 * speeds. In other words, we advertise everything we support.
	 */
	case ETHER_STAT_ADV_CAP_100FDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_100MB) != 0;
		break;
	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_1GB) != 0;
		break;
	case ETHER_STAT_ADV_CAP_10GFDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_10GB) != 0;
		break;
	case ETHER_STAT_ADV_CAP_40GFDX:
		*val = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_40GB) != 0;
		break;

	/*
	 * These ask if the peer supports these speeds, e.g. what did they tell
	 * us in auto-negotiation. Unfortunately, hardware doesn't appear to
	 * give us a way to determine whether or not they actually support
	 * something, only what they have enabled. This means that all we can
	 * tell the user is the speed that we're currently at, unfortunately.
	 */
	case ETHER_STAT_LP_CAP_100FDX:
		*val = i40e->i40e_link_speed == 100;
		break;
	case ETHER_STAT_LP_CAP_1000FDX:
		*val = i40e->i40e_link_speed == 1000;
		break;
	case ETHER_STAT_LP_CAP_10GFDX:
		*val = i40e->i40e_link_speed == 10000;
		break;
	case ETHER_STAT_LP_CAP_40GFDX:
		*val = i40e->i40e_link_speed == 40000;
		break;

	/*
	 * Statistics for unsupported speeds. Note that these often have the
	 * same constraints as the other ones. For example, we can't answer the
	 * question of the ETHER_STAT_LP_CAP family because hardware doesn't
	 * give us any way of knowing whether or not it does.
	 */
	case ETHER_STAT_CAP_100HDX:
	case ETHER_STAT_CAP_1000HDX:
	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
	case ETHER_STAT_CAP_100T4:
	case ETHER_STAT_CAP_100GFDX:
	case ETHER_STAT_CAP_2500FDX:
	case ETHER_STAT_CAP_5000FDX:
	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_100HDX:
	case ETHER_STAT_ADV_CAP_10FDX:
	case ETHER_STAT_ADV_CAP_10HDX:
	case ETHER_STAT_ADV_CAP_100T4:
	case ETHER_STAT_ADV_CAP_100GFDX:
	case ETHER_STAT_ADV_CAP_2500FDX:
	case ETHER_STAT_ADV_CAP_5000FDX:
	case ETHER_STAT_LP_CAP_1000HDX:
	case ETHER_STAT_LP_CAP_100HDX:
	case ETHER_STAT_LP_CAP_10FDX:
	case ETHER_STAT_LP_CAP_10HDX:
	case ETHER_STAT_LP_CAP_100T4:
	case ETHER_STAT_LP_CAP_100GFDX:
	case ETHER_STAT_LP_CAP_2500FDX:
	case ETHER_STAT_LP_CAP_5000FDX:
		*val = 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = i40e->i40e_link_duplex;
		break;
	case ETHER_STAT_TOOSHORT_ERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RUC(port),
		    &ipk->ipk_rx_undersize, &ips->ips_rx_undersize, B_FALSE);

		i40e_stat_get_uint32(i40e, I40E_GLPRT_MSPDC(port),
		    &ipk->ipk_rx_short_discards, &ips->ips_rx_short_discards,
		    B_FALSE);
		*val = ipk->ipk_rx_undersize.value.ui64 +
		    ipk->ipk_rx_short_discards.value.ui64;
		break;
	case ETHER_STAT_JABBER_ERRORS:
		i40e_stat_get_uint32(i40e, I40E_GLPRT_RJC(port),
		    &ipk->ipk_rx_jabber, &ips->ips_rx_jabber, B_FALSE);
		*val = ipk->ipk_rx_jabber.value.ui64;
		break;

	/*
	 * Non-Link speed related capabilities.
	 */
	case ETHER_STAT_CAP_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = (hw->phy.link_info.an_info & I40E_AQ_LP_AN_ABILITY) != 0;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = 1;
		break;

	/*
	 * Note that while the hardware does support the pause functionality, at
	 * this time we do not use it at all and effectively disable it.
	 */
	case ETHER_STAT_CAP_ASMPAUSE:
		*val = (i40e->i40e_phy.abilities &
		    I40E_AQ_PHY_FLAG_PAUSE_RX) != 0;
		break;
	case ETHER_STAT_CAP_PAUSE:
		*val = (i40e->i40e_phy.abilities &
		    I40E_AQ_PHY_FLAG_PAUSE_TX) != 0;
		break;

	/*
	 * Because we don't support these at this time, they are always
	 * hard-coded to zero.
	 */
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = 0;
		break;

	/*
	 * Like the other LP fields, we can only answer the question have we
	 * enabled it, not whether the other end actually supports it.
	 */
	case ETHER_STAT_LP_CAP_ASMPAUSE:
	case ETHER_STAT_LINK_ASMPAUSE:
		*val = (hw->phy.link_info.an_info & I40E_AQ_LINK_PAUSE_RX) != 0;
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
	case ETHER_STAT_LINK_PAUSE:
		*val = (hw->phy.link_info.an_info & I40E_AQ_LINK_PAUSE_TX) != 0;
		break;

	default:
	unimpl:
		mutex_exit(&i40e->i40e_stat_lock);
		mutex_exit(&i40e->i40e_general_lock);
		return (ENOTSUP);
	}

	mutex_exit(&i40e->i40e_stat_lock);
	mutex_exit(&i40e->i40e_general_lock);

	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

int
i40e_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	i40e_trqpair_t *itrq = (i40e_trqpair_t *)rh;
	i40e_t *i40e = itrq->itrq_i40e;

	if (i40e->i40e_state & I40E_SUSPENDED) {
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = itrq->itrq_rxstat.irxs_bytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		*val = itrq->itrq_rxstat.irxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

int
i40e_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	i40e_trqpair_t *itrq = (i40e_trqpair_t *)rh;
	i40e_t *i40e = itrq->itrq_i40e;

	if (i40e->i40e_state & I40E_SUSPENDED) {
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = itrq->itrq_txstat.itxs_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = itrq->itrq_txstat.itxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * When we end up refactoring all off the queue assignments and have non-static
 * queue to VSI mappings, then we may need to revisit the general locking
 * strategy that we employ and have the kstat creation / deletion be part of the
 * ring start and stop routines.
 */
void
i40e_stats_trqpair_fini(i40e_trqpair_t *itrq)
{
	if (itrq->itrq_txkstat != NULL) {
		kstat_delete(itrq->itrq_txkstat);
		itrq->itrq_txkstat = NULL;
	}

	if (itrq->itrq_rxkstat != NULL) {
		kstat_delete(itrq->itrq_rxkstat);
		itrq->itrq_rxkstat = NULL;
	}
}

boolean_t
i40e_stats_trqpair_init(i40e_trqpair_t *itrq)
{
	char buf[128];
	i40e_t *i40e = itrq->itrq_i40e;
	i40e_txq_stat_t *tsp = &itrq->itrq_txstat;
	i40e_rxq_stat_t *rsp = &itrq->itrq_rxstat;

	(void) snprintf(buf, sizeof (buf), "trqpair_tx_%d", itrq->itrq_index);
	itrq->itrq_txkstat = kstat_create(I40E_MODULE_NAME,
	    ddi_get_instance(i40e->i40e_dip), buf, "net", KSTAT_TYPE_NAMED,
	    sizeof (i40e_txq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (itrq->itrq_txkstat == NULL)
		return (B_FALSE);

	(void) snprintf(buf, sizeof (buf), "trqpair_rx_%d", itrq->itrq_index);
	itrq->itrq_rxkstat = kstat_create(I40E_MODULE_NAME,
	    ddi_get_instance(i40e->i40e_dip), buf, "net", KSTAT_TYPE_NAMED,
	    sizeof (i40e_rxq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (itrq->itrq_rxkstat == NULL) {
		kstat_delete(itrq->itrq_txkstat);
		itrq->itrq_txkstat = NULL;
		return (B_FALSE);
	}

	itrq->itrq_txkstat->ks_data = &itrq->itrq_txstat;
	itrq->itrq_rxkstat->ks_data = &itrq->itrq_rxstat;

	kstat_named_init(&tsp->itxs_bytes, "tx_bytes",
	    KSTAT_DATA_UINT64);
	tsp->itxs_bytes.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_packets, "tx_packets",
	    KSTAT_DATA_UINT64);
	tsp->itxs_packets.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_descriptors, "tx_descriptors",
	    KSTAT_DATA_UINT64);
	tsp->itxs_descriptors.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_recycled, "tx_recycled",
	    KSTAT_DATA_UINT64);
	tsp->itxs_recycled.value.ui64 = 0;

	kstat_named_init(&tsp->itxs_hck_meoifail, "tx_hck_meoifail",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_meoifail.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_hck_nol2info, "tx_hck_nol2info",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_nol2info.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_hck_nol3info, "tx_hck_nol3info",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_nol3info.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_hck_nol4info, "tx_hck_nol4info",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_nol4info.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_hck_badl3, "tx_hck_badl3",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_badl3.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_hck_badl4, "tx_hck_badl4",
	    KSTAT_DATA_UINT64);
	tsp->itxs_hck_badl4.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_err_notcb, "tx_err_notcb",
	    KSTAT_DATA_UINT64);
	tsp->itxs_err_notcb.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_err_nodescs, "tx_err_nodescs",
	    KSTAT_DATA_UINT64);
	tsp->itxs_err_nodescs.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_err_context, "tx_err_context",
	    KSTAT_DATA_UINT64);
	tsp->itxs_err_context.value.ui64 = 0;
	kstat_named_init(&tsp->itxs_num_unblocked, "tx_num_unblocked",
	    KSTAT_DATA_UINT64);
	tsp->itxs_num_unblocked.value.ui64 = 0;


	kstat_named_init(&rsp->irxs_bytes, "rx_bytes",
	    KSTAT_DATA_UINT64);
	rsp->irxs_bytes.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_packets, "rx_packets",
	    KSTAT_DATA_UINT64);
	rsp->irxs_packets.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_rx_desc_error, "rx_desc_error",
	    KSTAT_DATA_UINT64);
	rsp->irxs_rx_desc_error.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_rx_intr_limit, "rx_intr_limit",
	    KSTAT_DATA_UINT64);
	rsp->irxs_rx_intr_limit.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_rx_bind_norcb, "rx_bind_norcb",
	    KSTAT_DATA_UINT64);
	rsp->irxs_rx_bind_norcb.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_rx_bind_nomp, "rx_bind_nomp",
	    KSTAT_DATA_UINT64);
	rsp->irxs_rx_bind_nomp.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_rx_copy_nomem, "rx_copy_nomem",
	    KSTAT_DATA_UINT64);
	rsp->irxs_rx_copy_nomem.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_v4hdrok, "rx_hck_v4hdrok",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_v4hdrok.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_l4hdrok, "rx_hck_l4hdrok",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_l4hdrok.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_unknown, "rx_hck_unknown",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_unknown.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_nol3l4p, "rx_hck_nol3l4p",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_nol3l4p.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_iperr, "rx_hck_iperr",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_iperr.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_eiperr, "rx_hck_eiperr",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_eiperr.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_l4err, "rx_hck_l4err",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_l4err.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_v6skip, "rx_hck_v6skip",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_v6skip.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_set, "rx_hck_set",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_set.value.ui64 = 0;
	kstat_named_init(&rsp->irxs_hck_miss, "rx_hck_miss",
	    KSTAT_DATA_UINT64);
	rsp->irxs_hck_miss.value.ui64 = 0;

	kstat_install(itrq->itrq_txkstat);
	kstat_install(itrq->itrq_rxkstat);

	return (B_TRUE);
}
