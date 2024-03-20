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

#include "ena_hw.h"
#include "ena.h"

CTASSERT(sizeof (enahw_aenq_desc_t) == 64);

/*
 * We add this here as an extra safety check to make sure that any
 * addition to the AENQ group enum also updates the groups array num
 * value.
 */
CTASSERT(ENAHW_AENQ_GROUPS_ARR_NUM == 8);

typedef struct ena_aenq_grpstr {
	enahw_aenq_groups_t	eag_type;
	const char		*eag_str;
} ena_aenq_grpstr_t;

static ena_aenq_grpstr_t ena_groups_str[ENAHW_AENQ_GROUPS_ARR_NUM] = {
	{
		.eag_type = ENAHW_AENQ_GROUP_LINK_CHANGE,
		.eag_str = "LINK CHANGE"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_FATAL_ERROR,
		.eag_str = "FATAL ERROR"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_WARNING,
		.eag_str = "WARNING"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_NOTIFICATION,
		.eag_str = "NOTIFICATION"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_KEEP_ALIVE,
		.eag_str = "KEEP ALIVE"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_REFRESH_CAPABILITIES,
		.eag_str = "REFRESH CAPABILITIES"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_CONF_NOTIFICATIONS,
		.eag_str = "CONFIG NOTIFICATIONS"
	},
	{
		.eag_type = ENAHW_AENQ_GROUP_DEVICE_REQUEST_RESET,
		.eag_str = "DEVICE RESET REQUEST"
	}
};

bool
ena_aenq_configure(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_feat_aenq_t *cmd_feat =
	    &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_aenq;
	enahw_resp_desc_t resp;
	enahw_feat_aenq_t *resp_feat = &resp.erd_resp.erd_get_feat.ergf_aenq;
	enahw_aenq_groups_t to_enable;

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0) {
		return (false);
	}

	to_enable = BIT(ENAHW_AENQ_GROUP_LINK_CHANGE) |
	    BIT(ENAHW_AENQ_GROUP_FATAL_ERROR) |
	    BIT(ENAHW_AENQ_GROUP_WARNING) |
	    BIT(ENAHW_AENQ_GROUP_NOTIFICATION) |
	    BIT(ENAHW_AENQ_GROUP_KEEP_ALIVE) |
	    BIT(ENAHW_AENQ_GROUP_DEVICE_REQUEST_RESET);
	to_enable &= resp_feat->efa_supported_groups;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (cmd));
	cmd_feat->efa_enabled_groups = to_enable;

	if (ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0) {
		return (false);
	}

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0) {
		return (false);
	}

	ena->ena_aenq_supported_groups = resp_feat->efa_supported_groups;
	ena->ena_aenq_enabled_groups = resp_feat->efa_enabled_groups;

	for (uint_t i = 0; i < ENAHW_AENQ_GROUPS_ARR_NUM; i++) {
		ena_aenq_grpstr_t *grpstr = &ena_groups_str[i];
		bool supported = BIT(grpstr->eag_type) &
		    resp_feat->efa_supported_groups;
		bool enabled = BIT(grpstr->eag_type) &
		    resp_feat->efa_enabled_groups;

		ena_dbg(ena, "%s supported: %s enabled: %s", grpstr->eag_str,
		    supported ? "Y" : "N", enabled ? "Y" : "N");
	}

	return (true);
}

void
ena_aenq_work(ena_t *ena)
{
	ena_aenq_t *aenq = &ena->ena_aenq;
	uint16_t head_mod = aenq->eaenq_head & (aenq->eaenq_num_descs - 1);
	bool processed = false;
	enahw_aenq_desc_t *desc = &aenq->eaenq_descs[head_mod];

	ENA_DMA_SYNC(aenq->eaenq_dma, DDI_DMA_SYNC_FORKERNEL);

	while (ENAHW_AENQ_DESC_PHASE(desc) == aenq->eaenq_phase) {
		ena_aenq_hdlr_t hdlr;

		ASSERT3U(desc->ead_group, <, ENAHW_AENQ_GROUPS_ARR_NUM);
		processed = true;

		/*
		 * Keepalives occur once per second, we won't issue a debug
		 * log message for each of those.
		 */
		if (ena_debug &&
		    desc->ead_group != ENAHW_AENQ_GROUP_KEEP_ALIVE) {
			uint64_t ts = ((uint64_t)desc->ead_ts_high << 32) |
			    (uint64_t)desc->ead_ts_low;

			ena_dbg(ena,
			    "AENQ Group: (0x%x) %s Syndrome: 0x%x ts: %" PRIu64
			    " us", desc->ead_group,
			    ena_groups_str[desc->ead_group].eag_str,
			    desc->ead_syndrome, ts);
		}

		hdlr = ena->ena_aenq.eaenq_hdlrs[desc->ead_group];
		hdlr(ena, desc);

		aenq->eaenq_head++;
		head_mod = aenq->eaenq_head & (aenq->eaenq_num_descs - 1);

		if (head_mod == 0)
			aenq->eaenq_phase ^= 1;

		desc = &aenq->eaenq_descs[head_mod];
	}

	if (processed) {
		ena_hw_bar_write32(ena, ENAHW_REG_AENQ_HEAD_DB,
		    aenq->eaenq_head);
	}
}

static void
ena_aenq_link_change_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;
	bool is_up = (desc->ead_payload.link_change.flags &
	    ENAHW_AENQ_LINK_CHANGE_LINK_STATUS_MASK) != 0;
	link_state_t new_state = is_up ? LINK_STATE_UP : LINK_STATE_DOWN;

	/*
	 * The interrupts are not enabled until after we register mac,
	 * so the mac handle should be valid.
	 */
	ASSERT3U(ena->ena_attach_seq, >=, ENA_ATTACH_MAC_REGISTER);
	ena->ena_aenq_stat.eaes_link_change.value.ui64++;

	ena_dbg(ena, "link is %s", is_up ? "UP" : "DOWN");

	mutex_enter(&ena->ena_lock);

	/*
	 * Notify mac only on an actual change in status.
	 */
	if (ena->ena_link_state != new_state) {
		mac_link_update(ena->ena_mh, new_state);
		ena->ena_link_state = new_state;
	}

	mutex_exit(&ena->ena_lock);
}

static void
ena_aenq_notification_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	if (desc->ead_syndrome == ENAHW_AENQ_SYNDROME_UPDATE_HINTS) {
		enahw_device_hints_t *hints =
		    (enahw_device_hints_t *)desc->ead_payload.raw;

		ena_update_hints(ena, hints);
	} else {
		ena_err(ena, "Invalid aenq notification syndrome 0x%x",
		    desc->ead_syndrome);
	}

	ena->ena_aenq_stat.eaes_notification.value.ui64++;
}

static void
ena_aenq_keep_alive_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;
	uint64_t rx_drops, tx_drops, rx_overruns;
	ena_basic_stat_t *ebs = ena->ena_device_basic_kstat->ks_data;
	uint64_t now = (uint64_t)gethrtime();

	(void) atomic_swap_64(&ena->ena_watchdog_last_keepalive, now);

	rx_drops =
	    ((uint64_t)desc->ead_payload.keep_alive.rx_drops_high << 32) |
	    desc->ead_payload.keep_alive.rx_drops_low;
	tx_drops =
	    ((uint64_t)desc->ead_payload.keep_alive.tx_drops_high << 32) |
	    desc->ead_payload.keep_alive.tx_drops_low;
	rx_overruns =
	    ((uint64_t)desc->ead_payload.keep_alive.rx_overruns_high << 32) |
	    desc->ead_payload.keep_alive.rx_overruns_low;

	mutex_enter(&ena->ena_device_basic_stat_lock);
	ebs->ebs_rx_drops.value.ui64 = rx_drops;
	ebs->ebs_tx_drops.value.ui64 = tx_drops;
	ebs->ebs_rx_overruns.value.ui64 = rx_overruns;
	mutex_exit(&ena->ena_device_basic_stat_lock);

	ena->ena_aenq_stat.eaes_keep_alive.value.ui64++;
}

static void
ena_aenq_request_reset_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	ena->ena_reset_reason = ENAHW_RESET_DEVICE_REQUEST;
	atomic_or_32(&ena->ena_state, ENA_STATE_ERROR);

	ena->ena_aenq_stat.eaes_request_reset.value.ui64++;
}

static void
ena_aenq_fatal_error_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	/*
	 * The other open source drivers register this event but don't do
	 * anything when it triggers. We do the same for now. If this indicates
	 * that the fatal error bit has been set in the status register, the
	 * watchdog will pick that up directly and issue a reset.
	 */
	ena->ena_aenq_stat.eaes_fatal_error.value.ui64++;
}

static void
ena_aenq_warning_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	/*
	 * The other open source drivers register this event but don't do
	 * anything when it triggers. We do the same for now.
	 */
	ena->ena_aenq_stat.eaes_warning.value.ui64++;
}

static void
ena_aenq_default_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	ena->ena_aenq_stat.eaes_default.value.ui64++;
	/*
	 * We don't enable any of the groups that we don't support, so this
	 * should not happen.
	 */
	ena_dbg(ena, "unimplemented handler for aenq group: %s",
	    ena_groups_str[desc->ead_group].eag_str);
}

static void
ena_aenq_set_hdlrs(ena_aenq_t *aenq)
{
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_LINK_CHANGE] =
	    ena_aenq_link_change_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_NOTIFICATION] =
	    ena_aenq_notification_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_KEEP_ALIVE] =
	    ena_aenq_keep_alive_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_DEVICE_REQUEST_RESET] =
	    ena_aenq_request_reset_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_FATAL_ERROR] =
	    ena_aenq_fatal_error_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_WARNING] =
	    ena_aenq_warning_hdlr;

	/* The following events are not handled */
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_REFRESH_CAPABILITIES] =
	    ena_aenq_default_hdlr;
	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_CONF_NOTIFICATIONS] =
	    ena_aenq_default_hdlr;
}

bool
ena_aenq_init(ena_t *ena)
{
	ena_aenq_t *aenq = &ena->ena_aenq;
	uint32_t addr_low, addr_high, wval;

	if (aenq->eaenq_descs == NULL) {
		size_t size;

		aenq->eaenq_num_descs = ENA_AENQ_NUM_DESCS;
		size = aenq->eaenq_num_descs * sizeof (*aenq->eaenq_descs);

		ena_dma_conf_t conf = {
			.edc_size = size,
			.edc_align = ENAHW_AENQ_DESC_BUF_ALIGNMENT,
			.edc_sgl = 1,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = false,
		};

		if (!ena_dma_alloc(ena, &aenq->eaenq_dma, &conf, size)) {
			ena_err(ena, "failed to allocate DMA for AENQ");
			return (false);
		}

		ENA_DMA_VERIFY_ADDR(ena,
		    aenq->eaenq_dma.edb_cookie->dmac_laddress);
		aenq->eaenq_descs = (void *)aenq->eaenq_dma.edb_va;
		ena_aenq_set_hdlrs(aenq);
	} else {
		ena_dma_bzero(&aenq->eaenq_dma);
	}

	aenq->eaenq_head = aenq->eaenq_num_descs;
	aenq->eaenq_phase = 1;

	addr_low = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_BASE_HI, addr_high);
	ENA_DMA_SYNC(aenq->eaenq_dma, DDI_DMA_SYNC_FORDEV);
	wval = ENAHW_AENQ_CAPS_DEPTH(aenq->eaenq_num_descs) |
	    ENAHW_AENQ_CAPS_ENTRY_SIZE(sizeof (*aenq->eaenq_descs));
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_CAPS, wval);

	return (true);
}

void
ena_aenq_enable(ena_t *ena)
{
	/*
	 * We set this to zero here so that the watchdog will ignore it until
	 * the first keepalive event is received. Devices that do not support
	 * sending keepalives will result in this value remaining at 0.
	 */
	ena->ena_watchdog_last_keepalive = 0;
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_HEAD_DB,
	    ena->ena_aenq.eaenq_head);
}

void
ena_aenq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aenq.eaenq_dma);
}
