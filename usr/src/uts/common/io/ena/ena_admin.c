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
 * This file contains everything having to do with communicating with
 * the admin queue for sending commands to the device.
 */

#include "ena_hw.h"
#include "ena.h"

/*
 * Mark the context as complete (a response has been received).
 */
static void
ena_complete_cmd_ctx(ena_cmd_ctx_t *ctx, enahw_resp_desc_t *hwresp)
{
	bcopy(hwresp, ctx->ectx_resp, sizeof (*hwresp));
	ctx->ectx_pending = B_FALSE;
}

/*
 * Reset and release the context back to the free list.
 */
static void
ena_release_cmd_ctx(ena_t *ena, ena_cmd_ctx_t *ctx)
{
	ASSERT(ctx->ectx_pending == B_FALSE);
	ctx->ectx_resp = NULL;
	ctx->ectx_cmd_opcode = ENAHW_CMD_NONE;

	mutex_enter(&ena->ena_aq.ea_sq_lock);
	/*
	 * We return the free descriptor to the end of the list so that we
	 * cycle through them with each admin command, and don't end up almost
	 * always re-using the same entry with the same command ID. While the
	 * controller does not appear to mind, it's a little counterintuitive.
	 */
	list_insert_tail(&ena->ena_aq.ea_cmd_ctxs_free, ctx);
	ena->ena_aq.ea_pending_cmds--;
	mutex_exit(&ena->ena_aq.ea_sq_lock);
}

/*
 * Acquire the next available command context.
 */
static ena_cmd_ctx_t *
ena_acquire_cmd_ctx(ena_adminq_t *aq)
{
	VERIFY(MUTEX_HELD(&aq->ea_sq_lock));
	ASSERT3U(aq->ea_pending_cmds, <, aq->ea_qlen);
	ena_cmd_ctx_t *ctx = list_remove_head(&aq->ea_cmd_ctxs_free);

	ctx->ectx_pending = B_TRUE;
	return (ctx);
}

/*
 * Submit a command to the admin queue.
 */
int
ena_admin_submit_cmd(ena_t *ena, enahw_cmd_desc_t *cmd, enahw_resp_desc_t *resp,
    ena_cmd_ctx_t **ctx)
{
	VERIFY3U(cmd->ecd_opcode, !=, 0);
	ena_adminq_t *aq = &ena->ena_aq;
	ena_admin_sq_t *sq = &aq->ea_sq;
	uint16_t modulo_mask = aq->ea_qlen - 1;
	ena_cmd_ctx_t *lctx = NULL;

	mutex_enter(&aq->ea_sq_lock);
	uint16_t tail_mod = sq->eas_tail & modulo_mask;

	if (aq->ea_pending_cmds >= aq->ea_qlen) {
		mutex_enter(&aq->ea_stat_lock);
		aq->ea_stats.queue_full++;
		mutex_exit(&aq->ea_stat_lock);
		mutex_exit(&aq->ea_sq_lock);
		return (ENOSPC);
	}

	lctx = ena_acquire_cmd_ctx(aq);
	lctx->ectx_cmd_opcode = cmd->ecd_opcode;
	lctx->ectx_resp = resp;

	cmd->ecd_flags = sq->eas_phase & ENAHW_CMD_PHASE_MASK;
	ENAHW_CMD_ID(cmd, lctx->ectx_id);
	bcopy(cmd, &sq->eas_entries[tail_mod], sizeof (*cmd));
	ENA_DMA_SYNC(sq->eas_dma, DDI_DMA_SYNC_FORDEV);
	sq->eas_tail++;
	aq->ea_pending_cmds++;

	mutex_enter(&aq->ea_stat_lock);
	aq->ea_stats.cmds_submitted++;
	mutex_exit(&aq->ea_stat_lock);

	DTRACE_PROBE4(cmd__submit, enahw_cmd_desc_t *, cmd, ena_cmd_ctx_t *,
	    lctx, uint16_t, tail_mod, uint8_t, sq->eas_phase);

	if ((sq->eas_tail & modulo_mask) == 0) {
		sq->eas_phase ^= 1;
	}

	ena_hw_abs_write32(ena, sq->eas_dbaddr, sq->eas_tail);
	mutex_exit(&aq->ea_sq_lock);
	*ctx = lctx;
	return (0);
}

/*
 * Read a single response from the admin queue.
 */
static void
ena_admin_read_resp(ena_t *ena, enahw_resp_desc_t *hwresp)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_admin_cq_t *cq = &aq->ea_cq;
	ena_cmd_ctx_t *ctx = NULL;
	uint16_t modulo_mask = aq->ea_qlen - 1;
	VERIFY(MUTEX_HELD(&aq->ea_cq_lock));

	uint16_t head_mod = cq->eac_head & modulo_mask;
	uint8_t phase = cq->eac_phase & ENAHW_RESP_PHASE_MASK;
	uint16_t cmd_id = ENAHW_RESP_CMD_ID(hwresp);
	ctx = &aq->ea_cmd_ctxs[cmd_id];
	ASSERT3U(ctx->ectx_id, ==, cmd_id);
	ena_complete_cmd_ctx(ctx, hwresp);

	if (hwresp->erd_status != ENAHW_RESP_SUCCESS) {
		mutex_enter(&aq->ea_stat_lock);
		aq->ea_stats.cmds_fail++;
		mutex_exit(&aq->ea_stat_lock);
		DTRACE_PROBE4(cmd__fail, enahw_resp_desc_t *, hwresp,
		    ena_cmd_ctx_t *, ctx, uint16_t, head_mod, uint8_t, phase);
		return;
	}

	DTRACE_PROBE4(cmd__success, enahw_resp_desc_t *, hwresp,
	    ena_cmd_ctx_t *, ctx, uint16_t, head_mod, uint8_t, phase);
	mutex_enter(&aq->ea_stat_lock);
	aq->ea_stats.cmds_success++;
	mutex_exit(&aq->ea_stat_lock);
}

static void
ena_admin_process_responses(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_admin_cq_t *cq = &aq->ea_cq;
	uint16_t modulo_mask = aq->ea_qlen - 1;
	enahw_resp_desc_t *hwresp;

	mutex_enter(&aq->ea_cq_lock);
	uint16_t head_mod = cq->eac_head & modulo_mask;
	uint8_t phase = cq->eac_phase & ENAHW_RESP_PHASE_MASK;

	ENA_DMA_SYNC(cq->eac_dma, DDI_DMA_SYNC_FORKERNEL);
	hwresp = &cq->eac_entries[head_mod];
	while ((hwresp->erd_flags & ENAHW_RESP_PHASE_MASK) == phase) {
		ena_admin_read_resp(ena, hwresp);

		cq->eac_head++;
		head_mod = cq->eac_head & modulo_mask;

		if (head_mod == 0) {
			phase ^= 1;
		}

		hwresp = &cq->eac_entries[head_mod];
	}

	cq->eac_phase = phase;
	mutex_exit(&aq->ea_cq_lock);
}

/*
 * Wait for the command described by ctx to complete by polling for
 * status updates.
 */
int
ena_admin_poll_for_resp(ena_t *ena, ena_cmd_ctx_t *ctx)
{
	int ret = 0;
	hrtime_t expire = gethrtime() + ena->ena_aq.ea_cmd_timeout_ns;

	while (1) {
		ena_admin_process_responses(ena);

		if (!ctx->ectx_pending) {
			break;
		}

		/* Wait for 1 millisecond. */
		delay(drv_usectohz(1000));

		if (gethrtime() > expire) {
			/*
			 * We have no visibility into the device to
			 * confirm it is making progress on this
			 * command. At this point the driver and
			 * device cannot agree on the state of the
			 * world: perhaps the device is still making
			 * progress but not fast enough, perhaps the
			 * device completed the command but there was
			 * a failure to deliver the reply, perhaps the
			 * command failed but once again the reply was
			 * not delivered. With this unknown state the
			 * best thing to do is to reset the device and
			 * start from scratch. But as we don't have
			 * that capability at the moment the next best
			 * thing to do is to spin or panic; we choose
			 * to panic.
			 */
			dev_err(ena->ena_dip, CE_PANIC,
			    "timed out waiting for admin response");
		}
	}

	ret = enahw_resp_status_to_errno(ena, ctx->ectx_resp->erd_status);
	ena_release_cmd_ctx(ena, ctx);
	return (ret);
}

void
ena_free_host_info(ena_t *ena)
{
	ena_dma_free(&ena->ena_host_info);
}

boolean_t
ena_init_host_info(ena_t *ena)
{
	enahw_host_info_t *ehi;
	int ret = 0;
	int *regs;
	uint_t nregs;
	ena_dma_buf_t *hi_dma;
	enahw_cmd_desc_t cmd;
	enahw_feat_host_attr_t *ha_cmd =
	    &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_host_attr;
	enahw_resp_desc_t resp;
	ena_dma_conf_t conf = {
		.edc_size = ENAHW_HOST_INFO_ALLOC_SZ,
		.edc_align = ENAHW_HOST_INFO_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = B_FALSE,
	};

	hi_dma = &ena->ena_host_info;

	if (!ena_dma_alloc(ena, hi_dma, &conf, 4096)) {
		ena_err(ena, "failed to allocate DMA for host info");
		return (B_FALSE);
	}

	ehi = (void *)hi_dma->edb_va;
	ehi->ehi_ena_spec_version =
	    ((ENA_SPEC_VERSION_MAJOR << ENAHW_HOST_INFO_SPEC_MAJOR_SHIFT) |
	    (ENA_SPEC_VERSION_MINOR));

	ehi->ehi_bdf = 0;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ena->ena_dip,
	    DDI_PROP_DONTPASS, "reg", &regs, &nregs) == DDI_PROP_SUCCESS) {
		if (nregs != 0) {
			ehi->ehi_bdf |= PCI_REG_BUS_G(regs[0]) << 8;
			ehi->ehi_bdf |= PCI_REG_DEV_G(regs[0]) << 3;
			ehi->ehi_bdf |= PCI_REG_FUNC_G(regs[0]);
		}

		ddi_prop_free(regs);
	}

	/*
	 * There is no illumos OS type, it would be nice to ping
	 * someone at Amazon and see if we can't get one added.
	 */
	ehi->ehi_os_type = ENAHW_OS_FREEBSD;
	ehi->ehi_kernel_ver = 511; /* If you know you know */
	(void) strlcpy((char *)ehi->ehi_kernel_ver_str, utsname.version,
	    sizeof (ehi->ehi_kernel_ver_str));
	ehi->ehi_os_dist = 0;	/* What everyone else does. */
	ehi->ehi_driver_ver =
	    (ENA_MODULE_VER_MAJOR) |
	    (ENA_MODULE_VER_MINOR << ENAHW_HOST_INFO_MINOR_SHIFT) |
	    (ENA_MODULE_VER_SUBMINOR << ENAHW_HOST_INFO_SUB_MINOR_SHIFT);
	ehi->ehi_num_cpus = ncpus_online;

	/*
	 * ENA devices are not created equal. Some will support
	 * features not found in others. This field tells the device
	 * which features the driver supports.
	 *
	 * ENAHW_HOST_INFO_RX_OFFSET
	 *
	 *    Some ENA devices will write the frame data at an offset
	 *    in the buffer, presumably for alignment purposes. We
	 *    support this feature for the sole reason that the Linux
	 *    driver does as well.
	 *
	 * ENAHW_HOST_INFO_INTERRUPT_MODERATION
	 *
	 *    Based on the Linux history this flag indicates that the
	 *    driver "supports interrupt moderation properly". What
	 *    that means is anyone's guess. The Linux driver seems to
	 *    have some "adaptive" interrupt moderation, so perhaps
	 *    it's that? In any case, FreeBSD doesn't bother with
	 *    setting this flag, so we'll leave it be for now as well.
	 *
	 *    If you're curious to know if the device supports
	 *    interrupt moderation: the FEAT_INTERRUPT_MODERATION flag
	 *    will be set in ena_hw.eh_supported_features.
	 *
	 * ENAHW_HOST_INFO_RX_BUF_MIRRORING
	 *
	 *    Support traffic mirroring by allowing the hypervisor to
	 *    read the buffer memory directly. This probably has to do
	 *    with AWS flow logs, allowing more efficient mirroring.
	 *    But it's hard to say for sure given we only have the
	 *    Linux commit log to go off of. In any case, the only
	 *    requirement for this feature is that the Rx DMA buffers
	 *    be read/write, which they are.
	 *
	 * ENAHW_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY
	 *
	 *    The device supports the retrieving and updating of the
	 *    RSS function and hash key. As we don't yet implement RSS
	 *    this is disabled.
	 */
	ehi->ehi_driver_supported_features =
	    ENAHW_HOST_INFO_RX_OFFSET_MASK |
	    ENAHW_HOST_INFO_RX_BUF_MIRRORING_MASK;

	ENA_DMA_SYNC(*hi_dma, DDI_DMA_SYNC_FORDEV);
	bzero(&cmd, sizeof (cmd));
	ena_set_dma_addr(ena, hi_dma->edb_cookie->dmac_laddress,
	    &ha_cmd->efha_os_addr);

	/*
	 * You might notice the "debug area" is not allocated or
	 * configured, that is on purpose.
	 *
	 * The "debug area" is a region of host memory that contains
	 * the String Set (SS) tables used to report statistics to
	 * tools like ethtool (on Linux). This table consists of one
	 * of more entries of a 32-byte string (the name of the
	 * statistic) along with its associated 64-bit value. The
	 * stats reported here contain both the host-side stats as
	 * well as device-reported stats (ENAHW_GET_STATS_TYPE_ENI). I
	 * believe the reason for calling it the "debug area" is that
	 * it can be accessed from outside of the guest, allowing an
	 * AWS user (?) or Amazon employee to get basic information
	 * about the state of the device from the guest's point of
	 * view.
	 *
	 * In the fullness of time, our driver should probably support
	 * this aspect of ENA. For the time being, all testing
	 * indicates the driver and device function fine without it.
	 */

	ret = ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_HOST_ATTR_CONFIG,
	    ENAHW_FEAT_HOST_ATTR_CONFIG_VER);
	if (ret != 0) {
		ena_err(ena, "failed to set host attributes: %d", ret);
		ena_dma_free(hi_dma);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
ena_create_cq(ena_t *ena, uint16_t num_descs, uint64_t phys_addr,
    boolean_t is_tx, uint32_t vector, uint16_t *hw_index,
    uint32_t **unmask_addr, uint32_t **headdb, uint32_t **numanode)
{
	int ret;
	enahw_cmd_desc_t cmd;
	enahw_cmd_create_cq_t *cmd_cq = &cmd.ecd_cmd.ecd_create_cq;
	enahw_resp_desc_t resp;
	enahw_resp_create_cq_t *resp_cq = &resp.erd_resp.erd_create_cq;
	ena_cmd_ctx_t *ctx = NULL;
	uint8_t desc_size = is_tx ? sizeof (enahw_tx_cdesc_t) :
	    sizeof (enahw_rx_cdesc_t);

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));

	cmd.ecd_opcode = ENAHW_CMD_CREATE_CQ;
	ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLE(cmd_cq);
	ASSERT3U(desc_size % 4, ==, 0);
	ENAHW_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd_cq, desc_size / 4);
	cmd_cq->ecq_num_descs = num_descs;
	cmd_cq->ecq_msix_vector = vector;
	ena_set_dma_addr(ena, phys_addr, &cmd_cq->ecq_addr);

	if ((ret = ena_admin_submit_cmd(ena, &cmd, &resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Create CQ command: %d", ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed to Create CQ: %d", ret);
		return (ret);
	}

	*hw_index = resp_cq->ercq_idx;
	*unmask_addr = (uint32_t *)(ena->ena_reg_base +
	    resp_cq->ercq_interrupt_mask_reg_offset);

	if (resp_cq->ercq_head_db_reg_offset != 0) {
		*headdb = (uint32_t *)(ena->ena_reg_base +
		    resp_cq->ercq_head_db_reg_offset);
	} else {
		*headdb = NULL;
	}

	if (resp_cq->ercq_numa_node_reg_offset != 0) {
		*numanode = (uint32_t *)(ena->ena_reg_base +
		    resp_cq->ercq_numa_node_reg_offset);
	} else {
		*numanode = NULL;
	}

	return (0);
}

int
ena_destroy_cq(ena_t *ena, uint16_t hw_idx)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;
	ena_cmd_ctx_t *ctx = NULL;
	int ret;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENAHW_CMD_DESTROY_CQ;
	cmd.ecd_cmd.ecd_destroy_cq.edcq_idx = hw_idx;

	if ((ret = ena_admin_submit_cmd(ena, &cmd, &resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Destroy CQ command: %d", ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed to Destroy CQ: %d", ret);
		return (ret);
	}

	return (0);
}

int
ena_create_sq(ena_t *ena, uint16_t num_descs, uint64_t phys_addr,
    boolean_t is_tx, uint16_t cq_index, uint16_t *hw_index, uint32_t **db_addr)
{
	int ret;
	enahw_cmd_desc_t cmd;
	enahw_cmd_create_sq_t *cmd_sq = &cmd.ecd_cmd.ecd_create_sq;
	enahw_resp_desc_t resp;
	enahw_resp_create_sq_t *resp_sq = &resp.erd_resp.erd_create_sq;
	enahw_sq_direction_t dir =
	    is_tx ? ENAHW_SQ_DIRECTION_TX : ENAHW_SQ_DIRECTION_RX;
	ena_cmd_ctx_t *ctx = NULL;

	if (!ISP2(num_descs)) {
		ena_err(ena, "the number of descs must be a power of 2, but "
		    " is %d", num_descs);
		return (B_FALSE);
	}

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENAHW_CMD_CREATE_SQ;
	ENAHW_CMD_CREATE_SQ_DIR(cmd_sq, dir);
	ENAHW_CMD_CREATE_SQ_PLACEMENT_POLICY(cmd_sq,
	    ENAHW_PLACEMENT_POLICY_HOST);
	ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY(cmd_sq,
	    ENAHW_COMPLETION_POLICY_DESC);
	/*
	 * We limit all SQ descriptor rings to an SGL of 1, therefore
	 * they are always physically contiguous.
	 */
	ENAHW_CMD_CREATE_SQ_PHYSMEM_CONTIG(cmd_sq);
	cmd_sq->ecsq_cq_idx = cq_index;
	cmd_sq->ecsq_num_descs = num_descs;

	/*
	 * If we ever use a non-host placement policy, then guard this
	 * code against placement type (this value should not be set
	 * for device placement).
	 */
	ena_set_dma_addr(ena, phys_addr, &cmd_sq->ecsq_base);

	if ((ret = ena_admin_submit_cmd(ena, &cmd, &resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Create SQ command: %d", ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed to Create SQ: %d", ret);
		return (ret);
	}

	*hw_index = resp_sq->ersq_idx;
	*db_addr = (uint32_t *)(ena->ena_reg_base +
	    resp_sq->ersq_db_reg_offset);
	return (0);
}

int
ena_destroy_sq(ena_t *ena, uint16_t hw_idx, boolean_t is_tx)
{
	enahw_cmd_desc_t cmd;
	enahw_cmd_destroy_sq_t *cmd_sq = &cmd.ecd_cmd.ecd_destroy_sq;
	enahw_sq_direction_t dir =
	    is_tx ? ENAHW_SQ_DIRECTION_TX : ENAHW_SQ_DIRECTION_RX;
	enahw_resp_desc_t resp;
	ena_cmd_ctx_t *ctx = NULL;
	int ret;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENAHW_CMD_DESTROY_SQ;
	cmd_sq->edsq_idx = hw_idx;
	ENAHW_CMD_DESTROY_SQ_DIR(cmd_sq, dir);

	if ((ret = ena_admin_submit_cmd(ena, &cmd, &resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Destroy SQ command: %d", ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed Destroy SQ: %d", ret);
		return (ret);
	}

	return (0);
}

/*
 * Determine if a given feature is available on this device.
 */
static boolean_t
ena_is_feature_avail(ena_t *ena, const enahw_feature_id_t feat_id)
{
	VERIFY3U(feat_id, <=, ENAHW_FEAT_NUM);
	uint32_t mask = 1U << feat_id;

	/*
	 * The device attributes feature is always supported, as
	 * indicated by the common code.
	 */
	if (feat_id == ENAHW_FEAT_DEVICE_ATTRIBUTES) {
		return (B_TRUE);
	}

	return ((ena->ena_supported_features & mask) != 0);
}

int
ena_set_feature(ena_t *ena, enahw_cmd_desc_t *cmd, enahw_resp_desc_t *resp,
    const enahw_feature_id_t feat_id, const uint8_t feat_ver)
{
	enahw_cmd_set_feat_t *cmd_sf = &cmd->ecd_cmd.ecd_set_feat;
	ena_cmd_ctx_t *ctx = NULL;
	int ret = 0;

	if (!ena_is_feature_avail(ena, feat_id)) {
		ena_err(ena, "attempted to set unsupported feature: 0x%x %d"
		    " (0x%x)", feat_id, feat_ver, ena->ena_supported_features);
		return (ENOTSUP);
	}

	cmd->ecd_opcode = ENAHW_CMD_SET_FEATURE;
	cmd_sf->ecsf_comm.efc_id = feat_id;
	cmd_sf->ecsf_comm.efc_version = feat_ver;
	cmd_sf->ecsf_comm.efc_flags = 0;

	if ((ret = ena_admin_submit_cmd(ena, cmd, resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Set Feature command: %d", ret);
		return (ret);
	}

	return (ena_admin_poll_for_resp(ena, ctx));
}

int
ena_get_feature(ena_t *ena, enahw_resp_desc_t *resp,
    const enahw_feature_id_t feat_id, const uint8_t feat_ver)
{
	enahw_cmd_desc_t cmd;
	enahw_cmd_get_feat_t *cmd_gf = &cmd.ecd_cmd.ecd_get_feat;
	ena_cmd_ctx_t *ctx = NULL;
	int ret = 0;

	if (!ena_is_feature_avail(ena, feat_id)) {
		return (ENOTSUP);
	}

	bzero(&cmd, sizeof (cmd));
	cmd.ecd_opcode = ENAHW_CMD_GET_FEATURE;
	cmd_gf->ecgf_comm.efc_id = feat_id;
	cmd_gf->ecgf_comm.efc_version = feat_ver;
	ENAHW_GET_FEAT_FLAGS_GET_CURR_VAL(cmd_gf);

	if ((ret = ena_admin_submit_cmd(ena, &cmd, resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Get Feature command: %d", ret);
		return (ret);
	}

	return (ena_admin_poll_for_resp(ena, ctx));
}

int
ena_admin_get_basic_stats(ena_t *ena, enahw_resp_desc_t *resp)
{
	int ret = 0;
	enahw_cmd_desc_t cmd;
	enahw_cmd_get_stats_t *cmd_stats = &cmd.ecd_cmd.ecd_get_stats;
	ena_cmd_ctx_t *ctx = NULL;

	bzero(&cmd, sizeof (cmd));
	bzero(resp, sizeof (*resp));
	cmd.ecd_opcode = ENAHW_CMD_GET_STATS;
	cmd_stats->ecgs_type = ENAHW_GET_STATS_TYPE_BASIC;
	cmd_stats->ecgs_scope = ENAHW_GET_STATS_SCOPE_ETH;
	cmd_stats->ecgs_device_id = ENAHW_CMD_GET_STATS_MY_DEVICE_ID;

	if ((ret = ena_admin_submit_cmd(ena, &cmd, resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Get Basic Stats command: %d",
		    ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed to Get Basic Stats: %d", ret);
		return (ret);
	}

	return (0);
}

int
ena_admin_get_eni_stats(ena_t *ena, enahw_resp_desc_t *resp)
{
	int ret = 0;
	enahw_cmd_desc_t cmd;
	enahw_cmd_get_stats_t *cmd_stats = &cmd.ecd_cmd.ecd_get_stats;
	ena_cmd_ctx_t *ctx = NULL;

	bzero(&cmd, sizeof (cmd));
	bzero(resp, sizeof (*resp));
	cmd.ecd_opcode = ENAHW_CMD_GET_STATS;
	cmd_stats->ecgs_type = ENAHW_GET_STATS_TYPE_ENI;
	cmd_stats->ecgs_scope = ENAHW_GET_STATS_SCOPE_ETH;
	cmd_stats->ecgs_device_id = ENAHW_CMD_GET_STATS_MY_DEVICE_ID;

	if ((ret = ena_admin_submit_cmd(ena, &cmd, resp, &ctx)) != 0) {
		ena_err(ena, "failed to submit Get ENI Stats command: %d", ret);
		return (ret);
	}

	if ((ret = ena_admin_poll_for_resp(ena, ctx)) != 0) {
		ena_err(ena, "failed to Get ENI Stats: %d", ret);
		return (ret);
	}

	return (0);
}
