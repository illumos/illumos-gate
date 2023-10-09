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
 * Copyright 2023 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2021 RackTop Systems, Inc.
 */

/*
 * This file contains all routines necessary to interface with SCSA trans.
 */
#include <smartpqi.h>

/*
 * []------------------------------------------------------------------[]
 * | Forward declarations for SCSA trans routines.			|
 * []------------------------------------------------------------------[]
 */
static int pqi_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static void pqi_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int pqi_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int pqi_scsi_reset(struct scsi_address *ap, int level);
static int pqi_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int pqi_scsi_getcap(struct scsi_address *ap, char *cap, int tgtonly);
static int pqi_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int tgtonly);
static struct scsi_pkt *pqi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen, int tgtlen,
    int flags,  int (*callback)(), caddr_t arg);
static void pqi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static void pqi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static void pqi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static int pqi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);
static int pqi_quiesce(dev_info_t *dip);
static int pqi_unquiesce(dev_info_t *dip);
static int pqi_bus_config(dev_info_t *pdip, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);

/* ---- Support method declaration ---- */
static int config_one(dev_info_t *pdip, pqi_state_t *s,  pqi_device_t *,
    dev_info_t **childp);
static void abort_all(struct scsi_address *ap, pqi_state_t *s);
static int cmd_ext_alloc(pqi_cmd_t *cmd, int kf);
static void cmd_ext_free(pqi_cmd_t *cmd);
static boolean_t is_physical_dev(pqi_device_t *d);
static void cmd_timeout_scan(void *);

boolean_t
smartpqi_register_hba(pqi_state_t *s)
{
	scsi_hba_tran_t		*tran;
	int			flags;
	char			iport_str[16];
	int			instance = ddi_get_instance(s->s_dip);

	tran = scsi_hba_tran_alloc(s->s_dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL)
		return (B_FALSE);
	s->s_tran = tran;

	tran->tran_hba_private		= s;
	tran->tran_tgt_private		= NULL;

	tran->tran_tgt_init		= pqi_scsi_tgt_init;
	tran->tran_tgt_free		= pqi_scsi_tgt_free;
	tran->tran_tgt_probe		= scsi_hba_probe;

	tran->tran_start		= pqi_start;
	tran->tran_reset		= pqi_scsi_reset;
	tran->tran_abort		= pqi_scsi_abort;
	tran->tran_getcap		= pqi_scsi_getcap;
	tran->tran_setcap		= pqi_scsi_setcap;
	tran->tran_bus_config		= pqi_bus_config;

	tran->tran_init_pkt		= pqi_init_pkt;
	tran->tran_destroy_pkt		= pqi_destroy_pkt;
	tran->tran_dmafree		= pqi_dmafree;
	tran->tran_sync_pkt		= pqi_sync_pkt;

	tran->tran_reset_notify		= pqi_reset_notify;
	tran->tran_quiesce		= pqi_quiesce;
	tran->tran_unquiesce		= pqi_unquiesce;
	tran->tran_bus_reset		= NULL;

	tran->tran_add_eventcall	= NULL;
	tran->tran_get_eventcookie	= NULL;
	tran->tran_post_event		= NULL;
	tran->tran_remove_eventcall	= NULL;
	tran->tran_bus_config		= pqi_bus_config;
	tran->tran_interconnect_type	= INTERCONNECT_SAS;

	/*
	 * scsi_vhci needs to have "initiator-port" set, but doesn't
	 * seem to care what it's set to. iSCSI uses the InitiatorName
	 * whereas mpt_sas uses the WWN port id, but this HBA doesn't
	 * have such a value. So, for now the instance number will be used.
	 */
	(void) snprintf(iport_str, sizeof (iport_str), "0x%x", instance);
	if (ddi_prop_update_string(DDI_DEV_T_NONE, s->s_dip,
	    SCSI_ADDR_PROP_INITIATOR_PORT, iport_str) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to create prop (%s) on %d\n",
		    __func__, SCSI_ADDR_PROP_INITIATOR_PORT, instance);
	}

	flags = SCSI_HBA_ADDR_COMPLEX | SCSI_HBA_TRAN_SCB;
	if (scsi_hba_attach_setup(s->s_dip, &s->s_msg_dma_attr, tran,
	    flags) != DDI_SUCCESS) {
		dev_err(s->s_dip, CE_NOTE, "scsi_hba_attach_setup failed");
		scsi_hba_tran_free(s->s_tran);
		s->s_tran = NULL;
		return (B_FALSE);
	}

	if (!s->s_disable_mpxio) {
		if (mdi_phci_register(MDI_HCI_CLASS_SCSI, s->s_dip, 0) !=
		    MDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: Failed to register with mpxio",
			    __func__);
			s->s_disable_mpxio = B_TRUE;
		}
	}

	s->s_cmd_timeout = timeout(cmd_timeout_scan, s,
	    CMD_TIMEOUT_SCAN_SECS * drv_usectohz(MICROSEC));

	return (B_TRUE);
}

void
smartpqi_unregister_hba(pqi_state_t *s)
{
	if (!s->s_disable_mpxio)
		(void) mdi_phci_unregister(s->s_dip, 0);

	if (s->s_cmd_timeout != NULL) {
		(void) untimeout(s->s_cmd_timeout);
		s->s_cmd_timeout = NULL;
	}

	if (s->s_tran == NULL)
		return;
	scsi_hba_tran_free(s->s_tran);
	s->s_tran = NULL;
}

static int
pqi_scsi_tgt_init(dev_info_t *hba_dip __unused, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	pqi_device_t	*d;
	pqi_state_t	*s	= hba_tran->tran_hba_private;
	mdi_pathinfo_t	*pip;
	int		type;
	char		*ua;

	if ((ua = scsi_device_unit_address(sd)) == NULL) {
		return (DDI_FAILURE);
	}

	if ((d = pqi_find_target_ua(s, ua)) == NULL) {
		return (DDI_FAILURE);
	}

	scsi_device_hba_private_set(sd, d);

	type = mdi_get_component_type(tgt_dip);
	if (type == MDI_COMPONENT_CLIENT) {
		char	wwid_str[64];

		if ((pip = (mdi_pathinfo_t *)sd->sd_private) == NULL)
			return (DDI_NOT_WELL_FORMED);

		(void) snprintf(wwid_str, sizeof (wwid_str), "%" PRIx64,
		    d->pd_wwid);
		(void) mdi_prop_update_string(pip, SCSI_ADDR_PROP_TARGET_PORT,
		    wwid_str);
	}

	return (DDI_SUCCESS);
}

static void
pqi_scsi_tgt_free(dev_info_t *hba_dip __unused, dev_info_t *tgt_dip __unused,
    scsi_hba_tran_t *hba_tran __unused, struct scsi_device *sd __unused)
{
}

/*
 * Notes:
 *      - transport the command to the addressed SCSI target/lun device
 *      - normal operation is to schedule the command to be transported,
 *        and return TRAN_ACCEPT if this is successful.
 *      - if NO_INTR, tran_start must poll device for command completion
 */
static int
pqi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	boolean_t	poll	= ((pkt->pkt_flags & FLAG_NOINTR) != 0);
	int		rc;
	pqi_cmd_t	*cmd	= PKT2CMD(pkt);
	pqi_state_t	*s	= ap->a_hba_tran->tran_hba_private;

	ASSERT3P(cmd->pc_pkt, ==, pkt);
	ASSERT3P(cmd->pc_softc, ==, s);

	if (pqi_is_offline(s) || !cmd->pc_device->pd_online)
		return (TRAN_FATAL_ERROR);

	/*
	 * Reinitialize some fields because the packet may have been
	 * resubmitted.
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;

	/* ---- Zero status byte ---- */
	*(pkt->pkt_scbp) = 0;

	if ((cmd->pc_flags & PQI_FLAG_DMA_VALID) != 0) {
		ASSERT(cmd->pc_dma_count);
		pkt->pkt_resid = cmd->pc_dma_count;

		/* ---- Sync consistent packets first (only write data) ---- */
		if (((cmd->pc_flags & PQI_FLAG_IO_IOPB) != 0) ||
		    ((cmd->pc_flags & PQI_FLAG_IO_READ) == 0)) {
			(void) ddi_dma_sync(cmd->pc_dmahdl, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	}

	mutex_enter(&s->s_mutex);
	if (HBA_IS_QUIESCED(s) && !poll) {
		mutex_exit(&s->s_mutex);
		return (TRAN_BUSY);
	}
	mutex_exit(&s->s_mutex);

	rc = pqi_transport_command(s, cmd);

	if (poll) {
		boolean_t	qnotify;

		if (rc == TRAN_ACCEPT) {
			uint32_t	old_state;
			int		timeo;

			timeo = pkt->pkt_time ? pkt->pkt_time :
			    SCSI_POLL_TIMEOUT;
			timeo *= MILLISEC / 2;
			old_state = pqi_disable_intr(s);
			do {
				drv_usecwait(MILLISEC / 2);
				pqi_process_io_intr(s, &s->s_queue_groups[0]);
				if (--timeo == 0) {
					pkt->pkt_state |= STAT_TIMEOUT;
					pkt->pkt_reason = CMD_TIMEOUT;
					break;
				}
			} while (pkt->pkt_state == 0);
			pqi_enable_intr(s, old_state);
		}

		scsi_hba_pkt_comp(pkt);

		mutex_enter(&s->s_mutex);
		qnotify = HBA_QUIESCED_PENDING(s);
		mutex_exit(&s->s_mutex);

		if (qnotify)
			pqi_quiesced_notify(s);
	}

	return (rc);
}

static int
pqi_scsi_reset(struct scsi_address *ap, int level)
{
	pqi_device_t	*d;
	pqi_state_t	*s;
	int		rval = FALSE;

	s = ap->a_hba_tran->tran_hba_private;
	switch (level) {
	case RESET_TARGET:
	case RESET_LUN:
		if ((d = scsi_device_hba_private_get(ap->a.a_sd)) == NULL)
			break;

		pqi_lun_reset(s, d);
		rval = TRUE;
		break;

	case RESET_BUS:
	case RESET_ALL:
		mutex_enter(&s->s_mutex);
		for (d = list_head(&s->s_devnodes); d != NULL;
		    d = list_next(&s->s_devnodes, d)) {
			pqi_lun_reset(s, d);
		}
		mutex_exit(&s->s_mutex);
		rval = TRUE;
		break;
	}
	return (rval);
}

/*
 * abort handling:
 *
 * Notes:
 *      - if pkt is not NULL, abort just that command
 *      - if pkt is NULL, abort all outstanding commands for target
 */
static int
pqi_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	boolean_t	qnotify	= B_FALSE;
	pqi_state_t	*s	= ADDR2PQI(ap);

	if (pkt != NULL) {
		/* ---- Abort single command ---- */
		pqi_cmd_t	*cmd = PKT2CMD(pkt);

		mutex_enter(&cmd->pc_device->pd_mutex);
		(void) pqi_fail_cmd(cmd, CMD_ABORTED, STAT_ABORTED);
		mutex_exit(&cmd->pc_device->pd_mutex);
	} else {
		abort_all(ap, s);
	}
	qnotify = HBA_QUIESCED_PENDING(s);

	if (qnotify)
		pqi_quiesced_notify(s);
	return (1);
}

/*
 * capability handling:
 * (*tran_getcap).  Get the capability named, and return its value.
 */
static int
pqi_scsi_getcap(struct scsi_address *ap, char *cap, int tgtonly __unused)
{
	pqi_state_t *s = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL)
		return (-1);
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_LUN_RESET:
		return ((s->s_flags & PQI_HBA_LUN_RESET_CAP) != 0);
	case SCSI_CAP_ARQ:
		return ((s->s_flags & PQI_HBA_AUTO_REQUEST_SENSE) != 0);
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	default:
		return (-1);
	}
}

/*
 * (*tran_setcap).  Set the capability named to the value given.
 */
static int
pqi_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int tgtonly __unused)
{
	pqi_state_t	*s	= ADDR2PQI(ap);
	int		rval	= FALSE;

	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		if (value)
			s->s_flags |= PQI_HBA_AUTO_REQUEST_SENSE;
		else
			s->s_flags &= ~PQI_HBA_AUTO_REQUEST_SENSE;
		rval = 1;
		break;

	case SCSI_CAP_LUN_RESET:
		if (value)
			s->s_flags |= PQI_HBA_LUN_RESET_CAP;
		else
			s->s_flags &= ~PQI_HBA_LUN_RESET_CAP;
		break;

	default:
		break;
	}

	return (rval);
}

int
pqi_cache_constructor(void *buf, void *un, int flags)
{
	pqi_cmd_t		*c	= (pqi_cmd_t *)buf;
	pqi_state_t		*s	= un;
	int			(*callback)(caddr_t);

	bzero(c, sizeof (*c));
	c->pc_softc = s;
	callback = (flags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	/* ---- Allocate a DMA handle for data transfers ---- */
	if (ddi_dma_alloc_handle(s->s_dip, &s->s_msg_dma_attr, callback,
	    NULL, &c->pc_dmahdl) != DDI_SUCCESS) {
		dev_err(s->s_dip, CE_WARN, "Failed to alloc dma handle");
		return (-1);
	}

	return (0);
}

void
pqi_cache_destructor(void *buf, void *un __unused)
{
	pqi_cmd_t	*cmd = buf;
	if (cmd->pc_dmahdl != NULL) {
		(void) ddi_dma_unbind_handle(cmd->pc_dmahdl);
		ddi_dma_free_handle(&cmd->pc_dmahdl);
		cmd->pc_dmahdl = NULL;
	}
}

/*
 * tran_init_pkt(9E) - allocate scsi_pkt(9S) for command
 *
 * One of three possibilities:
 *      - allocate scsi_pkt
 *      - allocate scsi_pkt and DMA resources
 *      - allocate DMA resources to an already-allocated pkt
 */
static struct scsi_pkt *
pqi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(), caddr_t arg)
{
	pqi_cmd_t	*cmd;
	pqi_state_t	*s;
	int		kf = (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;
	boolean_t	is_new = B_FALSE;
	int		rc;
	int		i;
	pqi_device_t	*devp;

	s = ap->a_hba_tran->tran_hba_private;

	if (pkt == NULL) {
		ddi_dma_handle_t	saved_dmahdl;
		pqi_cmd_action_t	saved_action;

		if ((devp = scsi_device_hba_private_get(ap->a.a_sd)) == NULL)
			return (NULL);
		if ((cmd = kmem_cache_alloc(s->s_cmd_cache, kf)) == NULL)
			return (NULL);

		is_new = B_TRUE;
		saved_dmahdl = cmd->pc_dmahdl;
		saved_action = cmd->pc_last_action;

		(void) memset(cmd, 0, sizeof (*cmd));
		mutex_init(&cmd->pc_mutex, NULL, MUTEX_DRIVER, NULL);

		cmd->pc_dmahdl = saved_dmahdl;
		cmd->pc_last_action = saved_action;

		cmd->pc_device = devp;
		cmd->pc_pkt = &cmd->pc_cached_pkt;
		cmd->pc_softc = s;
		cmd->pc_tgtlen = tgtlen;
		cmd->pc_statuslen = statuslen;
		cmd->pc_cmdlen = cmdlen;
		cmd->pc_dma_count = 0;

		pkt = cmd->pc_pkt;
		pkt->pkt_ha_private = cmd;
		pkt->pkt_address = *ap;
		pkt->pkt_scbp = (uint8_t *)&cmd->pc_cmd_scb;
		pkt->pkt_cdbp = cmd->pc_cdb;
		pkt->pkt_private = (opaque_t)cmd->pc_tgt_priv;
		if (pkt->pkt_time == 0)
			pkt->pkt_time = SCSI_POLL_TIMEOUT;

		if (cmdlen > sizeof (cmd->pc_cdb) ||
		    statuslen > sizeof (cmd->pc_cmd_scb) ||
		    tgtlen > sizeof (cmd->pc_tgt_priv)) {
			if (cmd_ext_alloc(cmd, kf) != DDI_SUCCESS) {
				dev_err(s->s_dip, CE_WARN,
				    "extent allocation failed");
				goto out;
			}
		}
	} else {
		cmd = PKT2CMD(pkt);
		cmd->pc_flags &= PQI_FLAGS_PERSISTENT;
	}

	/* ---- Handle partial DMA transfer ---- */
	if (cmd->pc_nwin > 0) {
		if (++cmd->pc_winidx >= cmd->pc_nwin)
			return (NULL);
		if (ddi_dma_getwin(cmd->pc_dmahdl, cmd->pc_winidx,
		    &cmd->pc_dma_offset, &cmd->pc_dma_len, &cmd->pc_dmac,
		    &cmd->pc_dmaccount) == DDI_FAILURE)
			return (NULL);
		goto handle_dma_cookies;
	}

	/* ---- Setup data buffer ---- */
	if (bp != NULL && bp->b_bcount > 0 &&
	    (cmd->pc_flags & PQI_FLAG_DMA_VALID) == 0) {
		int	dma_flags;

		ASSERT(cmd->pc_dmahdl != NULL);

		if ((bp->b_flags & B_READ) != 0) {
			cmd->pc_flags |= PQI_FLAG_IO_READ;
			dma_flags = DDI_DMA_READ;
		} else {
			cmd->pc_flags &= ~PQI_FLAG_IO_READ;
			dma_flags = DDI_DMA_WRITE;
		}
		if ((flags & PKT_CONSISTENT) != 0) {
			cmd->pc_flags |= PQI_FLAG_IO_IOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}
		if ((flags & PKT_DMA_PARTIAL) != 0) {
			dma_flags |= DDI_DMA_PARTIAL;
		}
		rc = ddi_dma_buf_bind_handle(cmd->pc_dmahdl, bp,
		    dma_flags, callback, arg, &cmd->pc_dmac,
		    &cmd->pc_dmaccount);

		if (rc == DDI_DMA_PARTIAL_MAP) {
			(void) ddi_dma_numwin(cmd->pc_dmahdl, &cmd->pc_nwin);
			cmd->pc_winidx = 0;
			(void) ddi_dma_getwin(cmd->pc_dmahdl, cmd->pc_winidx,
			    &cmd->pc_dma_offset, &cmd->pc_dma_len,
			    &cmd->pc_dmac, &cmd->pc_dmaccount);
		} else if (rc != 0 && rc != DDI_DMA_MAPPED) {
			switch (rc) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			goto out;
		}

handle_dma_cookies:
		ASSERT(cmd->pc_dmaccount > 0);
		if (cmd->pc_dmaccount >
		    (sizeof (cmd->pc_cached_cookies) /
		    sizeof (ddi_dma_cookie_t))) {
			dev_err(s->s_dip, CE_WARN,
			    "invalid cookie count: %d", cmd->pc_dmaccount);
			goto out;
		}
		if (cmd->pc_dmaccount >
		    (s->s_sg_chain_buf_length / sizeof (pqi_sg_entry_t))) {
			dev_err(s->s_dip, CE_WARN,
			    "Cookie(0x%x) verses SG(0x%" PRIx64 ") mismatch",
			    cmd->pc_dmaccount,
			    s->s_sg_chain_buf_length / sizeof (pqi_sg_entry_t));
			goto out;
		}

		cmd->pc_flags |= PQI_FLAG_DMA_VALID;
		cmd->pc_dma_count = cmd->pc_dmac.dmac_size;
		cmd->pc_cached_cookies[0] = cmd->pc_dmac;

		for (i = 1; i < cmd->pc_dmaccount; i++) {
			ddi_dma_nextcookie(cmd->pc_dmahdl, &cmd->pc_dmac);
			cmd->pc_cached_cookies[i] = cmd->pc_dmac;
			cmd->pc_dma_count += cmd->pc_dmac.dmac_size;
		}

		pkt->pkt_resid = bp->b_bcount - cmd->pc_dma_count;
	}

	return (pkt);

out:
	if (is_new == B_TRUE)
		pqi_destroy_pkt(ap, pkt);
	return (NULL);
}

/*
 * tran_destroy_pkt(9E) - scsi_pkt(9s) deallocation
 *
 * Notes:
 *      - also frees DMA resources if allocated
 *      - implicit DMA synchonization
 */
static void
pqi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pqi_cmd_t	*c = PKT2CMD(pkt);
	pqi_state_t	*s = ADDR2PQI(ap);

	if ((c->pc_flags & PQI_FLAG_DMA_VALID) != 0) {
		c->pc_flags &= ~PQI_FLAG_DMA_VALID;
		(void) ddi_dma_unbind_handle(c->pc_dmahdl);
	}
	cmd_ext_free(c);

	kmem_cache_free(s->s_cmd_cache, c);
}

/*
 * tran_dmafree(9E) - deallocate DMA resources allocated for command
 */
static void
pqi_dmafree(struct scsi_address *ap __unused, struct scsi_pkt *pkt)
{
	pqi_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->pc_flags & PQI_FLAG_DMA_VALID) {
		cmd->pc_flags &= ~PQI_FLAG_DMA_VALID;
		(void) ddi_dma_unbind_handle(cmd->pc_dmahdl);
	}
}

/*
 * tran_sync_pkt(9E) - explicit DMA synchronization
 */
static void
pqi_sync_pkt(struct scsi_address *ap __unused, struct scsi_pkt *pkt)
{
	pqi_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->pc_dmahdl != NULL) {
		(void) ddi_dma_sync(cmd->pc_dmahdl, 0, 0,
		    (cmd->pc_flags & PQI_FLAG_IO_READ) ? DDI_DMA_SYNC_FORCPU :
		    DDI_DMA_SYNC_FORDEV);
	}
}

static int
pqi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	pqi_state_t	*s = ADDR2PQI(ap);

	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &s->s_mutex, &s->s_reset_notify_listf));
}

/*
 * Device / Hotplug control
 */
static int
pqi_quiesce(dev_info_t *dip)
{
	pqi_state_t	*s;
	scsi_hba_tran_t	*tran;

	if ((tran = ddi_get_driver_private(dip)) == NULL ||
	    (s = TRAN2PQI(tran)) == NULL)
		return (-1);

	mutex_enter(&s->s_mutex);
	if (!HBA_IS_QUIESCED(s))
		s->s_flags |= PQI_HBA_QUIESCED;

	if (s->s_cmd_queue_len != 0) {
		/* ---- Outstanding commands present, wait ---- */
		s->s_flags |= PQI_HBA_QUIESCED_PENDING;
		cv_wait(&s->s_quiescedvar, &s->s_mutex);
		ASSERT0(s->s_cmd_queue_len);
	}
	mutex_exit(&s->s_mutex);

	return (0);
}

static int
pqi_unquiesce(dev_info_t *dip)
{
	pqi_state_t	*s;
	scsi_hba_tran_t	*tran;

	if ((tran = ddi_get_driver_private(dip)) == NULL ||
	    (s = TRAN2PQI(tran)) == NULL)
		return (-1);

	mutex_enter(&s->s_mutex);
	if (!HBA_IS_QUIESCED(s)) {
		mutex_exit(&s->s_mutex);
		return (0);
	}
	ASSERT0(s->s_cmd_queue_len);
	s->s_flags &= ~PQI_HBA_QUIESCED;
	mutex_exit(&s->s_mutex);

	return (0);
}

static int
pqi_bus_config(dev_info_t *pdip, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t	*tran;
	pqi_state_t	*s;
	int		ret	= NDI_FAILURE;
	pqi_device_t	*d;
	char		*ua;

	tran = ddi_get_driver_private(pdip);
	s = tran->tran_hba_private;
	if (pqi_is_offline(s))
		return (NDI_FAILURE);

	ndi_devi_enter(scsi_vhci_dip);
	ndi_devi_enter(pdip);
	switch (op) {
	case BUS_CONFIG_ONE:
		if ((ua = strrchr((char *)arg, '@')) != NULL) {
			ua++;
			d = pqi_find_target_ua(s, ua);
			if (d != NULL)
				ret = config_one(pdip, s, d, childp);
		} else {
			dev_err(s->s_dip, CE_WARN, "Couldn't decode %s",
			    (char *)arg);
		}
		flag |= NDI_MDI_FALLBACK;
		break;

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		ret = pqi_config_all(pdip, s);
		break;
	default:
		ret = NDI_FAILURE;
	}
	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_config(pdip, flag, op, arg, childp, 0);
	ndi_devi_exit(pdip);
	ndi_devi_exit(scsi_vhci_dip);

	return (ret);
}

pqi_device_t *
pqi_find_target_ua(pqi_state_t *s, char *ua)
{
	pqi_device_t *d;

	mutex_enter(&s->s_mutex);
	for (d = list_head(&s->s_devnodes); d != NULL;
	    d = list_next(&s->s_devnodes, d)) {
		if (d->pd_online && strcmp(ua, d->pd_unit_address) == 0)
			break;
	}
	mutex_exit(&s->s_mutex);
	return (d);
}

int
pqi_config_all(dev_info_t *pdip, pqi_state_t *s)
{
	pqi_device_t *d;

	/*
	 * Make sure we bring the available devices into play first. These
	 * might be brand new devices just hotplugged into the system or
	 * they could be devices previously offlined because either they
	 * were pulled from an enclosure or a cable to the enclosure was
	 * pulled.
	 */
	/* ---- XXX Grab s_mutex ---- */
	for (d = list_head(&s->s_devnodes); d != NULL;
	    d = list_next(&s->s_devnodes, d)) {
		if (d->pd_online)
			(void) config_one(pdip, s, d, NULL);
	}

	/*
	 * Now deal with devices that we had previously known about, but are
	 * no longer available.
	 */
	for (d = list_head(&s->s_devnodes); d != NULL;
	    d = list_next(&s->s_devnodes, d)) {
		if (!d->pd_online)
			(void) config_one(pdip, s, d, NULL);
	}

	return (NDI_SUCCESS);
}

void
pqi_quiesced_notify(pqi_state_t *s)
{
	mutex_enter(&s->s_mutex);
	if (s->s_cmd_queue_len == 0 &&
	    (s->s_flags & PQI_HBA_QUIESCED_PENDING) != 0) {
		s->s_flags &= ~PQI_HBA_QUIESCED_PENDING;
		cv_broadcast(&s->s_quiescedvar);
	}
	mutex_exit(&s->s_mutex);
}

/*
 * []------------------------------------------------------------------[]
 * | Support routines used only by the trans_xxx routines		|
 * []------------------------------------------------------------------[]
 */
#ifdef DEBUG
int	pqi_force_timeout;
#endif	/* DEBUG */

static void
cmd_timeout_drive(pqi_device_t *d)
{
	uint32_t	timed_out_cnt = 0;
	pqi_cmd_t	*c, *next_c;
	hrtime_t	now = gethrtime();

	mutex_enter(&d->pd_mutex);

rescan:
	c = list_head(&d->pd_cmd_list);
	while (c != NULL) {
		next_c = list_next(&d->pd_cmd_list, c);
#ifdef DEBUG
		if (c->pc_expiration < now || pqi_force_timeout != 0) {
			pqi_force_timeout = 0;
#else
		if (c->pc_expiration < now) {
#endif	/* DEBUG */
			struct scsi_pkt	*pkt = CMD2PKT(c);

			if (pkt != NULL) {
				pkt->pkt_reason = CMD_TIMEOUT;
				pkt->pkt_statistics = STAT_TIMEOUT;
			}
			ASSERT(c->pc_io_rqst != NULL);
			/*
			 * If the i/o has not been serviced yet,
			 * mark the i/o as timed out and clear it out
			 */
			if (pqi_timeout_io(c->pc_io_rqst)) {
				(void) pqi_cmd_action_nolock(c,
				    PQI_CMD_TIMEOUT);
				timed_out_cnt++;
				/*
				 * We dropped pd_mutex so the cmd
				 * list could have changed, restart the
				 * scan of the cmds.  This will terminate
				 * since timed out cmds are removed from
				 * the list.
				 */
				goto rescan;
			}
		}
		c = next_c;
	}

	d->pd_timedout += timed_out_cnt;
	mutex_exit(&d->pd_mutex);
}

static void
cmd_timeout_scan(void *v)
{
	pqi_state_t		*s = v;
	pqi_device_t		*d;

	mutex_enter(&s->s_mutex);

	for (d = list_head(&s->s_devnodes); d != NULL;
	    d = list_next(&s->s_devnodes, d)) {
		cmd_timeout_drive(d);
	}
	cmd_timeout_drive(&s->s_special_device);

	mutex_exit(&s->s_mutex);
	s->s_cmd_timeout = timeout(cmd_timeout_scan, s,
	    CMD_TIMEOUT_SCAN_SECS * drv_usectohz(MICROSEC));
}

static void
abort_all(struct scsi_address *ap, pqi_state_t *s __unused)
{
	pqi_device_t	*devp;

	if ((devp = scsi_device_hba_private_get(ap->a.a_sd)) == NULL)
		return;

	pqi_fail_drive_cmds(devp, CMD_ABORTED);
}

static boolean_t
create_phys_lun(pqi_state_t *s, pqi_device_t *d,
    struct scsi_inquiry *inq, dev_info_t **childp)
{
	char		**compatible	= NULL;
	char		*nodename	= NULL;
	int		ncompatible	= 0;
	dev_info_t	*dip;

	/* ---- At this point we have a new device not in our list ---- */
	scsi_hba_nodename_compatible_get(inq, NULL,
	    inq->inq_dtype, NULL, &nodename, &compatible, &ncompatible);
	if (nodename == NULL)
		return (B_FALSE);

	if (ndi_devi_alloc(s->s_dip, nodename, DEVI_SID_NODEID, &dip) !=
	    NDI_SUCCESS) {
		dev_err(s->s_dip, CE_WARN, "failed to alloc device instance");
		goto free_nodename;
	}

	d->pd_dip = dip;
	d->pd_pip = NULL;

	if (ndi_prop_update_int64(DDI_DEV_T_NONE, dip, LUN64_PROP,
	    d->pd_lun) != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, COMPAT_PROP,
	    compatible, ncompatible) != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (d->pd_wwid != 0) {
		char		wwn_str[20];
		(void) snprintf(wwn_str, 20, "w%016" PRIx64, d->pd_wwid);
		if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    SCSI_ADDR_PROP_TARGET_PORT, wwn_str) != DDI_PROP_SUCCESS) {
			goto free_devi;
		}
	} else {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, TARGET_PROP,
		    d->pd_target) != DDI_PROP_SUCCESS) {
			goto free_devi;
		}
	}

	if (d->pd_guid != NULL) {
		if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, NDI_GUID,
		    d->pd_guid) != DDI_PROP_SUCCESS) {
			goto free_devi;
		}
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, "pm-capable", 1) !=
	    DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_devi_online(dip, NDI_ONLINE_ATTACH) != NDI_SUCCESS)
		goto free_devi;

	if (childp != NULL)
		*childp = dip;

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (B_TRUE);

free_devi:
	ndi_prop_remove_all(dip);
	(void) ndi_devi_free(dip);
	d->pd_dip = NULL;
free_nodename:
	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (B_FALSE);
}

static boolean_t
create_virt_lun(pqi_state_t *s, pqi_device_t *d, struct scsi_inquiry *inq,
    dev_info_t **childp)
{
	char		*nodename;
	char		**compatible;
	int		ncompatible;
	int		rval;
	mdi_pathinfo_t	*pip		= NULL;
	char		*guid_ptr;
	char		wwid_str[17];
	dev_info_t	*lun_dip;
	char		*old_guid;

	if (d->pd_pip_offlined != NULL) {
		lun_dip = mdi_pi_get_client(d->pd_pip_offlined);
		ASSERT(lun_dip != NULL);

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lun_dip,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    MDI_CLIENT_GUID_PROP, &old_guid) == DDI_SUCCESS) {
			if (strncmp(d->pd_guid, old_guid,
			    strlen(d->pd_guid)) == 0) {
				/* ---- Same path came back online ---- */
				(void) ddi_prop_free(old_guid);
				if (mdi_pi_online(d->pd_pip_offlined, 0) ==
				    DDI_SUCCESS) {
					d->pd_pip = d->pd_pip_offlined;
					d->pd_pip_offlined = NULL;
					return (B_TRUE);
				} else {
					return (B_FALSE);
				}
			} else {
				/* ---- Different device in slot ---- */
				(void) ddi_prop_free(old_guid);
				if (mdi_pi_offline(d->pd_pip_offlined, 0) !=
				    DDI_SUCCESS) {
					return (B_FALSE);
				}
				if (mdi_pi_free(d->pd_pip_offlined, 0) !=
				    MDI_SUCCESS) {
					return (B_FALSE);
				}
				d->pd_pip_offlined = NULL;
			}
		} else {
			dev_err(s->s_dip, CE_WARN, "Can't get client-guid "
			    "property for lun %lx", d->pd_wwid);
			return (B_FALSE);
		}
	}

	scsi_hba_nodename_compatible_get(inq, NULL, inq->inq_dtype, NULL,
	    &nodename, &compatible, &ncompatible);
	if (nodename == NULL)
		return (B_FALSE);

	if (d->pd_guid != NULL) {
		guid_ptr = d->pd_guid;
	} else {
		(void) snprintf(wwid_str, sizeof (wwid_str), "%" PRIx64,
		    d->pd_wwid);
		guid_ptr = wwid_str;
	}
	rval = mdi_pi_alloc_compatible(s->s_dip, nodename, guid_ptr,
	    d->pd_unit_address, compatible, ncompatible, 0, &pip);
	if (rval == MDI_SUCCESS) {
		mdi_pi_set_phci_private(pip, (caddr_t)d);

		if (mdi_prop_update_string(pip, MDI_GUID, guid_ptr) !=
		    DDI_SUCCESS) {
			dev_err(s->s_dip, CE_WARN,
			    "unable to create property (MDI_GUID) for %s",
			    guid_ptr);
			goto cleanup;
		}

		/*
		 * For MPxIO, we actually don't really need to care
		 * about the LUN or target property, because nothing
		 * really uses them.
		 */
		if (mdi_prop_update_int64(pip, LUN64_PROP, d->pd_lun) !=
		    DDI_SUCCESS) {
			dev_err(s->s_dip, CE_WARN,
			    "unable to create property (%s) for %s",
			    LUN64_PROP, guid_ptr);
			goto cleanup;
		}

		if (mdi_prop_update_string_array(pip, COMPAT_PROP,
		    compatible, ncompatible) != DDI_SUCCESS) {
			dev_err(s->s_dip, CE_WARN,
			    "unable to create property (%s) for %s",
			    COMPAT_PROP, guid_ptr);
			goto cleanup;
		}

		if (mdi_pi_online(pip, 0) == MDI_NOT_SUPPORTED)
			goto cleanup;

		d->pd_dip = NULL;
		d->pd_pip = pip;
	}

	scsi_hba_nodename_compatible_free(nodename, compatible);
	if (childp != NULL)
		*childp = mdi_pi_get_client(pip);
	return (B_TRUE);
cleanup:
	scsi_hba_nodename_compatible_free(nodename, compatible);
	d->pd_pip = NULL;
	d->pd_dip = NULL;
	(void) mdi_prop_remove(pip, NULL);
	(void) mdi_pi_free(pip, 0);
	return (B_FALSE);
}

static int
config_one(dev_info_t *pdip, pqi_state_t *s, pqi_device_t *d,
    dev_info_t **childp)
{
	struct scsi_inquiry	inq;
	boolean_t		rval = B_FALSE;

	/* ---- Inquiry target ---- */
	if (!d->pd_online ||
	    pqi_scsi_inquiry(s, d, 0, &inq, sizeof (inq)) == B_FALSE) {
		pqi_fail_drive_cmds(d, CMD_DEV_GONE);

		if (d->pd_dip != NULL) {
			(void) ndi_devi_offline(d->pd_dip,
			    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE);
			d->pd_dip = NULL;
		} else if (d->pd_pip != NULL) {
			(void) mdi_pi_offline(d->pd_pip, 0);
			d->pd_pip_offlined = d->pd_pip;
			d->pd_pip = NULL;
		}
		return (NDI_FAILURE);
	} else if (d->pd_dip != NULL) {
		if (childp != NULL)
			*childp = d->pd_dip;
		return (NDI_SUCCESS);
	} else if (d->pd_pip != NULL) {
		if (childp != NULL)
			*childp = mdi_pi_get_client(d->pd_pip);
		return (NDI_SUCCESS);
	}

	d->pd_parent = pdip;
	if ((!s->s_disable_mpxio) && is_physical_dev(d))
		rval = create_virt_lun(s, d, &inq, childp);

	if (rval == B_FALSE)
		rval = create_phys_lun(s, d, &inq, childp);

	return ((rval == B_TRUE) ? NDI_SUCCESS : NDI_FAILURE);
}

static void
cmd_ext_free(pqi_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	if ((cmd->pc_flags & PQI_FLAG_CDB_EXT) != 0) {
		kmem_free(pkt->pkt_cdbp, cmd->pc_cmdlen);
		cmd->pc_flags &= ~PQI_FLAG_CDB_EXT;
	}
	if ((cmd->pc_flags & PQI_FLAG_SCB_EXT) != 0) {
		kmem_free(pkt->pkt_scbp, cmd->pc_statuslen);
		cmd->pc_flags &= ~PQI_FLAG_SCB_EXT;
	}
	if ((cmd->pc_flags & PQI_FLAG_PRIV_EXT) != 0) {
		kmem_free(pkt->pkt_private, cmd->pc_tgtlen);
		cmd->pc_flags &= ~PQI_FLAG_PRIV_EXT;
	}
}

static int
cmd_ext_alloc(pqi_cmd_t *cmd, int kf)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);
	void			*buf;

	if (cmd->pc_cmdlen > sizeof (cmd->pc_cdb)) {
		if ((buf = kmem_zalloc(cmd->pc_cmdlen, kf)) == NULL)
			return (DDI_FAILURE);
		pkt->pkt_cdbp = buf;
		cmd->pc_flags |= PQI_FLAG_CDB_EXT;
	}

	if (cmd->pc_statuslen > sizeof (cmd->pc_cmd_scb)) {
		if ((buf = kmem_zalloc(cmd->pc_statuslen, kf)) == NULL)
			goto out;
		pkt->pkt_scbp = buf;
		cmd->pc_flags |= PQI_FLAG_SCB_EXT;
	}

	if (cmd->pc_tgtlen > sizeof (cmd->pc_tgt_priv)) {
		if ((buf = kmem_zalloc(cmd->pc_tgtlen, kf)) == NULL)
			goto out;
		pkt->pkt_private = buf;
		cmd->pc_flags |= PQI_FLAG_PRIV_EXT;
	}

	return (DDI_SUCCESS);

out:
	cmd_ext_free(cmd);

	return (DDI_FAILURE);
}

static boolean_t
is_physical_dev(pqi_device_t *d)
{
	return (d->pd_phys_dev ? B_TRUE : B_FALSE);
}
