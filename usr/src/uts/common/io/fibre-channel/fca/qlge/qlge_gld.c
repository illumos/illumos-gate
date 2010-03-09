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
 * Copyright 2009 QLogic Corporation. All rights reserved.
 */

#include <sys/note.h>
#include <qlge.h>
#include <sys/strsubr.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

/*
 * GLDv3 functions prototypes
 */
static int	ql_m_getstat(void *, uint_t, uint64_t *);
static int	ql_m_start(void *);
static void	ql_m_stop(void *);
static int	ql_m_setpromiscuous(void *, boolean_t);
static int	ql_m_multicst(void *, boolean_t, const uint8_t *);
static int	ql_m_unicst(void *, const uint8_t *);
static mblk_t	*ql_m_tx(void *, mblk_t *);
static void	ql_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t ql_m_getcapab(void *, mac_capab_t, void *);
static int	ql_unicst_set(qlge_t *qlge, const uint8_t *macaddr, int slot);

static int ql_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int ql_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void ql_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

#define	QL_M_CALLBACK_FLAGS (MC_IOCTL | MC_GETCAPAB | MC_SETPROP | \
    MC_GETPROP | MC_PROPINFO)
static mac_callbacks_t ql_m_callbacks = {
	QL_M_CALLBACK_FLAGS,
	ql_m_getstat,
	ql_m_start,
	ql_m_stop,
	ql_m_setpromiscuous,
	ql_m_multicst,
	NULL,
	NULL,
	NULL,
	ql_m_ioctl,
	ql_m_getcapab,
	NULL,
	NULL,
	ql_m_setprop,
	ql_m_getprop,
	ql_m_propinfo
};

char *qlge_priv_prop[] = {
	"_adv_pause_mode",
	NULL
};

/*
 * This function starts the driver
 */
static int
ql_m_start(void *arg)
{
	qlge_t *qlge = (qlge_t *)arg;

	/*
	 * reset chip, re-initialize everything but do not
	 * re-allocate memory
	 */
	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}
	mutex_enter(&qlge->hw_mutex);
	qlge->mac_flags = QL_MAC_INIT;
	/*
	 * Write default ethernet address to chip register Mac
	 * Address slot 0 and Enable Primary Mac Function.
	 */
	(void) ql_unicst_set(qlge,
	    (uint8_t *)qlge->unicst_addr[0].addr.ether_addr_octet, 0);
	qlge->stats.rpackets = 0;
	qlge->stats.rbytes = 0;
	qlge->stats.opackets = 0;
	qlge->stats.obytes = 0;
	mutex_exit(&qlge->hw_mutex);

	(void) ql_do_start(qlge);
	mutex_exit(&qlge->gen_mutex);

	mutex_enter(&qlge->mbx_mutex);
	(void) ql_get_firmware_version(qlge, NULL);
	mutex_exit(&qlge->mbx_mutex);

	return (0);
}

/*
 * This function stops the driver
 */
static void
ql_m_stop(void *arg)
{
	qlge_t *qlge = (qlge_t *)arg;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return;
	}
	(void) ql_do_stop(qlge);
	mutex_exit(&qlge->gen_mutex);
	qlge->mac_flags = QL_MAC_STOPPED;
}

/*
 * Add or remove a multicast address
 */
static int
ql_m_multicst(void *arg, boolean_t add, const uint8_t *ep)
{
	qlge_t *qlge = (qlge_t *)arg;
	int ret = DDI_SUCCESS;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}

	if (qlge->mac_flags == QL_MAC_DETACH) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}
	if (add) {
		QL_DUMP(DBG_GLD, "add to multicast list:\n",
		    (uint8_t *)ep, 8, ETHERADDRL);
		ret = ql_add_to_multicast_list(qlge, (uint8_t *)ep);
	} else {
		QL_DUMP(DBG_GLD, "remove from multicast list:\n",
		    (uint8_t *)ep, 8, ETHERADDRL);
		ret = ql_remove_from_multicast_list(qlge, (uint8_t *)ep);
	}
	mutex_exit(&qlge->gen_mutex);

	return ((ret == DDI_SUCCESS) ? 0 : EIO);
}

/*
 * Enable or disable promiscuous mode
 */
static int
ql_m_setpromiscuous(void* arg, boolean_t on)
{
	qlge_t *qlge = (qlge_t *)arg;
	int mode;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}

	/* enable reception of all packets on the medium, */
	if (on) {
		mode = 1;
		QL_PRINT(DBG_GLD, ("%s(%d) enable promiscuous mode\n",
		    __func__, qlge->instance));
	} else {
		mode = 0;
		QL_PRINT(DBG_GLD, ("%s(%d) disable promiscuous mode\n",
		    __func__, qlge->instance));
	}

	mutex_enter(&qlge->hw_mutex);
	ql_set_promiscuous(qlge, mode);
	mutex_exit(&qlge->hw_mutex);
	mutex_exit(&qlge->gen_mutex);
	return (DDI_SUCCESS);
}


static int
ql_m_getstat(void *arg, uint_t stat, uint64_t *valp)
{
	qlge_t *qlge = (qlge_t *)arg;
	struct ql_stats *cur_stats;
	uint64_t val = 0;
	int i;
	uint32_t val32;
	struct rx_ring *rx_ring;
	struct tx_ring *tx_ring;

	ASSERT(qlge != NULL);
	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}

	cur_stats = &qlge->stats;
	/* these stats are maintained in software */
	switch (stat) {

	case MAC_STAT_IFSPEED /* 1000 */ :
		if (CFG_IST(qlge, CFG_CHIP_8100) != 0) {
			qlge->speed = SPEED_10G;
		}
		val = qlge->speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		val = cur_stats->multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = cur_stats->brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		cur_stats->multixmt = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->multixmt += tx_ring->multixmt;
		}
		val = cur_stats->multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		cur_stats->brdcstxmt = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->brdcstxmt += tx_ring->brdcstxmt;
		}
		val = cur_stats->brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		val = cur_stats->norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		val = cur_stats->errrcv;
		break;

	case MAC_STAT_OBYTES:
		cur_stats->obytes = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->obytes += tx_ring->obytes;
		}
		val = cur_stats->obytes;
		break;

	case MAC_STAT_OPACKETS:
		cur_stats->opackets = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->opackets += tx_ring->opackets;
		}
		val = cur_stats->opackets;
		break;

	case ETHER_STAT_DEFER_XMTS:
		cur_stats->defer = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->defer += (tx_ring->defer);
		}
		val = cur_stats->defer;
		break;

	case MAC_STAT_OERRORS:
		cur_stats->errxmt = 0;
		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			cur_stats->errxmt += tx_ring->errxmt;
		}
		val = cur_stats->errxmt;
		break;

	case MAC_STAT_RBYTES:
		cur_stats->rbytes = 0;
		for (i = 0; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];
			cur_stats->rbytes += rx_ring->rx_bytes;
		}
		val = cur_stats->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		cur_stats->rpackets = 0;
		for (i = 0; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];
			cur_stats->rpackets += rx_ring->rx_packets;
		}
		val = cur_stats->rpackets;
		break;

	case ETHER_STAT_FCS_ERRORS:
		cur_stats->crc = 0;
		for (i = 0; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];
			cur_stats->crc += rx_ring->fcs_err;
		}
		val = cur_stats->crc;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		cur_stats->frame_too_long = 0;
		for (i = 0; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];
			cur_stats->frame_too_long +=
			    rx_ring->frame_too_long;
		}
		val = cur_stats->frame_too_long;
		break;

	case ETHER_STAT_XCVR_INUSE:
		val = XCVR_1000X;
		break;
	case ETHER_STAT_JABBER_ERRORS:
		if (ql_sem_spinlock(qlge, qlge->xgmac_sem_mask) !=
		    DDI_SUCCESS) {
			break;
		}
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_JABBER_PKTS,
		    &val32);
		val = val32;
		ql_sem_unlock(qlge, qlge->xgmac_sem_mask);
		QL_PRINT(DBG_STATS, ("%s(%d) MAC_STAT_JABBER_ERRORS "
		    "status %d\n", __func__, qlge->instance, val));
		break;
	case ETHER_STAT_LINK_DUPLEX:
		if (qlge->duplex == 1)
			val = LINK_DUPLEX_FULL;
		else
			val = LINK_DUPLEX_HALF;
		break;

	/* statics saved in hw */
	case ETHER_STAT_MACRCV_ERRORS:
		val = 0;
		if (ql_sem_spinlock(qlge, qlge->xgmac_sem_mask) !=
		    DDI_SUCCESS) {
			break;
		}
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_ALIGN_ERR,
		    &val32);
		val += val32;
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_FCS_ERR, &val32);
		val += val32;
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_JABBER_PKTS,
		    &val32);
		val += val32;
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_SYM_ERR,
		    &val32);
		val += val32;
		(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_INT_ERR,
		    &val32);
		val += val32;
		ql_sem_unlock(qlge, qlge->xgmac_sem_mask);
		break;

	default:
		mutex_exit(&qlge->gen_mutex);
		return (ENOTSUP);
	}
	*valp = val;
	mutex_exit(&qlge->gen_mutex);

	return (0);

}

/*
 * Set the physical network address
 */
static int
ql_unicst_set(qlge_t *qlge, const uint8_t *macaddr, int slot)
{
	int status;

	status = ql_sem_spinlock(qlge, SEM_MAC_ADDR_MASK);
	if (status != DDI_SUCCESS)
		return (EIO);
	status = ql_set_mac_addr_reg(qlge, (uint8_t *)macaddr,
	    MAC_ADDR_TYPE_CAM_MAC,
	    (uint16_t)(qlge->func_number * MAX_CQ + slot));
	ql_sem_unlock(qlge, SEM_MAC_ADDR_MASK);

	return ((status == DDI_SUCCESS) ? 0 : EIO);
}

/*
 * Set default MAC address
 * Each function has a total of 128 mac address, function0: 0~127,
 * function1 128~254 etc or func_number *128 + n (0~127), but
 * we only support one MAC address, so its address is
 * func_number*128+0
 */
static int
ql_m_unicst(void *arg, const uint8_t *mac)
{
	qlge_t *qlge = (qlge_t *)arg;
	int status;

	ASSERT(qlge->mac_flags != QL_MAC_DETACH);
	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}

	mutex_enter(&qlge->hw_mutex);
	bcopy(mac, qlge->unicst_addr[0].addr.ether_addr_octet, ETHERADDRL);
	/* Set Mac Address to slot 0 and Enable Primary Mac Function */
	status = ql_unicst_set(qlge, mac, 0);
	mutex_exit(&qlge->hw_mutex);
	mutex_exit(&qlge->gen_mutex);

	return (status);
}

/*
 * ql_m_tx is used only for sending data packets into ethernet wire.
 */
static mblk_t *
ql_m_tx(void *arg, mblk_t *mp)
{
	qlge_t *qlge = (qlge_t *)arg;
	struct tx_ring *tx_ring;
	mblk_t *next;
	int rval;
	uint32_t tx_count = 0;

	if (qlge->port_link_state == LS_DOWN) {
		cmn_err(CE_WARN, "%s(%d): exit due to link down",
		    __func__, qlge->instance);
		freemsgchain(mp);
		mp = NULL;
		goto tx_exit;
	}

	/*
	 * Always send this packet through tx ring 0 for now.
	 * Will use multiple tx rings when Crossbow is supported
	 */
	tx_ring = &qlge->tx_ring[0];
	mutex_enter(&tx_ring->tx_lock);
	if (tx_ring->mac_flags != QL_MAC_STARTED) {
		mutex_exit(&tx_ring->tx_lock);
		goto tx_exit;
	}

	/* we must try to send all */
	while (mp != NULL) {
		/*
		 * if number of available slots is less than a threshold,
		 * then quit
		 */
		if (tx_ring->tx_free_count <= TX_STOP_THRESHOLD) {
			tx_ring->queue_stopped = 1;
			rval = DDI_FAILURE;
			/*
			 * If we return the buffer back we are expected to
			 * call mac_tx_ring_update() when
			 * resources are available
			 */
			tx_ring->defer++;
			break;
		}
		next = mp->b_next;
		mp->b_next = NULL;

		rval = ql_send_common(tx_ring, mp);

		if (rval != DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		tx_count++;
		mp = next;
	}
	/*
	 * After all msg blocks are mapped or copied to tx buffer,
	 * trigger the hardware to send the msg!
	 */
	if (tx_count > 0) {
		ql_write_doorbell_reg(tx_ring->qlge, tx_ring->prod_idx_db_reg,
		    tx_ring->prod_idx);
	}
	mutex_exit(&tx_ring->tx_lock);
tx_exit:
	return (mp);
}

static void
ql_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	qlge_t *qlge = (qlge_t *)arg;
	struct iocblk *iocp;
	boolean_t need_privilege = B_TRUE;
	int err, cmd;
	enum ioc_reply status;

	/*
	 * Validate the command before bothering with the mutex...
	 */
	iocp = (struct iocblk *)(void *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		miocnak(wq, mp, 0, EINVAL);
		return;
	}
	switch (cmd) {
		default:
			QL_PRINT(DBG_GLD, ("unknown ioctl cmd \n"));
			miocnak(wq, mp, 0, EINVAL);
			mutex_exit(&qlge->gen_mutex);
			return;
		case QLA_PCI_STATUS:
		case QLA_WRITE_REG:
		case QLA_READ_PCI_REG:
		case QLA_WRITE_PCI_REG:
		case QLA_GET_DBGLEAVEL:
		case QLA_SET_DBGLEAVEL:
		case QLA_READ_CONTRL_REGISTERS:
		case QLA_MANUAL_READ_FLASH:
		case QLA_MANUAL_WRITE_FLASH:
		case QLA_GET_BINARY_CORE_DUMP:
		case QLA_SUPPORTED_DUMP_TYPES:
		case QLA_TRIGGER_SYS_ERROR_EVENT:
		case QLA_READ_FLASH:
		case QLA_WRITE_FLASH:
		case QLA_READ_VPD:
		case QLA_GET_PROP:
		case QLA_SHOW_REGION:
		case QLA_LIST_ADAPTER_INFO:
		case QLA_READ_FW_IMAGE:
		case QLA_WRITE_FW_IMAGE_HEADERS:
		case QLA_CONTINUE_COPY_IN:
		case QLA_CONTINUE_COPY_OUT:
		case QLA_SOFT_RESET:
			break;
		case LB_GET_INFO_SIZE:
		case LB_GET_INFO:
		case LB_GET_MODE:
			need_privilege = B_FALSE;
		/* FALLTHRU */
		case LB_SET_MODE:
			break;
	}

	if (need_privilege) {
		/*
		 * Check for specific net_config privilege
		 */
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			mutex_exit(&qlge->gen_mutex);
			return;
		}
	}
	/*
	 * Implement ioctl
	 */
	switch (cmd) {
		case QLA_PCI_STATUS:
		case QLA_WRITE_REG:
		case QLA_READ_PCI_REG:
		case QLA_WRITE_PCI_REG:
		case QLA_GET_DBGLEAVEL:
		case QLA_SET_DBGLEAVEL:
		case QLA_READ_CONTRL_REGISTERS:
		case QLA_MANUAL_READ_FLASH:
		case QLA_MANUAL_WRITE_FLASH:
		case QLA_GET_BINARY_CORE_DUMP:
		case QLA_SUPPORTED_DUMP_TYPES:
		case QLA_TRIGGER_SYS_ERROR_EVENT:
		case QLA_READ_FLASH:
		case QLA_WRITE_FLASH:
		case QLA_READ_VPD:
		case QLA_GET_PROP:
		case QLA_SHOW_REGION:
		case QLA_LIST_ADAPTER_INFO:
		case QLA_READ_FW_IMAGE:
		case QLA_WRITE_FW_IMAGE_HEADERS:
		case QLA_CONTINUE_COPY_IN:
		case QLA_CONTINUE_COPY_OUT:
		case QLA_SOFT_RESET:
			status = ql_chip_ioctl(qlge, wq, mp);
			break;
		case LB_GET_INFO_SIZE:
		case LB_GET_INFO:
		case LB_GET_MODE:
		case LB_SET_MODE:
			status = ql_loop_ioctl(qlge, wq, mp, iocp);
			break;
		default:
			status = IOC_INVAL;
			break;
	}

	/*
	 * Decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(wq, mp, 0, 0);
		break;

	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = (uint8_t)(iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK);
		qreply(wq, mp);
		break;
	}
	mutex_exit(&qlge->gen_mutex);
}
/* ARGSUSED */
static int
qlge_set_priv_prop(qlge_t *qlge, const char *pr_name, uint_t pr_valsize,
    const void *pr_val)
{
	int err = 0;
	long result;

	if (strcmp(pr_name, "_adv_pause_mode") == 0) {
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result > PAUSE_MODE_PER_PRIORITY ||
		    result < PAUSE_MODE_DISABLED) {
			err = EINVAL;
		} else if (qlge->pause != (uint32_t)result) {
			qlge->pause = (uint32_t)result;
			if (qlge->flags & INTERRUPTS_ENABLED) {
				mutex_enter(&qlge->mbx_mutex);
				if (ql_set_port_cfg(qlge) == DDI_FAILURE)
					err = EINVAL;
				mutex_exit(&qlge->mbx_mutex);
			}
		}
		return (err);
	}
	return (ENOTSUP);
}

/*
 * callback functions for set/get of properties
 */
/* ARGSUSED */
static int
ql_m_setprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	qlge_t *qlge = barg;
	int err = 0;
	uint32_t cur_mtu, new_mtu;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		mutex_exit(&qlge->gen_mutex);
		return (ECANCELED);
	}

	switch (pr_num) {
	case MAC_PROP_MTU:
		cur_mtu = qlge->mtu;
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));

		QL_PRINT(DBG_GLD, ("%s(%d) new mtu %d \n",
		    __func__, qlge->instance, new_mtu));
		if (new_mtu == cur_mtu) {
			err = 0;
			break;
		}
		if ((new_mtu != ETHERMTU) && (new_mtu != JUMBO_MTU)) {
			err = EINVAL;
			break;
		}
		/*
		 * do not change on the fly, allow only before
		 * driver is started or stopped
		 */
		if ((qlge->mac_flags == QL_MAC_STARTED) ||
		    (qlge->mac_flags == QL_MAC_DETACH)) {
			err = EBUSY;
			cmn_err(CE_WARN, "%s(%d) new mtu %d ignored, "
			    "driver busy, mac_flags %d", __func__,
			    qlge->instance, new_mtu, qlge->mac_flags);
			break;
		}
		qlge->mtu = new_mtu;
		err = mac_maxsdu_update(qlge->mh, qlge->mtu);
		if (err == 0) {
			/* EMPTY */
			QL_PRINT(DBG_GLD, ("%s(%d) new mtu %d set success\n",
			    __func__, qlge->instance,
			    new_mtu));
		}
		break;
	case MAC_PROP_PRIVATE:
		mutex_exit(&qlge->gen_mutex);
		err = qlge_set_priv_prop(qlge, pr_name, pr_valsize,
		    pr_val);
		mutex_enter(&qlge->gen_mutex);
		break;
	default:
		err = ENOTSUP;
		break;
	}
	mutex_exit(&qlge->gen_mutex);
	return (err);
}

static int
qlge_get_priv_prop(qlge_t *qlge, const char *pr_name, uint_t pr_valsize,
    void *pr_val)
{
	int err = ENOTSUP;
	uint32_t value;

	if (strcmp(pr_name, "_adv_pause_mode") == 0) {
		value = qlge->pause;
		err = 0;
		goto done;
	}

done:
	if (err == 0) {
		(void) snprintf(pr_val, pr_valsize, "%d", value);
	}
	return (err);
}

/* ARGSUSED */
static int
ql_m_getprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	qlge_t *qlge = barg;
	uint64_t speed;
	link_state_t link_state;
	link_duplex_t link_duplex;
	int err = 0;

	mutex_enter(&qlge->gen_mutex);
	if (qlge->mac_flags == QL_MAC_SUSPENDED) {
		err = ECANCELED;
		goto out;
	}

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		ASSERT(pr_valsize >= sizeof (link_duplex_t));
		if (qlge->duplex)
			link_duplex = LINK_DUPLEX_FULL;
		else
			link_duplex = LINK_DUPLEX_HALF;

		bcopy(&link_duplex, pr_val,
		    sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		ASSERT(pr_valsize >= sizeof (speed));
		speed = qlge->speed * 1000000ull;
		bcopy(&speed, pr_val, sizeof (speed));
		break;
	case MAC_PROP_STATUS:
		ASSERT(pr_valsize >= sizeof (link_state_t));
		if (qlge->port_link_state == LS_DOWN)
			link_state = LINK_STATE_DOWN;
		else
			link_state = LINK_STATE_UP;
		bcopy(&link_state, pr_val,
		    sizeof (link_state_t));
		break;

	case MAC_PROP_PRIVATE:
		err = qlge_get_priv_prop(qlge, pr_name, pr_valsize, pr_val);
		break;

	default:
		err = ENOTSUP;
	}
out:
	mutex_exit(&qlge->gen_mutex);
	return (err);
}

static void
ql_m_propinfo(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
        _NOTE(ARGUNUSED(barg));

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_PRIVATE: {
		char val_str[64];
		int default_val;

		if (strcmp(pr_name, "_adv_pause_mode") == 0)
			default_val = 2;
		else
			return;

		(void) snprintf(val_str, sizeof (val_str), "%d", default_val);
		mac_prop_info_set_default_str(prh, val_str);
		break;
	}
	}
}

/* ARGSUSED */
static boolean_t
ql_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	int ret = B_FALSE;
	uint32_t cksum = 0;
	qlge_t *qlge = (qlge_t *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		if ((qlge->cfg_flags & CFG_CKSUM_FULL_IPv4) != 0) {
			cksum |= HCKSUM_INET_FULL_V4;
		}
		if ((qlge->cfg_flags & CFG_CKSUM_FULL_IPv6) != 0) {
			cksum |= HCKSUM_INET_FULL_V6;
		}
		if ((qlge->cfg_flags & CFG_CKSUM_HEADER_IPv4) != 0) {
			cksum |= HCKSUM_IPHDRCKSUM;
		}
		if ((qlge->cfg_flags & CFG_CKSUM_PARTIAL) != 0) {
			cksum |= HCKSUM_INET_PARTIAL;
		}
		qlge->chksum_cap = cksum;
		*(uint32_t *)cap_data = cksum;
		ret = B_TRUE;
		break;

	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = (mac_capab_lso_t *)cap_data;
		uint32_t page_size;

		if ((qlge->cfg_flags & CFG_LSO)&&
		    (qlge->cfg_flags & CFG_SUPPORT_SCATTER_GATHER)) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			page_size = ddi_ptob(qlge->dip, (ulong_t)1);
			cap_lso->lso_basic_tcp_ipv4.lso_max = page_size *
			    (QL_MAX_TX_DMA_HANDLES-1);
			ret = B_TRUE;
		}
		break;
	}

	default:
		return (B_FALSE);
	}
	return (ret);
}

void
ql_gld3_init(qlge_t *qlge, mac_register_t *macp)
{
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = qlge;
	macp->m_dip = qlge->dip;
	/* This is the mac address from flash to be used by the port */
	macp->m_src_addr = qlge->dev_addr.ether_addr_octet;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = qlge->mtu;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = qlge_priv_prop;
	macp->m_v12n = 0;
	ql_m_callbacks.mc_unicst = ql_m_unicst;
	ql_m_callbacks.mc_tx = ql_m_tx;
	macp->m_callbacks = &ql_m_callbacks;
}
