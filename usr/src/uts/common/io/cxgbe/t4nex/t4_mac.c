/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/strsubr.h>
#include <sys/queue.h>

#include "common/common.h"
#include "common/t4_regs.h"

static int t4_mc_getstat(void *arg, uint_t stat, uint64_t *val);
static int t4_mc_start(void *arg);
static void t4_mc_stop(void *arg);
static int t4_mc_setpromisc(void *arg, boolean_t on);
static int t4_mc_multicst(void *arg, boolean_t add, const uint8_t *mcaddr);
static int t4_mc_unicst(void *arg, const uint8_t *ucaddr);
static boolean_t t4_mc_getcapab(void *arg, mac_capab_t cap, void *data);
static int t4_mc_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, const void *val);
static int t4_mc_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, void *val);
static void t4_mc_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t ph);

static int begin_synchronized_op(struct port_info *pi, int hold, int waitok);
static void end_synchronized_op(struct port_info *pi, int held);
static int t4_init_synchronized(struct port_info *pi);
static int t4_uninit_synchronized(struct port_info *pi);
static void propinfo(struct port_info *pi, const char *name,
    mac_prop_info_handle_t ph);
static int getprop(struct port_info *pi, const char *name, uint_t size,
    void *val);
static int setprop(struct port_info *pi, const char *name, const void *val);

mac_callbacks_t t4_m_callbacks = {
	.mc_callbacks	= MC_GETCAPAB | MC_PROPERTIES,
	.mc_getstat	= t4_mc_getstat,
	.mc_start	= t4_mc_start,
	.mc_stop	= t4_mc_stop,
	.mc_setpromisc	= t4_mc_setpromisc,
	.mc_multicst	= t4_mc_multicst,
	.mc_unicst =    t4_mc_unicst,
	.mc_tx =        t4_mc_tx,
	.mc_getcapab =	t4_mc_getcapab,
	.mc_setprop =	t4_mc_setprop,
	.mc_getprop =	t4_mc_getprop,
	.mc_propinfo =	t4_mc_propinfo,
};

/* I couldn't comeup with a better idea of not redefine
 * another strcture and instead somehow reuse the earlier
 * above structure and modify its members.
 */
mac_callbacks_t t4_m_ring_callbacks = {
	.mc_callbacks =	MC_GETCAPAB | MC_PROPERTIES,
	.mc_getstat =	t4_mc_getstat,
	.mc_start =	t4_mc_start,
	.mc_stop =	t4_mc_stop,
	.mc_setpromisc =t4_mc_setpromisc,
	.mc_multicst =	t4_mc_multicst,
	.mc_unicst =    NULL, /* t4_addmac */
	.mc_tx =        NULL, /* t4_eth_tx */
	.mc_getcapab	= t4_mc_getcapab,
	.mc_setprop	= t4_mc_setprop,
	.mc_getprop	= t4_mc_getprop,
	.mc_propinfo	= t4_mc_propinfo,
};

#define	T4PROP_TMR_IDX "_holdoff_timer_idx"
#define	T4PROP_PKTC_IDX "_holdoff_pktc_idx"
#define	T4PROP_MTU "_mtu"
#define	T4PROP_HW_CSUM	"_hw_csum"
#define	T4PROP_HW_LSO	"_hw_lso"
#define	T4PROP_TX_PAUSE	"_tx_pause"
#define	T4PROP_RX_PAUSE	"_rx_pause"

char *t4_priv_props[] = {
	T4PROP_TMR_IDX,
	T4PROP_PKTC_IDX,
#if MAC_VERSION == 1
	/* MAC_VERSION 1 doesn't seem to use MAC_PROP_MTU, hmmmm */
	T4PROP_MTU,
#endif
	T4PROP_HW_CSUM,
	T4PROP_HW_LSO,
	T4PROP_TX_PAUSE,
	T4PROP_RX_PAUSE,
	NULL
};

static int
t4_mc_getstat(void *arg, uint_t stat, uint64_t *val)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct link_config *lc = &pi->link_cfg;

#define	GET_STAT(name) \
	t4_read_reg64(sc, PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_##name##_L))

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (lc->link_ok != 0) {
			*val = lc->speed;
			*val *= 1000000;
		} else
			*val = 0;
		break;

	case MAC_STAT_MULTIRCV:
		*val = GET_STAT(RX_PORT_MCAST);
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = GET_STAT(RX_PORT_BCAST);
		break;

	case MAC_STAT_MULTIXMT:
		*val = GET_STAT(TX_PORT_MCAST);
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = GET_STAT(TX_PORT_BCAST);
		break;

	case MAC_STAT_NORCVBUF:
		*val = 0;	/* TODO should come from rxq->nomem */
		break;

	case MAC_STAT_IERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR) +
		    GET_STAT(RX_PORT_MTU_CRC_ERROR) +
		    GET_STAT(RX_PORT_CRC_ERROR) +
		    GET_STAT(RX_PORT_LEN_ERROR) +
		    GET_STAT(RX_PORT_SYM_ERROR) +
		    GET_STAT(RX_PORT_LESS_64B);
		break;

	case MAC_STAT_UNKNOWNS:
		return (ENOTSUP);

	case MAC_STAT_NOXMTBUF:
		*val = GET_STAT(TX_PORT_DROP);
		break;

	case MAC_STAT_OERRORS:
		*val = GET_STAT(TX_PORT_ERROR);
		break;

	case MAC_STAT_COLLISIONS:
		return (ENOTSUP);

	case MAC_STAT_RBYTES:
		*val = GET_STAT(RX_PORT_BYTES);
		break;

	case MAC_STAT_IPACKETS:
		*val = GET_STAT(RX_PORT_FRAMES);
		break;

	case MAC_STAT_OBYTES:
		*val = GET_STAT(TX_PORT_BYTES);
		break;

	case MAC_STAT_OPACKETS:
		*val = GET_STAT(TX_PORT_FRAMES);
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		return (ENOTSUP);

	case ETHER_STAT_FCS_ERRORS:
		*val = GET_STAT(RX_PORT_CRC_ERROR);
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
	case ETHER_STAT_MULTI_COLLISIONS:
	case ETHER_STAT_SQE_ERRORS:
	case ETHER_STAT_DEFER_XMTS:
	case ETHER_STAT_TX_LATE_COLLISIONS:
	case ETHER_STAT_EX_COLLISIONS:
		return (ENOTSUP);

	case ETHER_STAT_MACXMT_ERRORS:
		*val = GET_STAT(TX_PORT_ERROR);
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		return (ENOTSUP);

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR);
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR) +
		    GET_STAT(RX_PORT_MTU_CRC_ERROR) +
		    GET_STAT(RX_PORT_CRC_ERROR) +
		    GET_STAT(RX_PORT_LEN_ERROR) +
		    GET_STAT(RX_PORT_SYM_ERROR) +
		    GET_STAT(RX_PORT_LESS_64B);
		break;

	case ETHER_STAT_XCVR_ADDR:
	case ETHER_STAT_XCVR_ID:
	case ETHER_STAT_XCVR_INUSE:
		return (ENOTSUP);

	case ETHER_STAT_CAP_100GFDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_100G);
		break;

	case ETHER_STAT_CAP_40GFDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_40G);
		break;

	case ETHER_STAT_CAP_25GFDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_25G);
		break;

	case ETHER_STAT_CAP_10GFDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_10G);
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_1G);
		break;

	case ETHER_STAT_CAP_1000HDX:
		return (ENOTSUP);

	case ETHER_STAT_CAP_100FDX:
		*val = !!(lc->supported & FW_PORT_CAP_SPEED_100M);
		break;

	case ETHER_STAT_CAP_100HDX:
		return (ENOTSUP);

	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
		return (ENOTSUP);

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = 0;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = 1;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = !!(lc->supported & FW_PORT_CAP_ANEG);
		break;

	/*
	 * We have set flow control configuration based on tx_pause and rx_pause
	 * values supported through ndd. Now, we need to translate the settings
	 * we have in link_config structure to adv_cap_asmpause and
	 * adv_cap_pause.
	 *
	 * There are 4 combinations possible and the translation is as below:
	 * tx_pause = 0 => We don't send pause frames during Rx congestion
	 * tx_pause = 1 => We send pause frames during Rx congestion
	 * rx_pause = 0 => We ignore received pause frames
	 * rx_pause = 1 => We pause transmission when we receive pause frames
	 *
	 * +----------------------------+----------------------------------+
	 * |  tx_pause	|    rx_pause	| adv_cap_asmpause | adv_cap_pause |
	 * +-------------------------+-------------------------------------+
	 * |	0	|	0	|	0	   |	0	   |
	 * |	0	|	1	|	1	   |	0	   |
	 * |	1	|	0	|	1	   |	1	   |
	 * |	1	|	1	|	0	   |	1	   |
	 * +----------------------------+----------------------------------+
	 */

	/* Advertised asymmetric pause capability */
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = (((lc->requested_fc & PAUSE_TX) ? 1 : 0) ^
		    (lc->requested_fc & PAUSE_RX));
		break;

	/* Advertised pause capability */
	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = (lc->requested_fc & PAUSE_TX) ? 1 : 0;
		break;

	case ETHER_STAT_ADV_CAP_100GFDX:
		*val = !!(lc->advertising & FW_PORT_CAP_SPEED_100G);
		break;

	case ETHER_STAT_ADV_CAP_40GFDX:
		*val = !!(lc->advertising & FW_PORT_CAP_SPEED_40G);
		break;

	case ETHER_STAT_ADV_CAP_25GFDX:
		*val = !!(lc->advertising & FW_PORT_CAP_SPEED_25G);
		break;

	case ETHER_STAT_ADV_CAP_10GFDX:
		*val = !!(lc->advertising & FW_PORT_CAP_SPEED_10G);
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = !!(lc->advertising & FW_PORT_CAP_SPEED_1G);
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = !!(lc->advertising & FW_PORT_CAP_ANEG);
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_100FDX:
	case ETHER_STAT_ADV_CAP_100HDX:
	case ETHER_STAT_ADV_CAP_10FDX:
	case ETHER_STAT_ADV_CAP_10HDX:
		return (ENOTSUP);	/* TODO */


	case ETHER_STAT_LP_CAP_100GFDX:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_SPEED_100G);
		break;

	case ETHER_STAT_LP_CAP_40GFDX:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_SPEED_40G);
		break;

	case ETHER_STAT_LP_CAP_25GFDX:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_SPEED_25G);
		break;

	case ETHER_STAT_LP_CAP_10GFDX:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_SPEED_10G);
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_SPEED_1G);
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = !!(lc->lp_advertising & FW_PORT_CAP_ANEG);
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
	case ETHER_STAT_LP_CAP_100FDX:
	case ETHER_STAT_LP_CAP_100HDX:
	case ETHER_STAT_LP_CAP_10FDX:
	case ETHER_STAT_LP_CAP_10HDX:
	case ETHER_STAT_LP_CAP_ASMPAUSE:
	case ETHER_STAT_LP_CAP_PAUSE:
		return (ENOTSUP);

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = 0;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = 1;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = lc->autoneg == AUTONEG_ENABLE;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		if (lc->link_ok != 0)
			*val = LINK_DUPLEX_FULL;
		else
			*val = LINK_DUPLEX_UNKNOWN;
		break;

	default:
#ifdef DEBUG
		cxgb_printf(pi->dip, CE_NOTE, "stat %d not implemented.", stat);
#endif
		return (ENOTSUP);
	}
#undef GET_STAT

	return (0);
}

static int
t4_mc_start(void *arg)
{
	struct port_info *pi = arg;
	int rc;

	rc = begin_synchronized_op(pi, 0, 1);
	if (rc != 0)
		return (rc);
	rc = t4_init_synchronized(pi);
	end_synchronized_op(pi, 0);

	return (rc);
}

static void
t4_mc_stop(void *arg)
{
	struct port_info *pi = arg;

	while (begin_synchronized_op(pi, 0, 1) != 0)
		continue;
	(void) t4_uninit_synchronized(pi);
	end_synchronized_op(pi, 0);
}

static int
t4_mc_setpromisc(void *arg, boolean_t on)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);
	rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, -1, on ? 1 : 0, -1, -1, -1,
	    false);
	end_synchronized_op(pi, 1);

	return (rc);
}

/*
 * TODO: Starts failing as soon as the 336 entry table fills up.  Need to use
 * hash in that case.
 */
static int
t4_mc_multicst(void *arg, boolean_t add, const uint8_t *mcaddr)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct fw_vi_mac_cmd c;
	int len16, rc;

	len16 = howmany(sizeof (c.op_to_viid) + sizeof (c.freemacs_to_len16) +
	    sizeof (c.u.exact[0]), 16);
	c.op_to_viid = htonl(V_FW_CMD_OP(FW_VI_MAC_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | V_FW_VI_MAC_CMD_VIID(pi->viid));
	c.freemacs_to_len16 = htonl(V_FW_CMD_LEN16(len16));
	c.u.exact[0].valid_to_idx = htons(F_FW_VI_MAC_CMD_VALID |
	    V_FW_VI_MAC_CMD_IDX(add ? FW_VI_MAC_ADD_MAC :
	    FW_VI_MAC_MAC_BASED_FREE));
	bcopy(mcaddr, &c.u.exact[0].macaddr, ETHERADDRL);

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);
	rc = -t4_wr_mbox_meat(sc, sc->mbox, &c, len16 * 16, &c, true);
	end_synchronized_op(pi, 1);
	if (rc != 0)
		return (rc);
#ifdef DEBUG
	/*
	 * TODO: Firmware doesn't seem to return the correct index on removal
	 * (it gives back 0x3fd FW_VI_MAC_MAC_BASED_FREE unchanged. Remove this
	 * code once it is fixed.
	 */
	else {
		uint16_t idx;

		idx = G_FW_VI_MAC_CMD_IDX(ntohs(c.u.exact[0].valid_to_idx));
		cxgb_printf(pi->dip, CE_NOTE,
		    "%02x:%02x:%02x:%02x:%02x:%02x %s %d", mcaddr[0],
		    mcaddr[1], mcaddr[2], mcaddr[3], mcaddr[4], mcaddr[5],
		    add ? "added at index" : "removed from index", idx);
	}
#endif

	return (0);
}

int
t4_mc_unicst(void *arg, const uint8_t *ucaddr)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;

	if (ucaddr == NULL)
		return (EINVAL);

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);

	/* We will support adding only one mac address */
	if (pi->adapter->props.multi_rings && pi->macaddr_cnt) {
		end_synchronized_op(pi, 1);
		return (ENOSPC);
	}
	rc = t4_change_mac(sc, sc->mbox, pi->viid, pi->xact_addr_filt, ucaddr,
			   true, true);
	if (rc < 0)
		rc = -rc;
	else {
		pi->macaddr_cnt++;
		pi->xact_addr_filt = rc;
		rc = 0;
	}
	end_synchronized_op(pi, 1);

	return (rc);
}

int
t4_addmac(void *arg, const uint8_t *ucaddr)
{
	return (t4_mc_unicst(arg, ucaddr));
}

static int
t4_remmac(void *arg, const uint8_t *mac_addr)
{
	struct port_info *pi = arg;
	int rc;

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);

	pi->macaddr_cnt--;
	end_synchronized_op(pi, 1);

	return (0);
}

/*
 * Callback funtion for MAC layer to register all groups.
 */
void
t4_fill_group(void *arg, mac_ring_type_t rtype, const int rg_index,
	      mac_group_info_t *infop, mac_group_handle_t gh)
{
	struct port_info *pi = arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		infop->mgi_driver = (mac_group_driver_t)arg;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = t4_addmac;
		infop->mgi_remmac = t4_remmac;
		infop->mgi_count = pi->nrxq;
		break;
	}
	case MAC_RING_TYPE_TX:
	default:
		ASSERT(0);
		break;
	}
}

static int
t4_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	struct sge_rxq *rxq = (struct sge_rxq *)rh;

	RXQ_LOCK(rxq);
	rxq->ring_gen_num = mr_gen_num;
	RXQ_UNLOCK(rxq);
	return (0);
}

/*
 * Enable interrupt on the specificed rx ring.
 */
int
t4_ring_intr_enable(mac_intr_handle_t intrh)
{
	struct sge_rxq *rxq = (struct sge_rxq *)intrh;
	struct adapter *sc = rxq->port->adapter;
	struct sge_iq *iq;

	iq = &rxq->iq;
	RXQ_LOCK(rxq);
	iq->polling = 0;
	iq->state = IQS_IDLE;
	t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
		     V_SEINTARM(iq->intr_params) | V_INGRESSQID(iq->cntxt_id));
	RXQ_UNLOCK(rxq);
	return (0);
}

/*
 * Disable interrupt on the specificed rx ring.
 */
int
t4_ring_intr_disable(mac_intr_handle_t intrh)
{
	struct sge_rxq *rxq = (struct sge_rxq *)intrh;
	struct sge_iq *iq;

	/* Nothing to be done here wrt interrupt, as it
	 * will not fire, until we write back to
	 * A_SGE_PF_GTS.SEIntArm in t4_ring_intr_enable.
	 */

	iq = &rxq->iq;
	RXQ_LOCK(rxq);
	iq->polling = 1;
	iq->state = IQS_BUSY;
	RXQ_UNLOCK(rxq);
	return (0);
}

mblk_t *
t4_poll_ring(void *arg, int n_bytes)
{
	struct sge_rxq *rxq = (struct sge_rxq *)arg;
	mblk_t *mp = NULL;

	ASSERT(n_bytes >= 0);
	if (n_bytes == 0)
		return (NULL);

	RXQ_LOCK(rxq);
	mp = t4_ring_rx(rxq, n_bytes);
	RXQ_UNLOCK(rxq);

	return (mp);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
t4_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct sge_rxq *rxq = (struct sge_rxq *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rxq->rxbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rxq->rxpkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
t4_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct sge_txq *txq = (struct sge_txq *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = txq->txbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = txq->txpkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Callback funtion for MAC layer to register all rings
 * for given ring_group, noted by group_index.
 * Since we have only one group, ring index becomes
 * absolute index.
 */
void
t4_fill_ring(void *arg, mac_ring_type_t rtype, const int group_index,
	     const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	struct port_info *pi = arg;
	mac_intr_t *mintr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		struct sge_rxq *rxq;

		rxq = &pi->adapter->sge.rxq[pi->first_rxq + ring_index];
		rxq->ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)rxq;
		infop->mri_start = t4_ring_start;
		infop->mri_stop = NULL;
		infop->mri_poll = t4_poll_ring;
		infop->mri_stat = t4_rx_stat;

		mintr = &infop->mri_intr;
		mintr->mi_handle = (mac_intr_handle_t)rxq;
		mintr->mi_enable = t4_ring_intr_enable;
		mintr->mi_disable = t4_ring_intr_disable;

		break;
	}
	case MAC_RING_TYPE_TX: {
		struct sge_txq *txq = &pi->adapter->sge.txq[pi->first_txq + ring_index];
		txq->ring_handle = rh;
		infop->mri_driver = (mac_ring_driver_t)txq;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = t4_eth_tx;
		infop->mri_stat = t4_tx_stat;
		break;
	}
	default:
		ASSERT(0);
		break;
	}
}

mblk_t *
t4_mc_tx(void *arg, mblk_t *m)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct sge_txq *txq = &sc->sge.txq[pi->first_txq];

	return (t4_eth_tx(txq, m));
}

static int
t4_mc_transceiver_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
	struct port_info *pi = arg;

	if (id != 0 || infop == NULL)
		return (EINVAL);

	switch (pi->mod_type) {
	case FW_PORT_MOD_TYPE_NONE:
		mac_transceiver_info_set_present(infop, B_FALSE);
		break;
	case FW_PORT_MOD_TYPE_NOTSUPPORTED:
		mac_transceiver_info_set_present(infop, B_TRUE);
		mac_transceiver_info_set_usable(infop, B_FALSE);
		break;
	default:
		mac_transceiver_info_set_present(infop, B_TRUE);
		mac_transceiver_info_set_usable(infop, B_TRUE);
		break;
	}

	return (0);
}

static int
t4_mc_transceiver_read(void *arg, uint_t id, uint_t page, void *bp,
    size_t nbytes, off_t offset, size_t *nread)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;
	size_t i, maxread;
	/* LINTED: E_FUNC_VAR_UNUSED */
	struct fw_ldst_cmd ldst __unused;

	if (id != 0 || bp == NULL || nbytes == 0 || nread == NULL ||
	    (page != 0xa0 && page != 0xa2) || offset < 0)
		return (EINVAL);

	if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256))
		return (EINVAL);

	rc = begin_synchronized_op(pi, 0, 1);
	if (rc != 0)
		return (rc);

	/*
	 * Firmware has a maximum size that we can read. Don't read more than it
	 * allows.
	 */
	maxread = sizeof (ldst.u.i2c.data);
	for (i = 0; i < nbytes; i += maxread) {
		size_t toread = MIN(maxread, nbytes - i);
		rc = -t4_i2c_rd(sc, sc->mbox, pi->port_id, page, offset, toread,
		    bp);
		if (rc != 0)
			break;
		offset += toread;
		bp = (void *)((uintptr_t)bp + toread);
	}
	end_synchronized_op(pi, 0);
	if (rc == 0)
		*nread = nbytes;
	return (rc);
}

static boolean_t
t4_mc_getcapab(void *arg, mac_capab_t cap, void *data)
{
	struct port_info *pi = arg;
	boolean_t status = B_TRUE;
	mac_capab_transceiver_t *mct;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		if (pi->features & CXGBE_HW_CSUM) {
			uint32_t *d = data;
			*d = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
		} else
			status = B_FALSE;
		break;

	case MAC_CAPAB_LSO:
		/* Enabling LSO requires Checksum offloading */
		if (pi->features & CXGBE_HW_LSO &&
		    pi->features & CXGBE_HW_CSUM) {
			mac_capab_lso_t *d = data;

			d->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			d->lso_basic_tcp_ipv4.lso_max = 65535;
		} else
			status = B_FALSE;
		break;

	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = data;

		if (!pi->adapter->props.multi_rings) {
			status = B_FALSE;
			break;
		}
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = pi->nrxq;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = t4_fill_ring;
			cap_rings->mr_gget = t4_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = pi->ntxq;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = t4_fill_ring;
			cap_rings->mr_gget = NULL;
			break;
		}
		break;
	}

	case MAC_CAPAB_TRANSCEIVER:
		mct = data;

		mct->mct_flags = 0;
		mct->mct_ntransceivers = 1;
		mct->mct_info = t4_mc_transceiver_info;
		mct->mct_read = t4_mc_transceiver_read;
		break;

	default:
		status = B_FALSE; /* cap not supported */
	}

	return (status);
}

/* ARGSUSED */
static int
t4_mc_setprop(void *arg, const char *name, mac_prop_id_t id, uint_t size,
    const void *val)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct link_config lc_copy, *lc = &pi->link_cfg;
	uint8_t v8 = *(uint8_t *)val;
	uint32_t v32 = *(uint32_t *)val;
	int old, new = 0, relink = 0, rx_mode = 0, rc = 0;
	link_flowctrl_t fc;

	/*
	 * Save a copy of link_config. This can be used to restore link_config
	 * if t4_link_l1cfg() fails.
	 */
	bcopy(lc, &lc_copy, sizeof (struct link_config));

	switch (id) {
	case MAC_PROP_AUTONEG:
		if (lc->supported & FW_PORT_CAP_ANEG) {
			old = lc->autoneg;
			new = v8 ? AUTONEG_ENABLE : AUTONEG_DISABLE;
			if (old != new) {
				/* LINTED: E_CONSTANT_CONDITION */
				lc->autoneg = new;
				relink = 1;
				if (new == AUTONEG_DISABLE) {
					/* Only 100M is available */
					lc->requested_speed =
					    FW_PORT_CAP_SPEED_100M;
					lc->advertising =
					    FW_PORT_CAP_SPEED_100M;
				} else {
					/*
					 * Advertise autonegotiation capability
					 * along with supported speeds
					 */
					lc->advertising |= (FW_PORT_CAP_ANEG |
					    (lc->supported &
					    (FW_PORT_CAP_SPEED_100M |
					    FW_PORT_CAP_SPEED_1G)));
					lc->requested_speed = 0;
				}
			}
		} else
			rc = ENOTSUP;
		break;

	case MAC_PROP_MTU:
		if (v32 < 46 || v32 > MAX_MTU) {
			rc = EINVAL;
		} else if (v32 != pi->mtu) {
			pi->mtu = v32;
			(void) mac_maxsdu_update(pi->mh, v32);
			rx_mode = 1;
		}

		break;

	case MAC_PROP_FLOWCTRL:
		fc = *(link_flowctrl_t *)val;
		old = lc->requested_fc & (PAUSE_TX | PAUSE_RX);

		if (fc == LINK_FLOWCTRL_BI)
			new = (PAUSE_TX | PAUSE_RX);
		else if (fc == LINK_FLOWCTRL_TX)
			new = PAUSE_TX;
		else if (fc == LINK_FLOWCTRL_RX)
			new = PAUSE_RX;

		if (new != old) {
			lc->requested_fc &= ~(PAUSE_TX | PAUSE_RX);
			lc->requested_fc |= new;
			relink = 1;
		}
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		if (lc->supported & FW_PORT_CAP_ANEG && is_10G_port(pi)) {
			old = lc->advertising & FW_PORT_CAP_SPEED_10G;
			new = v8 ? FW_PORT_CAP_SPEED_10G : 0;
			if (new != old) {
				lc->advertising &= ~FW_PORT_CAP_SPEED_10G;
				lc->advertising |= new;
				relink = 1;
			}
		} else
			rc = ENOTSUP;

		break;

	case MAC_PROP_EN_1000FDX_CAP:
		/* Forced 1G */
		if (lc->autoneg == AUTONEG_ENABLE) {
			old = lc->advertising & FW_PORT_CAP_SPEED_1G;
			new = v8 ? FW_PORT_CAP_SPEED_1G : 0;

			if (old != new) {
				lc->advertising &= ~FW_PORT_CAP_SPEED_1G;
				lc->advertising |= new;
				relink = 1;
			}
		} else
			rc = ENOTSUP;
		break;

	case MAC_PROP_EN_100FDX_CAP:
		/* Forced 100M */
		if (lc->autoneg == AUTONEG_ENABLE) {
			old = lc->advertising & FW_PORT_CAP_SPEED_100M;
			new = v8 ? FW_PORT_CAP_SPEED_100M : 0;
			if (old != new) {
				lc->advertising &= ~FW_PORT_CAP_SPEED_100M;
				lc->advertising |= new;
				relink = 1;
			}
		} else
			rc = ENOTSUP;
		break;

	case MAC_PROP_PRIVATE:
		rc = setprop(pi, name, val);
		break;

	default:
		rc = ENOTSUP;
	}

	if (isset(&sc->open_device_map, pi->port_id) != 0) {
		if (relink != 0) {
			t4_os_link_changed(pi->adapter, pi->port_id, 0);
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan,
			    &pi->link_cfg);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "start_link failed:%d", rc);

				/* Restore link_config */
				bcopy(&lc_copy, lc,
				    sizeof (struct link_config));
			}
		}

		if (rx_mode != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, v32, -1,
			    -1, -1, -1, false);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "set_rxmode failed: %d", rc);
			}
		}
	}

	return (rc);
}

static int
t4_mc_getprop(void *arg, const char *name, mac_prop_id_t id, uint_t size,
    void *val)
{
	struct port_info *pi = arg;
	struct link_config *lc = &pi->link_cfg;
	uint8_t *u = val;

	switch (id) {
	case MAC_PROP_DUPLEX:
		*(link_duplex_t *)val = lc->link_ok ? LINK_DUPLEX_FULL :
		    LINK_DUPLEX_UNKNOWN;
		break;

	case MAC_PROP_SPEED:
		if (lc->link_ok != 0) {
			*(uint64_t *)val = lc->speed;
			*(uint64_t *)val *= 1000000;
		} else
			*(uint64_t *)val = 0;
		break;

	case MAC_PROP_STATUS:
		*(link_state_t *)val = lc->link_ok ? LINK_STATE_UP :
		    LINK_STATE_DOWN;
		break;

	case MAC_PROP_AUTONEG:
		*u = lc->autoneg == AUTONEG_ENABLE;
		break;

	case MAC_PROP_MTU:
		*(uint32_t *)val = pi->mtu;
		break;

	case MAC_PROP_FLOWCTRL:
		if ((lc->requested_fc & (PAUSE_TX | PAUSE_RX)) ==
		    (PAUSE_TX | PAUSE_RX))
			*(link_flowctrl_t *)val = LINK_FLOWCTRL_BI;
		else if (lc->requested_fc & PAUSE_TX)
			*(link_flowctrl_t *)val = LINK_FLOWCTRL_TX;
		else if (lc->requested_fc & PAUSE_RX)
			*(link_flowctrl_t *)val = LINK_FLOWCTRL_RX;
		else
			*(link_flowctrl_t *)val = LINK_FLOWCTRL_NONE;
		break;

	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_100G);
		break;

	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_40G);
		break;

	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_25G);
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_10G);
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_1G);
		break;

	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		*u = !!(lc->advertising & FW_PORT_CAP_SPEED_100M);
		break;

	case MAC_PROP_PRIVATE:
		return (getprop(pi, name, size, val));

	default:
		return (ENOTSUP);
	}

	return (0);
}

static void
t4_mc_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t ph)
{
	struct port_info *pi = arg;
	struct link_config *lc = &pi->link_cfg;

	switch (id) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		if (lc->supported & FW_PORT_CAP_ANEG)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(ph, 46, MAX_MTU);
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_default_link_flowctrl(ph, LINK_FLOWCTRL_BI);
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		if (lc->supported & FW_PORT_CAP_ANEG &&
		    lc->supported & FW_PORT_CAP_SPEED_10G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		if (lc->supported & FW_PORT_CAP_ANEG &&
		    lc->supported & FW_PORT_CAP_SPEED_1G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if (lc->supported & FW_PORT_CAP_ANEG &&
		    lc->supported & FW_PORT_CAP_SPEED_100M)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
		mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_PRIVATE:
		propinfo(pi, name, ph);
		break;

	default:
		break;
	}
}

static int
begin_synchronized_op(struct port_info *pi, int hold, int waitok)
{
	struct adapter *sc = pi->adapter;
	int rc = 0;

	ADAPTER_LOCK(sc);
	while (!IS_DOOMED(pi) && IS_BUSY(sc)) {
		if (!waitok) {
			rc = EBUSY;
			goto failed;
		} else if (cv_wait_sig(&sc->cv, &sc->lock) == 0) {
			rc = EINTR;
			goto failed;
		}
	}
	if (IS_DOOMED(pi) != 0) {	/* shouldn't happen on Solaris */
		rc = ENXIO;
		goto failed;
	}
	ASSERT(!IS_BUSY(sc));
	/* LINTED: E_CONSTANT_CONDITION */
	SET_BUSY(sc);

	if (!hold)
		ADAPTER_UNLOCK(sc);

	return (0);
failed:
	ADAPTER_UNLOCK(sc);
	return (rc);
}

static void
end_synchronized_op(struct port_info *pi, int held)
{
	struct adapter *sc = pi->adapter;

	if (!held)
		ADAPTER_LOCK(sc);

	ADAPTER_LOCK_ASSERT_OWNED(sc);
	ASSERT(IS_BUSY(sc));
	/* LINTED: E_CONSTANT_CONDITION */
	CLR_BUSY(sc);
	cv_signal(&sc->cv);
	ADAPTER_UNLOCK(sc);
}

static int
t4_init_synchronized(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int rc = 0;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	if (isset(&sc->open_device_map, pi->port_id) != 0)
		return (0);	/* already running */

	if (!(sc->flags & FULL_INIT_DONE) &&
	    ((rc = adapter_full_init(sc)) != 0))
		return (rc);	/* error message displayed already */

	if (!(pi->flags & PORT_INIT_DONE)) {
		rc = port_full_init(pi);
		if (rc != 0)
			return (rc); /* error message displayed already */
	} else
		enable_port_queues(pi);

	rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, pi->mtu, 0, 0, 1, 0, false);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "set_rxmode failed: %d", rc);
		goto done;
	}
	rc = t4_change_mac(sc, sc->mbox, pi->viid, pi->xact_addr_filt,
	    pi->hw_addr, true, true);
	if (rc < 0) {
		cxgb_printf(pi->dip, CE_WARN, "change_mac failed: %d", rc);
		rc = -rc;
		goto done;
	} else
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->xact_addr_filt = rc;

	rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, &pi->link_cfg);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "start_link failed: %d", rc);
		goto done;
	}

	rc = -t4_enable_vi(sc, sc->mbox, pi->viid, true, true);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "enable_vi failed: %d", rc);
		goto done;
	}

	/* all ok */
	setbit(&sc->open_device_map, pi->port_id);
done:
	if (rc != 0)
		(void) t4_uninit_synchronized(pi);

	return (rc);
}

/*
 * Idempotent.
 */
static int
t4_uninit_synchronized(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int rc;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	/*
	 * Disable the VI so that all its data in either direction is discarded
	 * by the MPS.  Leave everything else (the queues, interrupts, and 1Hz
	 * tick) intact as the TP can deliver negative advice or data that it's
	 * holding in its RAM (for an offloaded connection) even after the VI is
	 * disabled.
	 */
	rc = -t4_enable_vi(sc, sc->mbox, pi->viid, false, false);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "disable_vi failed: %d", rc);
		return (rc);
	}

	disable_port_queues(pi);

	clrbit(&sc->open_device_map, pi->port_id);

	pi->link_cfg.link_ok = 0;
	pi->link_cfg.speed = 0;
	mac_link_update(pi->mh, LINK_STATE_UNKNOWN);

	return (0);
}

static void
propinfo(struct port_info *pi, const char *name, mac_prop_info_handle_t ph)
{
	struct adapter *sc = pi->adapter;
	struct driver_properties *p = &sc->props;
	struct link_config *lc = &pi->link_cfg;
	int v;
	char str[16];

	if (strcmp(name, T4PROP_TMR_IDX) == 0)
		v = is_10G_port(pi) ? p->tmr_idx_10g : p->tmr_idx_1g;
	else if (strcmp(name, T4PROP_PKTC_IDX) == 0)
		v = is_10G_port(pi) ? p->pktc_idx_10g : p->pktc_idx_1g;
	else if (strcmp(name, T4PROP_HW_CSUM) == 0)
		v = (pi->features & CXGBE_HW_CSUM) ? 1 : 0;
	else if (strcmp(name, T4PROP_HW_LSO) == 0)
		v = (pi->features & CXGBE_HW_LSO) ? 1 : 0;
	else if (strcmp(name, T4PROP_TX_PAUSE) == 0)
		v = (lc->fc & PAUSE_TX) ? 1 : 0;
	else if (strcmp(name, T4PROP_RX_PAUSE) == 0)
		v = (lc->fc & PAUSE_RX) ? 1 : 0;
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0)
		v = ETHERMTU;
#endif
	else
		return;

	(void) snprintf(str, sizeof (str), "%d", v);
	mac_prop_info_set_default_str(ph, str);
}

static int
getprop(struct port_info *pi, const char *name, uint_t size, void *val)
{
	struct link_config *lc = &pi->link_cfg;
	int v;

	if (strcmp(name, T4PROP_TMR_IDX) == 0)
		v = pi->tmr_idx;
	else if (strcmp(name, T4PROP_PKTC_IDX) == 0)
		v = pi->pktc_idx;
	else if (strcmp(name, T4PROP_HW_CSUM) == 0)
		v = (pi->features & CXGBE_HW_CSUM) ? 1 : 0;
	else if (strcmp(name, T4PROP_HW_LSO) == 0)
		v = (pi->features & CXGBE_HW_LSO) ? 1 : 0;
	else if (strcmp(name, T4PROP_TX_PAUSE) == 0)
		v = (lc->fc & PAUSE_TX) ? 1 : 0;
	else if (strcmp(name, T4PROP_RX_PAUSE) == 0)
		v = (lc->fc & PAUSE_RX) ? 1 : 0;
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0)
		v = pi->mtu;
#endif
	else
		return (ENOTSUP);

	(void) snprintf(val, size, "%d", v);
	return (0);
}

static int
setprop(struct port_info *pi, const char *name, const void *val)
{
	struct adapter *sc = pi->adapter;
	long v;
	int i, rc = 0, relink = 0, rx_mode = 0;
	struct sge_rxq *rxq;
	struct link_config lc_old, *lc = &pi->link_cfg;

	/*
	 * Save a copy of link_config. This can be used to restore link_config
	 * if t4_link_l1cfg() fails.
	 */
	bcopy(lc, &lc_old, sizeof (struct link_config));

	(void) ddi_strtol(val, NULL, 0, &v);

	if (strcmp(name, T4PROP_TMR_IDX) == 0) {
		if (v < 0 || v >= SGE_NTIMERS)
			return (EINVAL);
		if (v == pi->tmr_idx)
			return (0);

		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->tmr_idx = v;
		for_each_rxq(pi, i, rxq) {
			rxq->iq.intr_params = V_QINTR_TIMER_IDX(v) |
			    V_QINTR_CNT_EN(pi->pktc_idx >= 0);
		}

	} else if (strcmp(name, T4PROP_PKTC_IDX) == 0) {
		if (v >= SGE_NCOUNTERS)
			return (EINVAL);
		if (v == pi->pktc_idx || (v < 0 && pi->pktc_idx == -1))
			return (0);

		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->pktc_idx = v < 0 ? -1 : v;
		for_each_rxq(pi, i, rxq) {
			rxq->iq.intr_params = V_QINTR_TIMER_IDX(pi->tmr_idx) |
			    /* takes effect right away */
			    V_QINTR_CNT_EN(v >= 0);
			/* LINTED: E_ASSIGN_NARROW_CONV */
			rxq->iq.intr_pktc_idx = v; /* this needs fresh plumb */
		}
	} else if (strcmp(name, T4PROP_HW_CSUM) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);
		if (v == 1)
			pi->features |= CXGBE_HW_CSUM;
		else
			pi->features &= ~CXGBE_HW_CSUM;
	} else if (strcmp(name, T4PROP_HW_LSO) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);
		if (v == 1)
			pi->features |= CXGBE_HW_LSO;
		else
			pi->features &= ~CXGBE_HW_LSO;
	} else if (strcmp(name, T4PROP_TX_PAUSE) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);

		if (v != 0)
			lc->requested_fc |= PAUSE_TX;
		else
			lc->requested_fc &= ~PAUSE_TX;

		relink = 1;

	} else if (strcmp(name, T4PROP_RX_PAUSE) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);

		if (v != 0)
			lc->requested_fc |= PAUSE_RX;
		else
			lc->requested_fc &= ~PAUSE_RX;

		relink = 1;
	}
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0) {
		if (v < 46 || v > MAX_MTU)
			return (EINVAL);
		if (v == pi->mtu)
			return (0);

		pi->mtu = (int)v;
		(void) mac_maxsdu_update(pi->mh, v);
		rx_mode = 1;
	}
#endif
	else
		return (ENOTSUP);

	if (!(relink || rx_mode))
		return (0);

	/* If we are here, either relink or rx_mode is 1 */
	if (isset(&sc->open_device_map, pi->port_id) != 0) {
		if (relink != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, lc);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "start_link failed:%d", rc);
				/* Restore link_config */
				bcopy(&lc_old, lc, sizeof (struct link_config));
			}
		} else if (rx_mode != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, v, -1, -1,
			    -1, -1, false);
			end_synchronized_op(pi, 1);
			if (rc != 0)  {
				cxgb_printf(pi->dip, CE_WARN,
				    "set_rxmode failed: %d", rc);
			}
		}
		return (rc);
	}

	return (0);
}

void
t4_mc_init(struct port_info *pi)
{
	pi->props = t4_priv_props;
}

void
t4_mc_cb_init(struct port_info *pi)
{
	if (pi->adapter->props.multi_rings)
		pi->mc = &t4_m_ring_callbacks;
	else
		pi->mc = &t4_m_callbacks;
}

void
t4_os_link_changed(struct adapter *sc, int idx, int link_stat)
{
	struct port_info *pi = sc->port[idx];

	mac_link_update(pi->mh, link_stat ? LINK_STATE_UP : LINK_STATE_DOWN);
}

/* ARGSUSED */
void
t4_mac_rx(struct port_info *pi, struct sge_rxq *rxq, mblk_t *m)
{
	mac_rx(pi->mh, NULL, m);
}

void
t4_mac_tx_update(struct port_info *pi, struct sge_txq *txq)
{
	if (pi->adapter->props.multi_rings)
		mac_tx_ring_update(pi->mh, txq->ring_handle);
	else
		mac_tx_update(pi->mh);
}
