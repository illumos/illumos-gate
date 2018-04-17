/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/


#include "qede.h"

#define	FP_LOCK(ptr)	\
mutex_enter(&ptr->fp_lock);
#define	FP_UNLOCK(ptr)	\
mutex_exit(&ptr->fp_lock);

int
qede_ucst_find(qede_t *qede, const uint8_t *mac_addr)
{
	int slot;

	for(slot = 0; slot < qede->ucst_total; slot++) {
		if (bcmp(qede->ucst_mac[slot].mac_addr.ether_addr_octet,
		    mac_addr, ETHERADDRL) == 0) {
			return (slot);
		}
	}
	return (-1);

}

static int
qede_set_mac_addr(qede_t *qede, uint8_t *mac_addr, uint8_t fl)
{
	struct ecore_filter_ucast params;

	memset(&params, 0, sizeof (params));

	params.opcode = fl;
	params.type = ECORE_FILTER_MAC;
	params.is_rx_filter = true;
	params.is_tx_filter = true;
	COPY_ETH_ADDRESS(mac_addr, params.mac);

	return (ecore_filter_ucast_cmd(&qede->edev, 
	    &params, ECORE_SPQ_MODE_EBLOCK, NULL));

			
}
static int 
qede_add_macaddr(qede_t *qede, uint8_t *mac_addr) 
{
	int i, ret = 0;

	i = qede_ucst_find(qede, mac_addr);
	if (i != -1) {
		/* LINTED E_ARGUMENT_MISMATCH */
		qede_info(qede, "mac addr already added %d\n", 
		    qede->ucst_avail);
		return (0);
	}
	if (qede->ucst_avail == 0) {
		qede_info(qede, "add macaddr ignored \n");
		return (ENOSPC);
	}
	for (i = 0; i < qede->ucst_total; i++) {
		if (qede->ucst_mac[i].set == 0) {
			break;
		}
	}
	if (i >= qede->ucst_total) {
		qede_info(qede, "add macaddr ignored no space");
		return (ENOSPC);
	}
	ret = qede_set_mac_addr(qede, (uint8_t *)mac_addr, ECORE_FILTER_ADD);
	if (ret == 0) {
		bcopy(mac_addr, 
		    qede->ucst_mac[i].mac_addr.ether_addr_octet,
		    ETHERADDRL);
		qede->ucst_mac[i].set = 1;
		qede->ucst_avail--;
		/* LINTED E_ARGUMENT_MISMATCH */
		qede_info(qede,  " add macaddr passed for addr "
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac_addr[0], mac_addr[1],
		    mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	} else {
		/* LINTED E_ARGUMENT_MISMATCH */
		qede_info(qede,  "add macaddr failed for addr "
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac_addr[0], mac_addr[1],
		    mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

	}
	if (qede->ucst_avail == (qede->ucst_total -1)) {
			u8 bcast_addr[] = 
			{ 
				0xff, 0xff, 0xff, 0xff, 0xff,
				0xff 
			};
			for (i = 0; i < qede->ucst_total; i++) {
				if (qede->ucst_mac[i].set == 0)
					break;
			}
			ret = qede_set_mac_addr(qede, 
			    (uint8_t *)bcast_addr, ECORE_FILTER_ADD);
			if (ret == 0) {
				bcopy(bcast_addr, 
				    qede->ucst_mac[i].mac_addr.ether_addr_octet,
				    ETHERADDRL);
				qede->ucst_mac[i].set = 1;
				qede->ucst_avail--;
			} else {

			/* LINTED E_ARGUMENT_MISMATCH */
			qede_info(qede,  "add macaddr failed for addr "
			    "%02x:%02x:%02x:%02x:%02x:%02x",
		            mac_addr[0], mac_addr[1],
		            mac_addr[2], mac_addr[3], mac_addr[4], 
			    mac_addr[5]);
		       }

		}	

	return (ret);

}

#ifndef ILLUMOS
static int
qede_add_mac_addr(void *arg, const uint8_t *mac_addr, const uint64_t flags)
#else
static int
qede_add_mac_addr(void *arg, const uint8_t *mac_addr)
#endif
{
	qede_mac_group_t *rx_group = (qede_mac_group_t *)arg;
	qede_t *qede = rx_group->qede;
	int ret = DDI_SUCCESS;

	/* LINTED E_ARGUMENT_MISMATCH */
	qede_info(qede, " mac addr :" MAC_STRING,  MACTOSTR(mac_addr));
	
	mutex_enter(&qede->gld_lock);
	if (qede->qede_state == QEDE_STATE_SUSPENDED) {
		mutex_exit(&qede->gld_lock);
		return (ECANCELED);
	}
	ret = qede_add_macaddr(qede, (uint8_t *)mac_addr);

	mutex_exit(&qede->gld_lock);


	return (ret);
}

static int
qede_rem_macaddr(qede_t *qede, uint8_t *mac_addr)
{
	int ret = 0;
	int i;

	i = qede_ucst_find(qede, mac_addr);
	if (i == -1) {
		/* LINTED E_ARGUMENT_MISMATCH */
		qede_info(qede, 
		    "mac addr not there to remove", 
		    MAC_STRING, MACTOSTR(mac_addr));
		return (0);
	}
	if (qede->ucst_mac[i].set == 0) {
	       	return (EINVAL);
	}	
	ret = qede_set_mac_addr(qede, (uint8_t *)mac_addr, ECORE_FILTER_REMOVE);
	if (ret == 0) {
		bzero(qede->ucst_mac[i].mac_addr.ether_addr_octet,ETHERADDRL);
		qede->ucst_mac[i].set = 0;
		qede->ucst_avail++;
	} else {
		/* LINTED E_ARGUMENT_MISMATCH */
		qede_info(qede, "mac addr remove failed", 
		    MAC_STRING, MACTOSTR(mac_addr));
	}
	return (ret);

}


static int
qede_rem_mac_addr(void *arg, const uint8_t *mac_addr)
{
	qede_mac_group_t *rx_group = (qede_mac_group_t *)arg;
	qede_t *qede = rx_group->qede;
	int ret = DDI_SUCCESS;

	/* LINTED E_ARGUMENT_MISMATCH */
	qede_info(qede, "mac addr remove:" MAC_STRING, MACTOSTR(mac_addr));
	mutex_enter(&qede->gld_lock);
	if (qede->qede_state == QEDE_STATE_SUSPENDED) {
		mutex_exit(&qede->gld_lock);
		return (ECANCELED);
	}
	ret = qede_rem_macaddr(qede, (uint8_t *)mac_addr);
	mutex_exit(&qede->gld_lock);
	return (ret);
}


static int
qede_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	int ret = 0;

	qede_fastpath_t *fp = (qede_fastpath_t *)rh;
	qede_tx_ring_t *tx_ring = fp->tx_ring[0];
	qede_t *qede = fp->qede;


	if (qede->qede_state == QEDE_STATE_SUSPENDED)
		return (ECANCELED);

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = tx_ring->tx_byte_count;
		break;

	case MAC_STAT_OPACKETS:
		*val = tx_ring->tx_pkt_count;
		break;

	default:
		*val = 0;
		ret = ENOTSUP;
	}

	return (ret);
}

#ifndef ILLUMOS
static mblk_t *
qede_rx_ring_poll(void *arg, int poll_bytes, int poll_pkts)
{
#else
static mblk_t *
qede_rx_ring_poll(void *arg, int poll_bytes)
{
	/* XXX pick a value at the moment */
	int poll_pkts = 100;
#endif
	qede_fastpath_t *fp = (qede_fastpath_t *)arg;
	mblk_t *mp = NULL;
	int work_done = 0;
	qede_t *qede = fp->qede;

	if (poll_bytes == 0) {
		return (NULL);
	}

	mutex_enter(&fp->fp_lock);
	qede->intrSbPollCnt[fp->vect_info->vect_index]++;

	mp = qede_process_fastpath(fp, poll_bytes, poll_pkts, &work_done);
	if (mp != NULL) {
		fp->rx_ring->rx_poll_cnt++;
	} else if ((mp == NULL) && (work_done == 0)) {
		qede->intrSbPollNoChangeCnt[fp->vect_info->vect_index]++;
	}

	mutex_exit(&fp->fp_lock);
	return (mp);
}

#ifndef ILLUMOS
static int
qede_rx_ring_intr_enable(mac_ring_driver_t rh)
#else
static int
qede_rx_ring_intr_enable(mac_intr_handle_t rh)
#endif
{
	qede_fastpath_t *fp = (qede_fastpath_t *)rh;

	mutex_enter(&fp->qede->drv_lock);
	if (!fp->sb_phys && (fp->sb_dma_handle == NULL)) {
		mutex_exit(&fp->qede->drv_lock);
		return (DDI_FAILURE);
	}

	fp->rx_ring->intrEnableCnt++;
	qede_enable_hw_intr(fp);
	fp->disabled_by_poll = 0;
	mutex_exit(&fp->qede->drv_lock);

	return (DDI_SUCCESS);
}

#ifndef	ILLUMOS
static int
qede_rx_ring_intr_disable(mac_ring_driver_t rh)
#else
static int
qede_rx_ring_intr_disable(mac_intr_handle_t rh)
#endif
{
	qede_fastpath_t *fp = (qede_fastpath_t *)rh;

	mutex_enter(&fp->qede->drv_lock);
	if (!fp->sb_phys && (fp->sb_dma_handle == NULL)) {
		mutex_exit(&fp->qede->drv_lock);
		return (DDI_FAILURE);
	}
	fp->rx_ring->intrDisableCnt++;
	qede_disable_hw_intr(fp);
	fp->disabled_by_poll = 1;
	mutex_exit(&fp->qede->drv_lock);
	return (DDI_SUCCESS);
}

static int
qede_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{

	int ret = 0;

	qede_fastpath_t *fp = (qede_fastpath_t *)rh;
	qede_t *qede = fp->qede;
	qede_rx_ring_t *rx_ring = fp->rx_ring;

	if (qede->qede_state == QEDE_STATE_SUSPENDED) {
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->rx_byte_cnt;
		break;
	case MAC_STAT_IPACKETS:
		*val = rx_ring->rx_pkt_cnt;
		break;
	default:
		*val = 0;
		ret = ENOTSUP;
		break;	
	}

	return (ret);
}

static int
qede_get_global_ring_index(qede_t *qede, int gindex, int rindex)
{
	qede_fastpath_t *fp;
	qede_rx_ring_t *rx_ring;
	int i = 0;

	for (i = 0; i < qede->num_fp; i++) {
		fp = &qede->fp_array[i];
		rx_ring = fp->rx_ring;

		if (rx_ring->group_index == gindex) {
			rindex--;
		}
		if (rindex < 0) {
			return (i);
		}
	}

	return (-1);
}

static void
qede_rx_ring_stop(mac_ring_driver_t rh)
{
	qede_fastpath_t *fp = (qede_fastpath_t *)rh;
	qede_rx_ring_t *rx_ring = fp->rx_ring;

	qede_print("!%s(%d): called", __func__,fp->qede->instance);
	mutex_enter(&fp->fp_lock);
	rx_ring->mac_ring_started = B_FALSE;
	mutex_exit(&fp->fp_lock);
}

static int
qede_rx_ring_start(mac_ring_driver_t rh, u64 mr_gen_num)
{
	qede_fastpath_t *fp = (qede_fastpath_t *)rh;
	qede_rx_ring_t *rx_ring = fp->rx_ring;

	qede_print("!%s(%d): called", __func__,fp->qede->instance);
	mutex_enter(&fp->fp_lock);
	rx_ring->mr_gen_num = mr_gen_num;
	rx_ring->mac_ring_started = B_TRUE;
        rx_ring->intrDisableCnt = 0;
	rx_ring->intrEnableCnt  = 0;
	fp->disabled_by_poll = 0;

	mutex_exit(&fp->fp_lock);

	return (DDI_SUCCESS);
}

/* Callback function from mac layer to register rings */
void
qede_fill_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	qede_t *qede = (qede_t *)arg;
	mac_intr_t *mintr = &infop->mri_intr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		/*
		 * Index passed as a param is the ring index within the
		 * given group index. If multiple groups are supported
		 * then need to search into all groups to find out the
		 * global ring index for the passed group relative
		 * ring index
		 */
		int global_ring_index = qede_get_global_ring_index(qede,
		    group_index, ring_index);
		qede_fastpath_t *fp;
		qede_rx_ring_t *rx_ring;
		int i;

		/* 
		 * global_ring_index < 0 means group index passed
		 * was registered by our driver
		 */
		ASSERT(global_ring_index >= 0);

		if (rh == NULL) {
			cmn_err(CE_WARN, "!rx ring(%d) ring handle NULL",
			    global_ring_index);
		}

		fp = &qede->fp_array[global_ring_index];
		rx_ring = fp->rx_ring;
		fp->qede = qede;

		rx_ring->mac_ring_handle = rh;

		qede_info(qede, "rx_ring %d mac_ring_handle %p",
		    rx_ring->rss_id, rh);

		/* mri_driver passed as arg to mac_ring* callbacks */
		infop->mri_driver = (mac_ring_driver_t)fp;
		/*
		 * mri_start callback will supply a mac rings generation
		 * number which is needed while indicating packets
		 * upstream via mac_ring_rx() call
		 */
		infop->mri_start = qede_rx_ring_start;
		infop->mri_stop = qede_rx_ring_stop;
		infop->mri_poll = qede_rx_ring_poll;
		infop->mri_stat = qede_rx_ring_stat;

		mintr->mi_handle = (mac_intr_handle_t)fp;
		mintr->mi_enable = qede_rx_ring_intr_enable;
		mintr->mi_disable = qede_rx_ring_intr_disable;
		if (qede->intr_ctx.intr_type_in_use &
		    (DDI_INTR_TYPE_MSIX | DDI_INTR_TYPE_MSI)) {
			mintr->mi_ddi_handle =
			    qede->intr_ctx.
			    intr_hdl_array[global_ring_index + qede->num_hwfns];
		}
		break;
	}
	case MAC_RING_TYPE_TX: {
		qede_fastpath_t *fp;
		qede_tx_ring_t *tx_ring;
		int i, tc;

		ASSERT(ring_index < qede->num_fp);
		
		fp = &qede->fp_array[ring_index];
		fp->qede = qede;
		tx_ring = fp->tx_ring[0];
		tx_ring->mac_ring_handle = rh;
		qede_info(qede, "tx_ring %d mac_ring_handle %p",
		    tx_ring->tx_queue_index, rh);
		infop->mri_driver = (mac_ring_driver_t)fp;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = qede_ring_tx;
		infop->mri_stat = qede_tx_ring_stat;
		if (qede->intr_ctx.intr_type_in_use &
		    (DDI_INTR_TYPE_MSIX | DDI_INTR_TYPE_MSI)) {
			mintr->mi_ddi_handle =
			    qede->intr_ctx.
			    intr_hdl_array[ring_index + qede->num_hwfns]; 
		}
		break;
	}
	default:
		break;
	}
}

/*
 * Callback function from mac layer to register group
 */
void
qede_fill_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	qede_t *qede = (qede_t *)arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		qede_mac_group_t *rx_group;

		rx_group = &qede->rx_groups[index];
		rx_group->group_handle = gh;
		rx_group->group_index = index;
		rx_group->qede = qede;
		infop->mgi_driver = (mac_group_driver_t)rx_group;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
#ifndef ILLUMOS
		infop->mgi_addvlan = NULL;
		infop->mgi_remvlan = NULL;
		infop->mgi_getsriov_info = NULL;
		infop->mgi_setmtu = NULL;
#endif
		infop->mgi_addmac = qede_add_mac_addr;
		infop->mgi_remmac = qede_rem_mac_addr;
		infop->mgi_count =  qede->num_fp;
#ifndef ILLUMOS
		if (index == 0) {
			infop->mgi_flags = MAC_GROUP_DEFAULT;
		}
#endif

		break;
	}
	case MAC_RING_TYPE_TX: {
		qede_mac_group_t *tx_group;

		tx_group = &qede->tx_groups[index];
		tx_group->group_handle = gh;
		tx_group->group_index = index;
		tx_group->qede = qede;

		infop->mgi_driver = (mac_group_driver_t)tx_group;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = NULL;
		infop->mgi_remmac = NULL;
#ifndef ILLUMOS
		infop->mgi_addvlan = NULL;
		infop->mgi_remvlan = NULL;
		infop->mgi_setmtu = NULL;
		infop->mgi_getsriov_info = NULL;
#endif

		infop->mgi_count = qede->num_fp;

#ifndef ILLUMOS
		if (index == 0) {
			infop->mgi_flags = MAC_GROUP_DEFAULT;
		}
#endif
		break;
	}
	default:
		break;
	}
}

#ifdef ILLUMOS
static int
qede_transceiver_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
        qede_t *qede = arg;
        struct ecore_dev *edev = &qede->edev;
        struct ecore_hwfn *hwfn;
        struct ecore_ptt *ptt;
        uint32_t transceiver_state;

        if (id >= edev->num_hwfns || arg == NULL || infop == NULL)
                return (EINVAL);

        hwfn = &edev->hwfns[id];
        ptt = ecore_ptt_acquire(hwfn);
        if (ptt == NULL) {
                return (EIO);
        }
        /*
         * Use the underlying raw API to get this information. While the
         * ecore_phy routines have some ways of getting to this information, it
         * ends up writing the raw data as ASCII characters which doesn't help
         * us one bit.
         */
        transceiver_state = ecore_rd(hwfn, ptt, hwfn->mcp_info->port_addr +
            OFFSETOF(struct public_port, transceiver_data));
        transceiver_state = GET_FIELD(transceiver_state, ETH_TRANSCEIVER_STATE);
        ecore_ptt_release(hwfn, ptt);

        if ((transceiver_state & ETH_TRANSCEIVER_STATE_PRESENT) != 0) {
                mac_transceiver_info_set_present(infop, B_TRUE);
                /*
                 * Based on our testing, the ETH_TRANSCEIVER_STATE_VALID flag is
                 * not set, so we cannot rely on it. Instead, we have found that
                 * the ETH_TRANSCEIVER_STATE_UPDATING will be set when we cannot
                 * use the transceiver.
                 */
                if ((transceiver_state & ETH_TRANSCEIVER_STATE_UPDATING) != 0) {
                        mac_transceiver_info_set_usable(infop, B_FALSE);
                } else {
                        mac_transceiver_info_set_usable(infop, B_TRUE);
                }
        } else {
                mac_transceiver_info_set_present(infop, B_FALSE);
                mac_transceiver_info_set_usable(infop, B_FALSE);
        }

        return (0);
}

static int
qede_transceiver_read(void *arg, uint_t id, uint_t page, void *buf,
    size_t nbytes, off_t offset, size_t *nread)
{
        qede_t *qede = arg;
        struct ecore_dev *edev = &qede->edev;
        struct ecore_hwfn *hwfn;
        uint32_t port, lane;
        struct ecore_ptt *ptt;
        enum _ecore_status_t ret;

        if (id >= edev->num_hwfns || buf == NULL || nbytes == 0 || nread == NULL ||
            (page != 0xa0 && page != 0xa2) || offset < 0)
                return (EINVAL);

        /*
         * Both supported pages have a length of 256 bytes, ensure nothing asks
         * us to go beyond that.
         */
        if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256)) {
               return (EINVAL);
        }

        hwfn = &edev->hwfns[id];
        ptt = ecore_ptt_acquire(hwfn);
        if (ptt == NULL) {
                return (EIO);
        }

        ret = ecore_mcp_phy_sfp_read(hwfn, ptt, hwfn->port_id, page, offset,
            nbytes, buf);
        ecore_ptt_release(hwfn, ptt);
        if (ret != ECORE_SUCCESS) {
                return (EIO);
        }
        *nread = nbytes;
        return (0);
}
#endif /* ILLUMOS */


static int
qede_mac_stats(void *     arg,
                        uint_t     stat,
                        uint64_t * value)
{
	qede_t * qede = (qede_t *)arg;
	struct ecore_eth_stats vstats;
	struct ecore_dev *edev = &qede->edev;
	struct qede_link_cfg lnkcfg;
	int rc = 0;
	qede_fastpath_t *fp = &qede->fp_array[0];
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;

	if ((qede == NULL) || (value == NULL)) {
		return EINVAL;
	}


	mutex_enter(&qede->gld_lock);

	if(qede->qede_state != QEDE_STATE_STARTED) {
		mutex_exit(&qede->gld_lock);
		return EAGAIN;
	}

	*value = 0;
	
	memset(&vstats, 0, sizeof(struct ecore_eth_stats));
	ecore_get_vport_stats(edev, &vstats);
	

        memset(&qede->curcfg, 0, sizeof(struct qede_link_cfg));
        qede_get_link_info(&edev->hwfns[0], &qede->curcfg);



	switch (stat)
	{
	case MAC_STAT_IFSPEED:
		*value = (qede->props.link_speed * 1000000ULL);
		break;
	case MAC_STAT_MULTIRCV:
		*value = vstats.common.rx_mcast_pkts;
		break;
	case MAC_STAT_BRDCSTRCV:
		*value = vstats.common.rx_bcast_pkts;
		break;
	case MAC_STAT_MULTIXMT:
		*value = vstats.common.tx_mcast_pkts;
		break;
	case MAC_STAT_BRDCSTXMT:
		*value = vstats.common.tx_bcast_pkts;
		break;
	case MAC_STAT_NORCVBUF:
		*value = vstats.common.no_buff_discards;
		break;
	case MAC_STAT_NOXMTBUF:
		*value = 0;
		break;
	case MAC_STAT_IERRORS:
	case ETHER_STAT_MACRCV_ERRORS:
		*value = vstats.common.mac_filter_discards + 
		    vstats.common.packet_too_big_discard + 
		    vstats.common.rx_crc_errors;	
		break;
	
	case MAC_STAT_OERRORS:
		break;

	case MAC_STAT_COLLISIONS:
		*value = vstats.bb.tx_total_collisions;
		break;

	case MAC_STAT_RBYTES:
		*value = vstats.common.rx_ucast_bytes + 
		    vstats.common.rx_mcast_bytes + 
		    vstats.common.rx_bcast_bytes;
		break;

	case MAC_STAT_IPACKETS:
		*value = vstats.common.rx_ucast_pkts + 
		    vstats.common.rx_mcast_pkts + 
		    vstats.common.rx_bcast_pkts; 
		break;

	case MAC_STAT_OBYTES:
		*value = vstats.common.tx_ucast_bytes + 
		    vstats.common.tx_mcast_bytes + 
		    vstats.common.tx_bcast_bytes;
		break;

	case MAC_STAT_OPACKETS:
		*value = vstats.common.tx_ucast_pkts + 
		    vstats.common.tx_mcast_pkts + 
		    vstats.common.tx_bcast_pkts;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*value = vstats.common.rx_align_errors;
		break;
	
	case ETHER_STAT_FCS_ERRORS:
		*value = vstats.common.rx_crc_errors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		break;

	case ETHER_STAT_DEFER_XMTS:
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		break;

	case ETHER_STAT_EX_COLLISIONS:
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*value = 0;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*value = vstats.common.rx_oversize_packets;
		break;

#if (MAC_VERSION > 1)
	case ETHER_STAT_TOOSHORT_ERRORS:
		*value = vstats.common.rx_undersize_packets;
		break;
#endif

	case ETHER_STAT_XCVR_ADDR:
        	*value = 0;
        	break;

	case ETHER_STAT_XCVR_ID:
        	*value = 0;
        	break;

	case ETHER_STAT_XCVR_INUSE:
		switch (qede->props.link_speed) {
		default:
			*value = XCVR_UNDEFINED;
		}
		break;
#if (MAC_VERSION > 1)
	case ETHER_STAT_CAP_10GFDX:
		*value = 0;
		break;
#endif
	case ETHER_STAT_CAP_100FDX:
        	*value = 0;
        	break;	
	case ETHER_STAT_CAP_100HDX:
        	*value = 0;
        	break;	
	case ETHER_STAT_CAP_ASMPAUSE:
		*value = 1;
		break;
	case ETHER_STAT_CAP_PAUSE:	
		*value = 1;
		break;
	case ETHER_STAT_CAP_AUTONEG:
		*value = 1;
		break;
	
#if (MAC_VERSION > 1)
	case ETHER_STAT_CAP_REMFAULT:
		*value = 0;
		break;
#endif

#if (MAC_VERSION > 1)
	case ETHER_STAT_ADV_CAP_10GFDX:
		*value = 0; 
		break;
#endif
    case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*value = 1;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*value = 1;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*value = qede->curcfg.adv_capab.autoneg;
		break;

#if (MAC_VERSION > 1)
	case ETHER_STAT_ADV_REMFAULT:
		*value = 0;
		break;
#endif	

	case ETHER_STAT_LINK_AUTONEG:
		*value	= qede->curcfg.autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*value = (qede->props.link_duplex == DUPLEX_FULL) ?
				    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		break;
        /*
         * Supported speeds. These indicate what hardware is capable of.
         */
        case ETHER_STAT_CAP_1000HDX:
                *value = qede->curcfg.supp_capab.param_1000hdx;
                break;

        case ETHER_STAT_CAP_1000FDX:
                *value = qede->curcfg.supp_capab.param_1000fdx;
                break;

        case ETHER_STAT_CAP_10GFDX:
                *value = qede->curcfg.supp_capab.param_10000fdx;
                break;

        case ETHER_STAT_CAP_25GFDX:
                *value = qede->curcfg.supp_capab.param_25000fdx;
                break;

        case ETHER_STAT_CAP_40GFDX:
                *value = qede->curcfg.supp_capab.param_40000fdx;
                break;

        case ETHER_STAT_CAP_50GFDX:
                *value = qede->curcfg.supp_capab.param_50000fdx;
                break;

        case ETHER_STAT_CAP_100GFDX:
                *value = qede->curcfg.supp_capab.param_100000fdx;
                break;

        /*
         * Advertised speeds. These indicate what hardware is currently sending.
         */
        case ETHER_STAT_ADV_CAP_1000HDX:
                *value = qede->curcfg.adv_capab.param_1000hdx;
                break;

        case ETHER_STAT_ADV_CAP_1000FDX:
                *value = qede->curcfg.adv_capab.param_1000fdx;
                break;

        case ETHER_STAT_ADV_CAP_10GFDX:
                *value = qede->curcfg.adv_capab.param_10000fdx;
                break;

        case ETHER_STAT_ADV_CAP_25GFDX:
                *value = qede->curcfg.adv_capab.param_25000fdx;
                break;

        case ETHER_STAT_ADV_CAP_40GFDX:
                *value = qede->curcfg.adv_capab.param_40000fdx;
                break;

        case ETHER_STAT_ADV_CAP_50GFDX:
                *value = qede->curcfg.adv_capab.param_50000fdx;
                break;

        case ETHER_STAT_ADV_CAP_100GFDX:
                *value = qede->curcfg.adv_capab.param_100000fdx;
                break;

	default:
		rc = ENOTSUP;
	}

	mutex_exit(&qede->gld_lock);
	return (rc);
}

/* (flag) TRUE = on, FALSE = off */
static int
qede_mac_promiscuous(void *arg,
    boolean_t on)
{
    	qede_t *qede = (qede_t *)arg;
	qede_print("!%s(%d): called", __func__,qede->instance);
	int ret = DDI_SUCCESS;
	enum qede_filter_rx_mode_type mode;
	
	mutex_enter(&qede->drv_lock);
	
	if (qede->qede_state == QEDE_STATE_SUSPENDED) {
		ret = ECANCELED;
		goto exit;
	}

	if (on) {
		qede_info(qede, "Entering promiscuous mode");
		mode = QEDE_FILTER_RX_MODE_PROMISC;
		qede->params.promisc_fl = B_TRUE;
	} else {
		qede_info(qede, "Leaving promiscuous mode");
		if(qede->params.multi_promisc_fl == B_TRUE) {
			mode = QEDE_FILTER_RX_MODE_MULTI_PROMISC;
		} else {	
			 mode = QEDE_FILTER_RX_MODE_REGULAR;
		}
		qede->params.promisc_fl = B_FALSE;
	}

	ret = qede_set_filter_rx_mode(qede, mode);

exit:
	mutex_exit(&qede->drv_lock);
    	return (ret);
}

int qede_set_rx_mac_mcast(qede_t *qede, enum ecore_filter_opcode opcode, 
			  uint8_t *mac, int mc_cnt) 
{
	struct ecore_filter_mcast cmd;
	int i;
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opcode;
	cmd.num_mc_addrs = mc_cnt;

        for (i = 0; i < mc_cnt; i++, mac += ETH_ALLEN) {
		COPY_ETH_ADDRESS(mac, cmd.mac[i]);
        }


        return (ecore_filter_mcast_cmd(&qede->edev, &cmd, 
	    ECORE_SPQ_MODE_CB, NULL));
		
}

int
qede_set_filter_rx_mode(qede_t * qede, enum qede_filter_rx_mode_type type) 
{
	struct ecore_filter_accept_flags flg;

	memset(&flg, 0, sizeof(flg));

	flg.update_rx_mode_config      = 1;
	flg.update_tx_mode_config      = 1;
	flg.rx_accept_filter           = ECORE_ACCEPT_UCAST_MATCHED | 
	    ECORE_ACCEPT_MCAST_MATCHED | ECORE_ACCEPT_BCAST;
	flg.tx_accept_filter = ECORE_ACCEPT_UCAST_MATCHED | 
	    ECORE_ACCEPT_MCAST_MATCHED | ECORE_ACCEPT_BCAST;

	if (type == QEDE_FILTER_RX_MODE_PROMISC)
		flg.rx_accept_filter |= ECORE_ACCEPT_UCAST_UNMATCHED | 
		    ECORE_ACCEPT_MCAST_UNMATCHED;
	else if (type == QEDE_FILTER_RX_MODE_MULTI_PROMISC)
		flg.rx_accept_filter |= ECORE_ACCEPT_MCAST_UNMATCHED;
	qede_info(qede, "rx_mode rx_filter=0x%x tx_filter=0x%x type=0x%x\n", 
	    flg.rx_accept_filter, flg.tx_accept_filter, type);
	return (ecore_filter_accept_cmd(&qede->edev, 0, flg,
			0, /* update_accept_any_vlan */
			0, /* accept_any_vlan */
			ECORE_SPQ_MODE_CB, NULL));
}

int 
qede_multicast(qede_t *qede, boolean_t flag, const uint8_t *ptr_mcaddr)
{
	int i, ret = DDI_SUCCESS;
	qede_mcast_list_entry_t *ptr_mlist;
	qede_mcast_list_entry_t *ptr_entry;
	int mc_cnt;
	unsigned char *mc_macs, *tmpmc;
	size_t size;
	boolean_t mcmac_exists = B_FALSE;
	enum qede_filter_rx_mode_type mode;

	if (!ptr_mcaddr)  {
		cmn_err(CE_NOTE, "Removing all multicast");
	} else  {
		cmn_err(CE_NOTE,
		    "qede=%p %s multicast: %02x:%02x:%02x:%02x:%02x:%02x",
		    qede, (flag) ? "Adding" : "Removing", ptr_mcaddr[0], 
		    ptr_mcaddr[1],ptr_mcaddr[2],ptr_mcaddr[3],ptr_mcaddr[4],
		    ptr_mcaddr[5]);
	}


	if (flag && (ptr_mcaddr == NULL)) {
		cmn_err(CE_WARN, "ERROR: Multicast address not specified");
		return EINVAL;
	}


	/* exceeds addition of mcaddr above limit */
	if (flag && (qede->mc_cnt >= MAX_MC_SOFT_LIMIT)) {
		qede_info(qede, "Cannot add more than MAX_MC_SOFT_LIMIT");
		return ENOENT;
	}

	size = MAX_MC_SOFT_LIMIT * ETH_ALLEN;

	mc_macs = kmem_zalloc(size, KM_NOSLEEP);
	if (!mc_macs) { 
		cmn_err(CE_WARN, "ERROR: Failed to allocate for mc_macs");
		return EINVAL;
	}

	tmpmc = mc_macs;

        /* remove all multicast - as flag not set and mcaddr not specified*/
        if (!flag && (ptr_mcaddr == NULL)) {
                QEDE_LIST_FOR_EACH_ENTRY(ptr_entry, 
		    &qede->mclist.head, qede_mcast_list_entry_t, mclist_entry)
                {
                        if (ptr_entry != NULL) {
                        QEDE_LIST_REMOVE(&ptr_entry->mclist_entry, 
			    &qede->mclist.head);
                        kmem_free(ptr_entry, 
			    sizeof (qede_mcast_list_entry_t) + ETH_ALLEN);
                        }
                }

                ret = qede_set_rx_mac_mcast(qede, 
		    ECORE_FILTER_REMOVE, mc_macs, 1);
                qede->mc_cnt = 0;
                goto exit;
        }

        QEDE_LIST_FOR_EACH_ENTRY(ptr_entry, 
	    &qede->mclist.head, qede_mcast_list_entry_t, mclist_entry)
        {
                if ((ptr_entry != NULL) && 
		    IS_ETH_ADDRESS_EQUAL(ptr_mcaddr, ptr_entry->mac)) {
                        mcmac_exists = B_TRUE;
                        break;
                }
        }
        if (flag && mcmac_exists) {
                ret = DDI_SUCCESS;
                goto exit;
        } else if (!flag && !mcmac_exists) {
                ret = DDI_SUCCESS;
                goto exit;
        }

       if (flag) {
                ptr_entry = kmem_zalloc((sizeof (qede_mcast_list_entry_t) + 
		    ETH_ALLEN), KM_NOSLEEP);
                ptr_entry->mac = (uint8_t *)ptr_entry + 
		    sizeof (qede_mcast_list_entry_t);
                COPY_ETH_ADDRESS(ptr_mcaddr, ptr_entry->mac);
                QEDE_LIST_ADD(&ptr_entry->mclist_entry, &qede->mclist.head);
        } else {
                QEDE_LIST_REMOVE(&ptr_entry->mclist_entry, &qede->mclist.head);
                kmem_free(ptr_entry, sizeof(qede_mcast_list_entry_t) + 
		    ETH_ALLEN);
        }

	mc_cnt = 0;
        QEDE_LIST_FOR_EACH_ENTRY(ptr_entry, &qede->mclist.head, 
	    qede_mcast_list_entry_t, mclist_entry) {
                COPY_ETH_ADDRESS(ptr_entry->mac, tmpmc);
                tmpmc += ETH_ALLEN;
                mc_cnt++;
        }
        qede->mc_cnt = mc_cnt;
        if (mc_cnt <=64) {
                ret = qede_set_rx_mac_mcast(qede, ECORE_FILTER_ADD, 
		    (unsigned char *)mc_macs, mc_cnt);
                if ((qede->params.multi_promisc_fl == B_TRUE) && 
		    (qede->params.promisc_fl == B_FALSE)) {
                        mode = QEDE_FILTER_RX_MODE_REGULAR;
                        ret = qede_set_filter_rx_mode(qede, mode);
                }
                qede->params.multi_promisc_fl = B_FALSE;
        } else {
                if ((qede->params.multi_promisc_fl == B_FALSE) && 
		    (qede->params.promisc_fl = B_FALSE)) {
                        ret = qede_set_filter_rx_mode(qede, 
			    QEDE_FILTER_RX_MODE_MULTI_PROMISC);
                }
                qede->params.multi_promisc_fl = B_TRUE;
                qede_info(qede, "mode is MULTI_PROMISC");
        }
exit:
kmem_free(mc_macs, size);
qede_info(qede, "multicast ret %d mc_cnt %d\n", ret, qede->mc_cnt);
return (ret);
}

/*
 * This function is used to enable or disable multicast packet reception for
 * particular multicast addresses.
 * (flag) TRUE = add, FALSE = remove
 */
static int
qede_mac_multicast(void *arg,
    boolean_t       flag,
    const uint8_t * mcast_addr)
{
	qede_t *qede = (qede_t *)arg;
	int ret = DDI_SUCCESS;


	mutex_enter(&qede->gld_lock);
	if(qede->qede_state != QEDE_STATE_STARTED) {
		mutex_exit(&qede->gld_lock);
		return (EAGAIN);
	}
	ret = qede_multicast(qede, flag, mcast_addr);
		
	mutex_exit(&qede->gld_lock);

    return (ret);
}
int 
qede_clear_filters(qede_t *qede)
{
	int ret = 0;
	int i;
	if ((qede->params.promisc_fl == B_TRUE) || 
	    (qede->params.multi_promisc_fl == B_TRUE)) {
		ret = qede_set_filter_rx_mode(qede, 
		    QEDE_FILTER_RX_MODE_REGULAR);
		if (ret) {
			qede_info(qede, 
			    "qede_clear_filters failed to set rx_mode");
		}
	}
	for (i=0; i < qede->ucst_total; i++)
	{
		if (qede->ucst_mac[i].set) {
			qede_rem_macaddr(qede, 
			    qede->ucst_mac[i].mac_addr.ether_addr_octet);
		}
	}
	qede_multicast(qede, B_FALSE, NULL);
	return (ret);
}


#ifdef  NO_CROSSBOW
static int
qede_mac_unicast(void *arg,
    const uint8_t * mac_addr)
{
    qede_t *qede = (qede_t *)arg;
    return 0;
}


static mblk_t *
qede_mac_tx(void *arg,
    mblk_t * mblk)
{
    qede_t *qede = (qede_t *)arg;
    qede_fastpath_t *fp = &qede->fp_array[0];

    mblk = qede_ring_tx((void *)fp, mblk);

    return (mblk);
}
#endif  /* NO_CROSSBOW */


static lb_property_t loopmodes[] = {
	{ normal,       "normal",       QEDE_LOOP_NONE                },
	{ internal,     "internal",     QEDE_LOOP_INTERNAL            },
	{ external,     "external",     QEDE_LOOP_EXTERNAL            },
};

/* 
 * Set Loopback mode 
 */

static enum ioc_reply
qede_set_loopback_mode(qede_t *qede, uint32_t mode)
{
	int ret, i = 0;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *hwfn;
	struct ecore_ptt *ptt = NULL;
	struct ecore_mcp_link_params *link_params;

	hwfn = &edev->hwfns[0];
	link_params = ecore_mcp_get_link_params(hwfn);
	ptt = ecore_ptt_acquire(hwfn);

	switch(mode) {
	default:
		qede_info(qede, "unknown loopback mode !!");
		ecore_ptt_release(hwfn, ptt);
		return IOC_INVAL;

	case QEDE_LOOP_NONE:
		ecore_mcp_set_link(hwfn, ptt, 0);

		while (qede->params.link_state && i < 5000) {
			OSAL_MSLEEP(1);
			i++;
		}
		i = 0;

		link_params->loopback_mode = ETH_LOOPBACK_NONE;
		qede->loop_back_mode = QEDE_LOOP_NONE;
		ret = ecore_mcp_set_link(hwfn, ptt, 1);
		ecore_ptt_release(hwfn, ptt);

		while (!qede->params.link_state && i < 5000) {
			OSAL_MSLEEP(1);
			i++;
		}
		return IOC_REPLY;

	case QEDE_LOOP_INTERNAL:
		qede_print("!%s(%d) : loopback mode (INTERNAL) is set!",
		    __func__, qede->instance);
		    ecore_mcp_set_link(hwfn, ptt, 0);

		while(qede->params.link_state && i < 5000) {
			OSAL_MSLEEP(1);
			i++;
		}
		i = 0;
		link_params->loopback_mode = ETH_LOOPBACK_INT_PHY;
		qede->loop_back_mode = QEDE_LOOP_INTERNAL;
		ret = ecore_mcp_set_link(hwfn, ptt, 1);
		ecore_ptt_release(hwfn, ptt);

		while(!qede->params.link_state && i < 5000) {
			OSAL_MSLEEP(1);
			i++;
		}
		return IOC_REPLY;

	case QEDE_LOOP_EXTERNAL:
		qede_print("!%s(%d) : External loopback mode is not supported",
		    __func__, qede->instance);
		ecore_ptt_release(hwfn, ptt);
		return IOC_INVAL;
	}
}

static int
qede_ioctl_pcicfg_rd(qede_t *qede, u32 addr, void *data,
    int len)
{
	u32 crb, actual_crb; 
	uint32_t ret = 0;
	int cap_offset = 0, cap_id = 0, next_cap = 0;
	ddi_acc_handle_t pci_cfg_handle  = qede->pci_cfg_handle;
	qede_ioctl_data_t * data1 = (qede_ioctl_data_t *) data;
	
	cap_offset = pci_config_get8(pci_cfg_handle, PCI_CONF_CAP_PTR);
	while (cap_offset != 0) {
                /* Check for an invalid PCI read. */
                if (cap_offset == PCI_EINVAL8) {
                        return DDI_FAILURE;
                }
		cap_id = pci_config_get8(pci_cfg_handle, cap_offset);
		if (cap_id == PCI_CAP_ID_PCI_E) {
			/* PCIe expr capab struct found */
			break;
		} else {
			next_cap = pci_config_get8(pci_cfg_handle,
			    cap_offset + 1);
			cap_offset = next_cap;
		}
	}

	switch (len) {
	case 1:
		ret = pci_config_get8(qede->pci_cfg_handle, addr);
		(void) memcpy(data, &ret, sizeof(uint8_t));
		break;
	case 2:
		ret = pci_config_get16(qede->pci_cfg_handle, addr);
		(void) memcpy(data, &ret, sizeof(uint16_t));
		break;
	case 4:
		ret = pci_config_get32(qede->pci_cfg_handle, addr);
		(void) memcpy(data, &ret, sizeof(uint32_t));
		break;
	default:
		cmn_err(CE_WARN, "bad length for pci config read\n");
		return (1);
	}
	return (0);
}

static int
qede_ioctl_pcicfg_wr(qede_t *qede, u32 addr, void *data,
    int len)
{
	uint16_t ret = 0;
	int cap_offset = 0, cap_id = 0, next_cap = 0;
	qede_ioctl_data_t * data1 = (qede_ioctl_data_t *) data;
	ddi_acc_handle_t pci_cfg_handle  = qede->pci_cfg_handle;
#if 1
	cap_offset = pci_config_get8(pci_cfg_handle, PCI_CONF_CAP_PTR);
	while (cap_offset != 0) {
		cap_id = pci_config_get8(pci_cfg_handle, cap_offset);
		if (cap_id == PCI_CAP_ID_PCI_E) {
			/* PCIe expr capab struct found */
			break;
		} else {
			next_cap = pci_config_get8(pci_cfg_handle, 
			    cap_offset + 1);
			cap_offset = next_cap;
		}
	}
#endif

	switch(len) {
	case 1:
		pci_config_put8(qede->pci_cfg_handle, addr, 
		    *(char *)&(data));
		break;
	case 2:
		ret = pci_config_get16(qede->pci_cfg_handle, addr);
		ret = ret | *(uint16_t *)data1->uabc;

		pci_config_put16(qede->pci_cfg_handle, addr, 
		    ret);
		break;
	case 4:
		pci_config_put32(qede->pci_cfg_handle, addr, *(uint32_t *)data1->uabc);
		break;
		
	default:
		return (1);
	}
	return (0);
}

static int
qede_ioctl_rd_wr_reg(qede_t *qede, void *data)
{
	struct ecore_hwfn *p_hwfn;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_ptt *ptt;
	qede_ioctl_data_t *data1 = (qede_ioctl_data_t *)data;
	uint32_t ret = 0;
	uint8_t cmd = (uint8_t) data1->unused1;
	uint32_t addr = data1->off;
	uint32_t val = *(uint32_t *)&data1->uabc[1];
	uint32_t hwfn_index = *(uint32_t *)&data1->uabc[5];	
	uint32_t *reg_addr;

	if (hwfn_index > qede->num_hwfns) {
		cmn_err(CE_WARN, "invalid hwfn index from application\n");
		return (EINVAL);
	}
	p_hwfn = &edev->hwfns[hwfn_index];
	
	switch(cmd) {
	case QEDE_REG_READ:
		ret = ecore_rd(p_hwfn, p_hwfn->p_main_ptt, addr);
		(void) memcpy(data1->uabc, &ret, sizeof(uint32_t));
		break;
		
	case QEDE_REG_WRITE:
		ecore_wr(p_hwfn, p_hwfn->p_main_ptt, addr, val);
		break;

	default:
		cmn_err(CE_WARN, 
		    "wrong command in register read/write from application\n");
		break;
	}
	return (ret);
}

static int
qede_ioctl_rd_wr_nvram(qede_t *qede, mblk_t *mp)
{
	qede_nvram_data_t *data1 = (qede_nvram_data_t *)(mp->b_cont->b_rptr); 
	qede_nvram_data_t *data2, *next_data;
	struct ecore_dev *edev = &qede->edev;
	uint32_t ret = 0, hdr_size = 24, bytes_to_copy, copy_len = 0;
	uint32_t copy_len1 = 0;
	uint32_t addr = data1->off;
	uint32_t size = data1->size, i, buf_size;
	uint8_t cmd, cmd2;
	uint8_t *buf, *tmp_buf;
	mblk_t *mp1;

	cmd = (uint8_t)data1->unused1;

	switch(cmd) {
	case QEDE_NVRAM_CMD_READ:
		buf = kmem_zalloc(size, GFP_KERNEL);
		if(buf == NULL) {
			cmn_err(CE_WARN, "memory allocation failed" 
			" in nvram read ioctl\n");
			return (DDI_FAILURE);
		}
		ret = ecore_mcp_nvm_read(edev, addr, buf, data1->size);

		copy_len = (MBLKL(mp->b_cont)) - hdr_size;
		if(copy_len > size) {
			(void) memcpy(data1->uabc, buf, size);
			kmem_free(buf, size);
			//OSAL_FREE(edev, buf);
			ret = 0;
			break;
		}
		(void) memcpy(data1->uabc, buf, copy_len);
		bytes_to_copy = size - copy_len;
		tmp_buf = ((uint8_t *)buf) + copy_len;
		copy_len1 = copy_len;
		mp1 = mp->b_cont;
		mp1 = mp1->b_cont;

		while (mp1) {
			copy_len = MBLKL(mp1);
			if(mp1->b_cont == NULL) {
				copy_len = MBLKL(mp1) - 4;
			}
			data2 = (qede_nvram_data_t *)mp1->b_rptr;
			if (copy_len > bytes_to_copy) {
				(void) memcpy(data2->uabc, tmp_buf, 
				    bytes_to_copy);
				kmem_free(buf, size);
				//OSAL_FREE(edev, buf);
				break;
			}
			(void) memcpy(data2->uabc, tmp_buf, copy_len);
			tmp_buf = tmp_buf + copy_len;
			copy_len += copy_len;
			mp1 = mp1->b_cont;
			bytes_to_copy = bytes_to_copy - copy_len;
		}
			
		kmem_free(buf, size);
		//OSAL_FREE(edev, buf);
		break;
	
	case QEDE_NVRAM_CMD_WRITE:
		cmd2 = (uint8_t )data1->cmd2;
		size = data1->size;
		addr = data1->off;
		buf_size =  size; //data1->buf_size;
		//buf_size =  data1->buf_size;
		ret = 0;

		switch(cmd2){
		case START_NVM_WRITE:
			buf = kmem_zalloc(size, GFP_KERNEL);
			//buf = qede->reserved_buf;
			qede->nvm_buf_size = data1->size;
			if(buf == NULL) {
				cmn_err(CE_WARN, 
				"memory allocation failed in START_NVM_WRITE\n");
				return DDI_FAILURE;
			}
			qede->nvm_buf_start = buf;
			cmn_err(CE_NOTE, 
			    "buf = %p, size = %x\n", qede->nvm_buf_start, size);
			qede->nvm_buf = buf;
			qede->copy_len = 0;
			//tmp_buf = buf + addr;
			ret = 0;
			break;
			
		case ACCUMULATE_NVM_BUF:
			tmp_buf = qede->nvm_buf;
			copy_len = MBLKL(mp->b_cont) - hdr_size;
			if(copy_len > buf_size) {
			 	if (buf_size < qede->nvm_buf_size) {
				(void) memcpy(tmp_buf, data1->uabc, buf_size);
					qede->copy_len = qede->copy_len + 
					    buf_size;
				} else {
					(void) memcpy(tmp_buf, 
					    data1->uabc, qede->nvm_buf_size);
					qede->copy_len = 
					    qede->copy_len + qede->nvm_buf_size;
				}
				tmp_buf = tmp_buf + buf_size;
				qede->nvm_buf = tmp_buf;
				//qede->copy_len = qede->copy_len + buf_size;
				cmn_err(CE_NOTE, 
				    "buf_size from app = %x\n", copy_len);
				ret = 0;
				break;
			}
			(void) memcpy(tmp_buf, data1->uabc, copy_len);
			tmp_buf = tmp_buf + copy_len;
			bytes_to_copy = buf_size - copy_len;
			mp1 = mp->b_cont;
			mp1 = mp1->b_cont;
			copy_len1 = copy_len;
			
			while (mp1) {
				copy_len = MBLKL(mp1);
				if (mp1->b_cont == NULL) {
					copy_len = MBLKL(mp1) - 4;
				}
				next_data = (qede_nvram_data_t *) mp1->b_rptr;
				if (copy_len > bytes_to_copy){
					(void) memcpy(tmp_buf, next_data->uabc,
					    bytes_to_copy);
					qede->copy_len = qede->copy_len + 
					    bytes_to_copy;
					ret = 0;
					break;
				}
				(void) memcpy(tmp_buf, next_data->uabc, 
				    copy_len);
				qede->copy_len = qede->copy_len + copy_len;
				tmp_buf = tmp_buf + copy_len;
				copy_len = copy_len1 + copy_len;
				bytes_to_copy = bytes_to_copy - copy_len;
				mp1 = mp1->b_cont;
			}
			qede->nvm_buf = tmp_buf;
			ret = 0;
			break;

		case STOP_NVM_WRITE:
			//qede->nvm_buf = tmp_buf;
			ret = 0;
			break;
		case READ_BUF:
			tmp_buf = (uint8_t *)qede->nvm_buf_start;
			for(i = 0; i < size ; i++){
				cmn_err(CE_NOTE, 
				    "buff (%d) : %d\n", i, *tmp_buf);
				tmp_buf ++;
			}
			ret = 0;
			break;
		}
		break;
	case QEDE_NVRAM_CMD_PUT_FILE_DATA:
		tmp_buf = qede->nvm_buf_start;	
		ret = ecore_mcp_nvm_write(edev, ECORE_PUT_FILE_DATA,
			  addr, tmp_buf, size);
		kmem_free(qede->nvm_buf_start, size);
		//OSAL_FREE(edev, tmp_buf);
		cmn_err(CE_NOTE, "total size = %x, copied size = %x\n",
		    qede->nvm_buf_size, qede->copy_len);
		tmp_buf = NULL;
		qede->nvm_buf = NULL;
		qede->nvm_buf_start = NULL;
		ret = 0;
		break;

	case QEDE_NVRAM_CMD_SET_SECURE_MODE:
		ret = ecore_mcp_nvm_set_secure_mode(edev, addr);
		break;

	case QEDE_NVRAM_CMD_DEL_FILE:
		ret = ecore_mcp_nvm_del_file(edev, addr);
		break;

	case QEDE_NVRAM_CMD_PUT_FILE_BEGIN:
		ret = ecore_mcp_nvm_put_file_begin(edev, addr);
		break;

	case QEDE_NVRAM_CMD_GET_NVRAM_RESP:
		buf = kmem_zalloc(size, KM_SLEEP);
		ret = ecore_mcp_nvm_resp(edev, buf);
		(void)memcpy(data1->uabc, buf, size);
		kmem_free(buf, size);
		break;

	default:
		cmn_err(CE_WARN, 
		    "wrong command in NVRAM read/write from application\n");
		break;
	}
	return (DDI_SUCCESS);	
}

static int
qede_get_func_info(qede_t *qede, void *data)
{
	qede_link_output_t link_op;
	qede_func_info_t func_info;
	qede_ioctl_data_t *data1 = (qede_ioctl_data_t *)data;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *hwfn;
	struct ecore_mcp_link_params params;
	struct ecore_mcp_link_state link;
	
	hwfn = &edev->hwfns[0];

	if(hwfn == NULL){
		cmn_err(CE_WARN, "(%s) : cannot acquire hwfn\n",
		    __func__);
		return (DDI_FAILURE);
	}
	memcpy(&params, &hwfn->mcp_info->link_input, sizeof(params));
	memcpy(&link, &hwfn->mcp_info->link_output, sizeof(link));

	if(link.link_up) {
		link_op.link_up = true;
	}

	link_op.supported_caps = SUPPORTED_FIBRE;
	if(params.speed.autoneg) {
		link_op.supported_caps |= SUPPORTED_Autoneg;
	}
	
	if(params.pause.autoneg ||
	    (params.pause.forced_rx && params.pause.forced_tx)) {
		link_op.supported_caps |= SUPPORTED_Asym_Pause;
	}

	if (params.pause.autoneg || params.pause.forced_rx ||
	     params.pause.forced_tx) {
		link_op.supported_caps |= SUPPORTED_Pause;
	}
	
	if (params.speed.advertised_speeds &
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_1G) {
		link_op.supported_caps |= SUPPORTED_1000baseT_Half |
	    	    SUPPORTED_1000baseT_Full;
	}

	if (params.speed.advertised_speeds &
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_10G) {
		link_op.supported_caps |= SUPPORTED_10000baseKR_Full;
	}
	
	if (params.speed.advertised_speeds &
	    NVM_CFG1_PORT_DRV_LINK_SPEED_40G) {
		link_op.supported_caps |= SUPPORTED_40000baseLR4_Full;
	}
	
	link_op.advertised_caps = link_op.supported_caps;

	if(link.link_up) {
		link_op.speed = link.speed;
	} else {
		link_op.speed = 0;
	}

	link_op.duplex = DUPLEX_FULL;
	link_op.port = PORT_FIBRE;
	
	link_op.autoneg = params.speed.autoneg;

	/* Link partner capabilities */
	if (link.partner_adv_speed &
	    ECORE_LINK_PARTNER_SPEED_1G_HD) {
		link_op.lp_caps |= SUPPORTED_1000baseT_Half;
	}
	
	if (link.partner_adv_speed &
	    ECORE_LINK_PARTNER_SPEED_1G_FD) {
		link_op.lp_caps |= SUPPORTED_1000baseT_Full;
	}
	
	if (link.partner_adv_speed &
	    ECORE_LINK_PARTNER_SPEED_10G) {
		link_op.lp_caps |= SUPPORTED_10000baseKR_Full;
	}
	
	if (link.partner_adv_speed &
	    ECORE_LINK_PARTNER_SPEED_20G) {
		link_op.lp_caps |= SUPPORTED_20000baseKR2_Full;
	}
	
	if (link.partner_adv_speed &
	    ECORE_LINK_PARTNER_SPEED_40G) {
		link_op.lp_caps |= SUPPORTED_40000baseLR4_Full;
	}
	
	if (link.an_complete) {
		link_op.lp_caps |= SUPPORTED_Autoneg;
	}
	
	if (link.partner_adv_pause) {
		link_op.lp_caps |= SUPPORTED_Pause;
	}
	
	if (link.partner_adv_pause == ECORE_LINK_PARTNER_ASYMMETRIC_PAUSE ||
	    link.partner_adv_pause == ECORE_LINK_PARTNER_BOTH_PAUSE) {
		link_op.lp_caps |= SUPPORTED_Asym_Pause;
	}

	func_info.supported = link_op.supported_caps;
	func_info.advertising = link_op.advertised_caps;
	func_info.speed = link_op.speed;
	func_info.duplex = link_op.duplex;
	func_info.port = qede->pci_func & 0x1;
	func_info.autoneg = link_op.autoneg;	
	
	(void) memcpy(data1->uabc, &func_info, sizeof(qede_func_info_t));
	
	return (0);
}

static int 
qede_do_ioctl(qede_t *qede, queue_t *q, mblk_t *mp)
{
	qede_ioctl_data_t *up_data;
	qede_driver_info_t driver_info;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *hwfn;
	struct ecore_ptt *ptt = NULL;
	struct mcp_file_att attrib;
	uint32_t flash_size;
	uint32_t mcp_resp, mcp_param, txn_size;
	uint32_t cmd, size, ret = 0;
	uint64_t off;
	int * up_data1;
	void * ptr;
	mblk_t *mp1 = mp;
	char mac_addr[32];
	
	up_data = (qede_ioctl_data_t *)(mp->b_cont->b_rptr);
	
	cmd = up_data->cmd;
	off = up_data->off;
	size = up_data->size;
	
	switch (cmd) {
	case QEDE_DRV_INFO:
		hwfn = &edev->hwfns[0]; 
		ptt = ecore_ptt_acquire(hwfn);
	
		snprintf(driver_info.drv_name, MAX_QEDE_NAME_LEN, "%s", "qede");
		snprintf(driver_info.drv_version, QEDE_STR_SIZE, 
		    "v:%s", qede->version);
		snprintf(driver_info.mfw_version, QEDE_STR_SIZE, 
		    "%s", qede->versionMFW);
		snprintf(driver_info.stormfw_version, QEDE_STR_SIZE, 
		    "%s", qede->versionFW);
		snprintf(driver_info.bus_info, QEDE_STR_SIZE, 
		    "%s", qede->bus_dev_func);


		/* 
		 * calling ecore_mcp_nvm_rd_cmd to find the flash length, i
		 * 0x08 is equivalent of NVM_TYPE_MFW_TRACE1
		 */
		ecore_mcp_get_flash_size(hwfn, ptt, &flash_size);
		driver_info.eeprom_dump_len = flash_size;	
		(void) memcpy(up_data->uabc, &driver_info, 
		    sizeof (qede_driver_info_t));
		up_data->size = sizeof (qede_driver_info_t);

		ecore_ptt_release(hwfn, ptt);
		break;

	case QEDE_RD_PCICFG:
		ret = qede_ioctl_pcicfg_rd(qede, off, up_data->uabc, size);
		break;

	case QEDE_WR_PCICFG:
		ret = qede_ioctl_pcicfg_wr(qede, off, up_data, size);
		break;
	
	case QEDE_RW_REG:
		ret = qede_ioctl_rd_wr_reg(qede, (void *)up_data);
	       	break;

	case QEDE_RW_NVRAM:
		ret = qede_ioctl_rd_wr_nvram(qede, mp1);
		break;

	case QEDE_FUNC_INFO:
		ret = qede_get_func_info(qede, (void *)up_data);
		break;

	case QEDE_MAC_ADDR:
		snprintf(mac_addr, sizeof(mac_addr),
			"%02x:%02x:%02x:%02x:%02x:%02x", 
			qede->ether_addr[0], qede->ether_addr[1],
			qede->ether_addr[2], qede->ether_addr[3],
			qede->ether_addr[4], qede->ether_addr[5]);
		(void) memcpy(up_data->uabc, &mac_addr, sizeof(mac_addr));
		break;

	}
	//if (cmd == QEDE_RW_NVRAM) {
	//	miocack (q, mp, (sizeof(qede_ioctl_data_t)), 0);
	//	return IOC_REPLY;
	//}
	miocack (q, mp, (sizeof(qede_ioctl_data_t)), ret);
	//miocack (q, mp, 0, ret);
	return (IOC_REPLY);
}

static void
qede_ioctl(qede_t *qede, int cmd, queue_t *q, mblk_t *mp)
{
	void *ptr;

	switch(cmd) {
	case QEDE_CMD:
		(void) qede_do_ioctl(qede, q, mp);
		break;
	default :
		cmn_err(CE_WARN, "qede ioctl command %x not supported\n", cmd);
		break;
	}
	return;
}
enum ioc_reply
qede_loopback_ioctl(qede_t *qede, queue_t *wq, mblk_t *mp,
    struct iocblk *iocp)
{
	lb_info_sz_t *lb_info_size;
	lb_property_t *lb_prop;
	uint32_t *lb_mode;
	int cmd;

	/*
	 * Validate format of ioctl
	 */
	if(mp->b_cont == NULL) {
		return IOC_INVAL;
	}
	
	cmd = iocp->ioc_cmd;

	switch(cmd) {
	default:
		qede_print("!%s(%d): unknown ioctl command %x\n",
		    __func__, qede->instance, cmd);
		return IOC_INVAL;
	case LB_GET_INFO_SIZE:
		if (iocp->ioc_count != sizeof(lb_info_sz_t)) {
			qede_info(qede, "error: ioc_count %d, sizeof %d",
			    iocp->ioc_count,  sizeof(lb_info_sz_t));
			return IOC_INVAL;
		}
		lb_info_size = (void *)mp->b_cont->b_rptr;
		*lb_info_size = sizeof(loopmodes);
		return IOC_REPLY;
	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes)) {
			qede_info(qede, "error: iocp->ioc_count %d, sizepof %d",
			    iocp->ioc_count,  sizeof (loopmodes));
			return (IOC_INVAL);
		}
		lb_prop = (void *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lb_prop, sizeof (loopmodes));
		return IOC_REPLY;
	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t)) {
			qede_info(qede, "iocp->ioc_count %d, sizeof : %d\n",
			    iocp->ioc_count, sizeof (uint32_t));
			return (IOC_INVAL);
		}
		lb_mode = (void *)mp->b_cont->b_rptr;
		*lb_mode = qede->loop_back_mode;
		return IOC_REPLY;
	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t)) {
			qede_info(qede, "iocp->ioc_count %d, sizeof : %d\n",
			    iocp->ioc_count, sizeof (uint32_t));
			return (IOC_INVAL);
		}
		lb_mode = (void *)mp->b_cont->b_rptr;
		return (qede_set_loopback_mode(qede,*lb_mode));
	}
}

static void
qede_mac_ioctl(void *    arg,
               queue_t * wq,
               mblk_t *  mp)
{
	int err, cmd;
    	qede_t * qede = (qede_t *)arg;
    	struct iocblk *iocp = (struct iocblk *) (uintptr_t)mp->b_rptr;
    	enum ioc_reply status = IOC_DONE;
    	boolean_t need_privilege = B_TRUE;

	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	mutex_enter(&qede->drv_lock);
	if ((qede->qede_state == QEDE_STATE_SUSPENDING) ||
	   (qede->qede_state == QEDE_STATE_SUSPENDED)) {
		mutex_exit(&qede->drv_lock);
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	switch(cmd) {
		case QEDE_CMD:
			break;
		case LB_GET_INFO_SIZE:
		case LB_GET_INFO:
		case LB_GET_MODE:
			need_privilege = B_FALSE;
		case LB_SET_MODE:
			break;
		default:
			qede_print("!%s(%d) unknown ioctl command %x\n",
			    __func__, qede->instance, cmd);
			miocnak(wq, mp, 0, EINVAL);
			mutex_exit(&qede->drv_lock);
			return;
	}
	
	if(need_privilege) {
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if(err){
			qede_info(qede, "secpolicy() failed");
			miocnak(wq, mp, 0, err);
		       	mutex_exit(&qede->drv_lock);
			return;
		}
	}

	switch (cmd) {
		default:
			qede_print("!%s(%d) : unknown ioctl command %x\n", 
			    __func__, qede->instance, cmd);
			status = IOC_INVAL;
			mutex_exit(&qede->drv_lock);
			return;
		case LB_GET_INFO_SIZE:
		case LB_GET_INFO:
		case LB_GET_MODE:
		case LB_SET_MODE:
			status = qede_loopback_ioctl(qede, wq, mp, iocp);
			break;
		case QEDE_CMD:
			qede_ioctl(qede, cmd, wq, mp);
			status = IOC_DONE; 
			break;
	}

	switch(status){
		default:
			qede_print("!%s(%d) : invalid status from ioctl",
			    __func__,qede->instance);
			break;
		case IOC_DONE:
			/*
			 * OK, Reply already sent
			 */
			
			break;
		case IOC_REPLY:
			mp->b_datap->db_type = iocp->ioc_error == 0 ?
				M_IOCACK : M_IOCNAK;
			qreply(wq, mp);
			break;
		case IOC_INVAL:
			mutex_exit(&qede->drv_lock);
			//miocack(wq, mp, 0, 0);
			miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
			    EINVAL : iocp->ioc_error); 
			return; 
	}
	mutex_exit(&qede->drv_lock);
}

extern ddi_dma_attr_t qede_buf2k_dma_attr_txbuf;
extern ddi_dma_attr_t qede_dma_attr_rxbuf;
extern ddi_dma_attr_t qede_dma_attr_desc;

static boolean_t
qede_mac_get_capability(void *arg,
	mac_capab_t capability,
	void *      cap_data)
{
 	qede_t * qede = (qede_t *)arg;
	uint32_t *txflags = cap_data;
	boolean_t ret = B_FALSE;

	switch (capability) {
	case MAC_CAPAB_HCKSUM: {
		u32 *tx_flags = cap_data;
		/*
		 * Check if checksum is enabled on
		 * tx and advertise the cksum capab
		 * to mac layer accordingly. On Rx
		 * side checksummed packets are
		 * reveiced anyway
		 */
		qede_info(qede, "%s tx checksum offload",
		    (qede->checksum == DEFAULT_CKSUM_OFFLOAD) ?
		    "Enabling":
		    "Disabling");

		if (qede->checksum != DEFAULT_CKSUM_OFFLOAD) {
			ret = B_FALSE;
			break;
		}
                /*
                 * Hardware does not support ICMPv6 checksumming. Right now the
                 * GLDv3 doesn't provide us a way to specify that we don't
                 * support that. As such, we cannot indicate
                 * HCKSUM_INET_FULL_V6.
                 */

		*tx_flags = HCKSUM_INET_FULL_V4 |
		    HCKSUM_IPHDRCKSUM;
		ret = B_TRUE;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = (mac_capab_lso_t *)cap_data;

		qede_info(qede, "%s large segmentation offload",
		    qede->lso_enable ? "Enabling": "Disabling");
		if (qede->lso_enable) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			cap_lso->lso_basic_tcp_ipv4.lso_max = QEDE_LSO_MAXLEN;
			ret = B_TRUE;
		}
		break;
	}
	case MAC_CAPAB_RINGS: {
#ifndef NO_CROSSBOW
		mac_capab_rings_t *cap_rings = cap_data;
#ifndef ILLUMOS
		cap_rings->mr_version = MAC_RINGS_VERSION_1;
#endif

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
#ifndef ILLUMOS
			cap_rings->mr_flags = MAC_RINGS_VLAN_TRANSPARENT;
#endif
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			//cap_rings->mr_rnum = 1; /* qede variable */
			cap_rings->mr_rnum = qede->num_fp; /* qede variable */
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = qede_fill_ring;
			cap_rings->mr_gget = qede_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
#ifndef	ILLUMOS
			cap_rings->mr_ggetringtc = NULL;
#endif
			ret = B_TRUE;
			break;
		case MAC_RING_TYPE_TX:
#ifndef ILLUMOS
			cap_rings->mr_flags = MAC_RINGS_VLAN_TRANSPARENT;
#endif
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			//cap_rings->mr_rnum = 1;
			cap_rings->mr_rnum = qede->num_fp;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = qede_fill_ring;
			cap_rings->mr_gget = qede_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
#ifndef	ILLUMOS
			cap_rings->mr_ggetringtc = NULL;
#endif
			ret = B_TRUE;
			break;
		default:
			ret = B_FALSE;
			break;
		}
#endif
		break; /* CASE MAC_CAPAB_RINGS */
	}
#ifdef ILLUMOS
        case MAC_CAPAB_TRANSCEIVER: {
                mac_capab_transceiver_t *mct = cap_data;

                mct->mct_flags = 0;
                mct->mct_ntransceivers = qede->edev.num_hwfns;
                mct->mct_info = qede_transceiver_info;
                mct->mct_read = qede_transceiver_read;

                ret = B_TRUE;
                break;
        }
#endif
	default:
		break;
	}

    return (ret);
}

int
qede_configure_link(qede_t *qede, bool op);

static int
qede_mac_set_property(void *        arg,
                              const char *  pr_name,
                              mac_prop_id_t pr_num,
                              uint_t        pr_valsize,
                              const void *  pr_val)
{
	qede_t * qede = (qede_t *)arg;
	struct ecore_mcp_link_params *link_params;
	struct ecore_dev *edev = &qede->edev;
	struct ecore_hwfn *hwfn;
	int ret_val = 0, i;
	uint32_t option;

	mutex_enter(&qede->gld_lock);
	switch (pr_num)
	{
        case MAC_PROP_MTU:
                bcopy(pr_val, &option, sizeof (option));

                if(option == qede->mtu) {
                        ret_val = 0;
                        break;
                }
                if ((option != DEFAULT_JUMBO_MTU) &&
                   (option != DEFAULT_MTU)) {
                        ret_val = EINVAL;
                        break;
                }
                if(qede->qede_state == QEDE_STATE_STARTED) {
                        ret_val = EBUSY;
                        break;
                }

                ret_val = mac_maxsdu_update(qede->mac_handle, qede->mtu);
                if (ret_val == 0) {

                        qede->mtu = option;
                        if (option == DEFAULT_JUMBO_MTU) {
                                qede->jumbo_enable = B_TRUE;
			} else {
				qede->jumbo_enable = B_FALSE;
			}

                        hwfn = ECORE_LEADING_HWFN(edev);
                        hwfn->hw_info.mtu = qede->mtu;
                        ret_val = ecore_mcp_ov_update_mtu(hwfn, 
			    hwfn->p_main_ptt,
			    hwfn->hw_info.mtu);
                        if (ret_val != ECORE_SUCCESS) {
                                qede_print("!%s(%d): MTU change %d option %d"
				    "FAILED",
				    __func__,qede->instance, qede->mtu, option);
				break;
			}
                        qede_print("!%s(%d): MTU changed  %d MTU option"
			    " %d hwfn %d",
			    __func__,qede->instance, qede->mtu, 
			    option, hwfn->hw_info.mtu);
                }
                break;

	case MAC_PROP_EN_10GFDX_CAP:
		hwfn = &edev->hwfns[0];
		link_params = ecore_mcp_get_link_params(hwfn);
		if (*(uint8_t *) pr_val) {
			link_params->speed.autoneg = 0;
			link_params->speed.forced_speed = 10000;
			link_params->speed.advertised_speeds = 
			    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_10G;
			qede->forced_speed_10G = *(uint8_t *)pr_val;
		}
		else {
			memcpy(link_params, 
			    &qede->link_input_params.default_link_params, 
			    sizeof (struct ecore_mcp_link_params));
			qede->forced_speed_10G = *(uint8_t *)pr_val;
		}
		if (qede->qede_state == QEDE_STATE_STARTED) {
			qede_configure_link(qede,1);
		} else {
			mutex_exit(&qede->gld_lock);
			return (0);
		}
		break;
	default:
		ret_val = ENOTSUP;
		break;
	}
	mutex_exit(&qede->gld_lock);
	return (ret_val); 
}

static void
qede_mac_stop(void *arg)
{
    qede_t *qede = (qede_t *)arg;
	int status;

	qede_print("!%s(%d): called",
	    __func__,qede->instance);
	mutex_enter(&qede->drv_lock);
	status = qede_stop(qede);
	if (status != DDI_SUCCESS) {
		qede_print("!%s(%d): qede_stop "
		    "FAILED",
	        __func__,qede->instance);
	}

	mac_link_update(qede->mac_handle, LINK_STATE_UNKNOWN);
	mutex_exit(&qede->drv_lock);
}

static int
qede_mac_start(void *arg)
{
    	qede_t *qede = (qede_t *)arg;
	int status;

	qede_print("!%s(%d): called", __func__,qede->instance);
	if (!mutex_tryenter(&qede->drv_lock)) {
		return (EAGAIN);
	}

	if (qede->qede_state == QEDE_STATE_SUSPENDED) {
		mutex_exit(&qede->drv_lock);
		return (ECANCELED);
	}

	status = qede_start(qede);
	if (status != DDI_SUCCESS) {
		mutex_exit(&qede->drv_lock);
		return (EIO);
	}

	mutex_exit(&qede->drv_lock);

#ifdef	DBLK_DMA_PREMAP
	qede->pm_handle = mac_pmh_tx_get(qede->mac_handle);
#endif
	return (0);
}

static int
qede_mac_get_property(void *arg,
    const char *pr_name,
    mac_prop_id_t pr_num,
    uint_t        pr_valsize,
    void *pr_val)
{
	qede_t *qede = (qede_t *)arg;
	struct ecore_dev *edev = &qede->edev;
	link_state_t    link_state;
	link_duplex_t   link_duplex;
	uint64_t        link_speed;
	link_flowctrl_t link_flowctrl;
	struct qede_link_cfg link_cfg;
	qede_link_cfg_t  *hw_cfg  = &qede->hwinit;
	int ret_val = 0;

	memset(&link_cfg, 0, sizeof (struct qede_link_cfg));
	qede_get_link_info(&edev->hwfns[0], &link_cfg);

	

	switch (pr_num)
	{
	case MAC_PROP_MTU:

		ASSERT(pr_valsize >= sizeof(uint32_t));
		bcopy(&qede->mtu, pr_val, sizeof(uint32_t));
		break;

	case MAC_PROP_DUPLEX:

		ASSERT(pr_valsize >= sizeof(link_duplex_t));
		link_duplex = (qede->props.link_duplex) ?
					  LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		bcopy(&link_duplex, pr_val, sizeof(link_duplex_t));
		break;

	case MAC_PROP_SPEED:

		ASSERT(pr_valsize >= sizeof(link_speed));

		link_speed = (qede->props.link_speed * 1000000ULL);
		bcopy(&link_speed, pr_val, sizeof(link_speed));
	    	break;

	case MAC_PROP_STATUS:

		ASSERT(pr_valsize >= sizeof(link_state_t));

		link_state = (qede->params.link_state) ?
		                        LINK_STATE_UP : LINK_STATE_DOWN;
		bcopy(&link_state, pr_val, sizeof(link_state_t));
		qede_info(qede, "mac_prop_status %d\n", link_state);
		break;	

	case MAC_PROP_AUTONEG:

		*(uint8_t *)pr_val = link_cfg.autoneg;
		break;

	case MAC_PROP_FLOWCTRL:

		ASSERT(pr_valsize >= sizeof(link_flowctrl_t));

/*
 * illumos does not have the notion of LINK_FLOWCTRL_AUTO at this time.
 */
#ifndef	ILLUMOS
		if (link_cfg.pause_cfg & QEDE_LINK_PAUSE_AUTONEG_ENABLE)  {
	            link_flowctrl = LINK_FLOWCTRL_AUTO;
		}
#endif

		if (!(link_cfg.pause_cfg & QEDE_LINK_PAUSE_RX_ENABLE) && 
		    !(link_cfg.pause_cfg & QEDE_LINK_PAUSE_TX_ENABLE)) {
	            link_flowctrl = LINK_FLOWCTRL_NONE;
		}
		if ((link_cfg.pause_cfg & QEDE_LINK_PAUSE_RX_ENABLE) && 
		    !(link_cfg.pause_cfg & QEDE_LINK_PAUSE_TX_ENABLE)) {
	            link_flowctrl = LINK_FLOWCTRL_RX;
	    	}
        	if (!(link_cfg.pause_cfg & QEDE_LINK_PAUSE_RX_ENABLE) && 
		    (link_cfg.pause_cfg & QEDE_LINK_PAUSE_TX_ENABLE)) {
	            link_flowctrl = LINK_FLOWCTRL_TX;
		}
		if ((link_cfg.pause_cfg & QEDE_LINK_PAUSE_RX_ENABLE) && 
		    (link_cfg.pause_cfg & QEDE_LINK_PAUSE_TX_ENABLE)) {
	            link_flowctrl = LINK_FLOWCTRL_BI;
		}

        	bcopy(&link_flowctrl, pr_val, sizeof (link_flowctrl_t));
        	break;

	case MAC_PROP_ADV_10GFDX_CAP:
		*(uint8_t *)pr_val = link_cfg.adv_capab.param_10000fdx;
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		*(uint8_t *)pr_val = qede->forced_speed_10G;
		break;

	case MAC_PROP_PRIVATE:
	default:
		return (ENOTSUP);

	}
		
	return (0);
}

static void
qede_mac_property_info(void *arg,
    const char *pr_name,
    mac_prop_id_t  pr_num, 
    mac_prop_info_handle_t prh)
{
	qede_t *qede = (qede_t *)arg;
	qede_link_props_t *def_cfg = &qede_def_link_props;
	link_flowctrl_t link_flowctrl;


	switch (pr_num)
	{

	case MAC_PROP_STATUS:
	case MAC_PROP_SPEED:
	case MAC_PROP_DUPLEX:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_MTU:

		mac_prop_info_set_range_uint32(prh,
		    MIN_MTU,
		    MAX_MTU);
		break;

	case MAC_PROP_AUTONEG:

		mac_prop_info_set_default_uint8(prh, def_cfg->autoneg);
		break;
 
	case MAC_PROP_FLOWCTRL:

		if (!def_cfg->pause) {
			link_flowctrl = LINK_FLOWCTRL_NONE;
		} else {
			link_flowctrl = LINK_FLOWCTRL_BI;
		}

		mac_prop_info_set_default_link_flowctrl(prh, link_flowctrl);
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	default:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

    }
}

static mac_callbacks_t qede_callbacks =
{
    (
      MC_IOCTL
/*    | MC_RESOURCES */
    | MC_SETPROP
    | MC_GETPROP
    | MC_PROPINFO
    | MC_GETCAPAB
    ),
    qede_mac_stats,
    qede_mac_start,
    qede_mac_stop,
    qede_mac_promiscuous,
    qede_mac_multicast,
    NULL,
#ifndef NO_CROSSBOW
    NULL,
#else
    qede_mac_tx,
#endif
    NULL,	/* qede_mac_resources, */
    qede_mac_ioctl,
    qede_mac_get_capability,
    NULL,
    NULL,
    qede_mac_set_property,
    qede_mac_get_property,
#ifdef MC_PROPINFO
    qede_mac_property_info
#endif
};

boolean_t
qede_gld_init(qede_t *qede)
{
	int status, ret;
	mac_register_t *macp;

	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		cmn_err(CE_NOTE, "%s: mac_alloc() failed\n", __func__);
		return (B_FALSE);
	}

 	macp->m_driver = qede;
	macp->m_dip = qede->dip;
	macp->m_instance = qede->instance;
	macp->m_priv_props = NULL;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
 	macp->m_src_addr = qede->ether_addr;
	macp->m_callbacks = &qede_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = qede->mtu;
	macp->m_margin = VLAN_TAGSZ;
#ifdef	ILLUMOS
	macp->m_v12n = MAC_VIRT_LEVEL1;
#endif

	status = mac_register(macp, &qede->mac_handle);
	if (status != 0) {
		cmn_err(CE_NOTE, "%s: mac_register() failed\n", __func__);
	}

	mac_free(macp);
	if (status == 0) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

boolean_t qede_gld_fini(qede_t * qede)
{
    return (B_TRUE);
}


void qede_link_update(qede_t * qede,
                 link_state_t  state)
{
    mac_link_update(qede->mac_handle, state);
}

