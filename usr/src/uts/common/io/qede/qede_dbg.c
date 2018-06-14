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

/*
 * Compliments of Larry W. and qlc team.
 */
void
qede_stacktrace(qede_t *qede)
{
	int depth, i;
	pc_t pcstack[16];
	char *sym;
	ulong_t	off;

	depth = getpcstack(&pcstack[0], 16);

	cmn_err(CE_CONT, "qede(%d): ---------- \n", qede->instance);
	for (i = 0; i < OSAL_MIN_T(int, depth, 16); i++) {
		sym = kobj_getsymname((uintptr_t)pcstack[i], &off);

		if (sym == NULL) {
			cmn_err(CE_CONT, "qede(%d): sym is NULL\n",
			    qede->instance);
		} else {
			cmn_err(CE_CONT, "%s(%d): %s+%lx\n", __func__,
			    qede->instance, sym ? sym : "?", off);
		}
	}
	cmn_err(CE_CONT, "qede(%d): ---------- \n", qede->instance);
}

void
qede_dbg_ipv6_ext_hdr(qede_tx_pktinfo_t *pktinfo, mblk_t *mp)
{
	struct ether_header *eth_hdr = 
	    (struct ether_header *)(void *)mp->b_rptr;
	ipha_t *ip_hdr;
	struct ip6_hdr *ipv6hdr = NULL;

	/* mac header type and len */
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		pktinfo->ether_type = ntohs(eth_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_header);
	} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
		struct ether_vlan_header *vlan_hdr =
		    (struct ether_vlan_header *)(void *)mp->b_rptr;
		pktinfo->ether_type = ntohs(vlan_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_vlan_header);
	}

	ip_hdr = (ipha_t *)(void *)((u8 *)mp->b_rptr + pktinfo->mac_hlen);

	if (IPH_HDR_VERSION(ip_hdr) == IPV6_VERSION) {
		ipv6hdr = (struct ip6_hdr *)(void *)ip_hdr;
		
		if (ipv6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_IPV6) {
			cmn_err(CE_NOTE, "%s: ipv6 extenstion header found !",
			    __func__);
		}
	}
}

char *
qede_get_L4_type(uint16_t parse_flags)
{
	parse_flags = (parse_flags >> PARSING_AND_ERR_FLAGS_L4PROTOCOL_SHIFT)
	    & PARSING_AND_ERR_FLAGS_L4PROTOCOL_MASK;
	if (parse_flags == 1)  {
		return ("TCP");
	} else if (parse_flags == 2) {
		return ("UDP");
	} else {
		return ("UNKNOWN");
	}
}

char *
qede_get_L3_type(uint16_t parse_flags)
{
	parse_flags = (parse_flags >> PARSING_AND_ERR_FLAGS_L3TYPE_SHIFT)
	    & PARSING_AND_ERR_FLAGS_L3TYPE_MASK;
	if (parse_flags == 1) {
		return ("IPv4");
	} else if (parse_flags == 2) {
		return ("IPv6");
	} else {
		return ("UNKNOWN");
	}
}


void
qede_print_vport_params(qede_t *qede,
    struct ecore_sp_vport_update_params *vport_params)
{
	struct ecore_filter_accept_flags *accept_flags;

	accept_flags = &vport_params->accept_flags;

	cmn_err(CE_WARN, "opaque_fid = %d",
		vport_params->opaque_fid);
	cmn_err(CE_WARN, "vport_id = %d",
		vport_params->vport_id);
	cmn_err(CE_WARN, "update_vport_active_rx_flg = %d",
		vport_params->update_vport_active_rx_flg);
	cmn_err(CE_WARN, "vport_active_rx_flg = %d",
		vport_params->vport_active_rx_flg);
	cmn_err(CE_WARN, "update_vport_active_tx_flg = %d",
		vport_params->update_vport_active_tx_flg);
	cmn_err(CE_WARN, "vport_active_tx_flg = %d",
		vport_params->vport_active_tx_flg);
	cmn_err(CE_WARN, "update_inner_vlan_removal_flg = %d",
		vport_params->update_inner_vlan_removal_flg);
	cmn_err(CE_WARN, "inner_vlan_removal_flg = %d",
		vport_params->inner_vlan_removal_flg);
	cmn_err(CE_WARN, "update_default_vlan_enable_flg = %d",
		vport_params->update_default_vlan_enable_flg);
	cmn_err(CE_WARN, "default_vlan_enable_flg = %d",
		vport_params->default_vlan_enable_flg);
	cmn_err(CE_WARN, "update_default_vlan_flg = %d",
		vport_params->update_default_vlan_flg);
	cmn_err(CE_WARN, "default_vlan = %d",
		vport_params->default_vlan);
	cmn_err(CE_WARN, "update_tx_switching_flg = %d",
		vport_params->update_tx_switching_flg);
	cmn_err(CE_WARN, "tx_switching_flg = %d",
		vport_params->tx_switching_flg);
	cmn_err(CE_WARN, "update_approx_mcast_flg = %d",
		vport_params->update_approx_mcast_flg);
	cmn_err(CE_WARN, "update_anti_spoofing_en_flg = %d",
		vport_params->update_anti_spoofing_en_flg);
	cmn_err(CE_WARN, "anti_spoofing_en = %d",
		vport_params->anti_spoofing_en);
	cmn_err(CE_WARN, "update_accept_any_vlan_flg = %d",
		vport_params->update_accept_any_vlan_flg);
	cmn_err(CE_WARN, "accept_any_vlan = %d",
		vport_params->accept_any_vlan);

	cmn_err(CE_WARN, "update_rx_mode_config; = %d",
		accept_flags->update_rx_mode_config);
	cmn_err(CE_WARN, "update_tx_mode_config; = %d",
		accept_flags->update_tx_mode_config);
}

void
qede_dump_bytes(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i += 8, buf+=8) {
		cmn_err(CE_NOTE, 
		    "!%.02x %.02x %.02x %.02x %.02x %.02x %.02x %.02x",
		    buf[i + 0] & 0xff, buf[i + 1] & 0xff,
		    buf[i + 2] & 0xff, buf[i + 3] & 0xff,
		    buf[i + 4] & 0xff, buf[i + 5] & 0xff,
		    buf[i + 6] & 0xff, buf[i + 7] & 0xff);
	}
}

void
qede_dump_single_mblk(qede_t *qede, mblk_t *mp)
{
	int len = MBLKL(mp);
	u8 *buf = mp->b_rptr;
	int i;

	for (i = 0; i < len; i += 8) {
		cmn_err(CE_NOTE, "!%p: %2x %2x %2x %2x %2x %2x %2x %2x",
		    buf, buf[i], buf[i + 1],
		    buf[i + 2], buf[i + 3],
		    buf[i + 4], buf[i + 5],
		    buf[i + 6], buf[i + 7]);
	}
}

void
qede_dump_mblk_chain_bcont_ptr(qede_t *qede, mblk_t *mp)
{
	mblk_t *bp;
	int len, num_mblk = 0;
	int total_len = 0;

	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		len = MBLKL(bp);
		total_len += len;
		num_mblk++;
		
		qede_info(qede, "b_cont bp len %d", len);	
		qede_dump_single_mblk(qede, bp);
	}

	qede_info(qede, "Total b_cont mblks %d, total_len %d",
	    num_mblk, total_len);
}
/*
 * Loop through all data elements in mp
 * and print them
 */
void
qede_dump_mblk_chain_bnext_ptr(qede_t *qede, mblk_t *mp)
{
	mblk_t *bp;
	int len, num_mblk = 0;
	int total_len = 0;

	for (bp = mp; bp != NULL; bp = bp->b_next) {
		len = MBLKL(bp);
		total_len += len;
		num_mblk++;
		
		qede_info(qede, "b_next bp len %d", len);	
	}

	qede_info(qede, "Total b_next mblks %d, total_len %d",
	    num_mblk, total_len);
}

void
qede_print_intr_ctx(qede_intr_context_t *intr_ctx)
{
}

void
qede_print_tx_ring(qede_tx_ring_t *tx_ring)
{
}

void
qede_print_rx_ring(qede_rx_ring_t *rx_ring)
{
}

void
qede_print_fastpath(qede_fastpath_t *fp)
{
}

void
qede_print_qede(qede_t *qede)
{
}

/*
 * This function is called from ecore in the init path
 * just before starting the function
 */
void 
qede_debug_before_pf_start(struct ecore_dev *edev, u8 id)
{
}

void 
qede_debug_after_pf_stop(void *cdev, u8 my_id)
{
}


void 
qede_dump_reg_cqe(struct eth_fast_path_rx_reg_cqe *cqe)
{
	cmn_err(CE_WARN, "qede_dump_reg_cqe");
	cmn_err(CE_WARN, "    pkt_len = %d", LE_16(cqe->pkt_len));
	cmn_err(CE_WARN, "    bd_num = %d", cqe->bd_num);
	cmn_err(CE_WARN, "    len_on_first_bd = %d", 
	    LE_16(cqe->len_on_first_bd));
	cmn_err(CE_WARN, "    placement_offset = %d", cqe->placement_offset);
	cmn_err(CE_WARN, "    vlan_tag = %d", LE_16(cqe->vlan_tag));
	cmn_err(CE_WARN, "    rss_hash = %d", LE_32(cqe->rss_hash));
	cmn_err(CE_WARN, "    pars_flags = %x", 
	    LE_16((uint16_t)cqe->pars_flags.flags));
	cmn_err(CE_WARN, "    tunnel_pars_flags = %x", 
	    cqe->tunnel_pars_flags.flags);
	cmn_err(CE_WARN, "    bitfields = %x", cqe->bitfields);
}

void 
qede_dump_start_lro_cqe(struct eth_fast_path_rx_tpa_start_cqe *cqe)
{
	int i;
	cmn_err(CE_WARN, "qede_dump_start_lro_cqe");
	cmn_err(CE_WARN, "    tpa_agg_index = %d", cqe->tpa_agg_index);
	cmn_err(CE_WARN, "    seg_len = %d", LE_16(cqe->seg_len));
	cmn_err(CE_WARN, "    vlan_tag = %d", LE_16(cqe->vlan_tag));
	cmn_err(CE_WARN, "    rss_hash = %d", LE_32(cqe->rss_hash));
	cmn_err(CE_WARN, "    len_on_first_bd = %d", 
	    LE_16(cqe->len_on_first_bd));
	cmn_err(CE_WARN, "    placement_offset = %d", cqe->placement_offset);
	cmn_err(CE_WARN, "    header_len = %d", cqe->header_len);
	for (i = 0; i < ETH_TPA_CQE_START_LEN_LIST_SIZE; i++)
		cmn_err(CE_WARN, "    ext_bd_len_list[%d] = %d", i, 
		    LE_16(cqe->ext_bd_len_list[i]));
	cmn_err(CE_WARN, "    pars_flags = 0x%x", 
	    LE_16((uint16_t)cqe->pars_flags.flags));
	cmn_err(CE_WARN, "    tunnel_pars_flags = 0x%x", 
	    cqe->tunnel_pars_flags.flags);
	cmn_err(CE_WARN, "    bitfields = 0x%x", cqe->bitfields );
}

void 
qede_dump_cont_lro_cqe(struct eth_fast_path_rx_tpa_cont_cqe *cqe)
{
	int i;
	cmn_err(CE_WARN, "qede_dump_cont_lro_cqe");
	cmn_err(CE_WARN, "    tpa_agg_index = %d", cqe->tpa_agg_index);
	for (i = 0; i < ETH_TPA_CQE_CONT_LEN_LIST_SIZE; i++) {
		cmn_err(CE_WARN, "    len_list[%d] = %d", i, 
		    LE_16(cqe->len_list[i]));
	}
}

void 
qede_dump_end_lro_cqe(struct eth_fast_path_rx_tpa_end_cqe *cqe)
{
	int i;
	cmn_err(CE_WARN, "qede_dump_end_lro_cqe");
	cmn_err(CE_WARN, "    tpa_agg_index = %d", cqe->tpa_agg_index );
	cmn_err(CE_WARN, "    total_packet_len = %d", 
	    LE_16(cqe->total_packet_len));
	cmn_err(CE_WARN, "    num_of_bds = %d", cqe->num_of_bds);
	cmn_err(CE_WARN, "    num_of_coalesced_segs = %d", 
	    LE_16(cqe->num_of_coalesced_segs));
	for (i = 0; i < ETH_TPA_CQE_END_LEN_LIST_SIZE; i++) {
		cmn_err(CE_WARN, "    len_list[%d] = %d", i, 
		    LE_16(cqe->len_list[i]));
	}
	cmn_err(CE_WARN, "    ts_delta = %d", LE_32(cqe->ts_delta));
}
