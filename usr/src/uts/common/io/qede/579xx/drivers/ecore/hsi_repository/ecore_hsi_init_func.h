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

#ifndef __ECORE_HSI_INIT_FUNC__
#define __ECORE_HSI_INIT_FUNC__ 
/********************************/
/* HSI Init Functions constants */
/********************************/

/* Number of VLAN priorities */
#define NUM_OF_VLAN_PRIORITIES			8

/* Size of CRC8 lookup table */
#ifndef LINUX_REMOVE
#define CRC8_TABLE_SIZE					256
#endif

/*
 * BRB RAM init requirements
 */
struct init_brb_ram_req
{
	__le32 guranteed_per_tc /* guaranteed size per TC, in bytes */;
	__le32 headroom_per_tc /* headroom size per TC, in bytes */;
	__le32 min_pkt_size /* min packet size, in bytes */;
	__le32 max_ports_per_engine /* min packet size, in bytes */;
	u8 num_active_tcs[MAX_NUM_PORTS] /* number of active TCs per port */;
};


/*
 * ETS per-TC init requirements
 */
struct init_ets_tc_req
{
	u8 use_sp /* if set, this TC participates in the arbitration with a strict priority (the priority is equal to the TC ID) */;
	u8 use_wfq /* if set, this TC participates in the arbitration with a WFQ weight (indicated by the weight field) */;
	__le16 weight /* An arbitration weight. Valid only if use_wfq is set. */;
};

/*
 * ETS init requirements
 */
struct init_ets_req
{
	__le32 mtu /* Max packet size (in bytes) */;
	struct init_ets_tc_req tc_req[NUM_OF_TCS] /* ETS initialization requirements per TC. */;
};



/*
 * NIG LB RL init requirements
 */
struct init_nig_lb_rl_req
{
	__le16 lb_mac_rate /* Global MAC+LB RL rate (in Mbps). If set to 0, the RL will be disabled. */;
	__le16 lb_rate /* Global LB RL rate (in Mbps). If set to 0, the RL will be disabled. */;
	__le32 mtu /* Max packet size (in bytes) */;
	__le16 tc_rate[NUM_OF_PHYS_TCS] /* RL rate per physical TC (in Mbps). If set to 0, the RL will be disabled. */;
};


/*
 * NIG TC mapping for each priority
 */
struct init_nig_pri_tc_map_entry
{
	u8 tc_id /* the mapped TC ID */;
	u8 valid /* indicates if the mapping entry is valid */;
};


/*
 * NIG priority to TC map init requirements
 */
struct init_nig_pri_tc_map_req
{
	struct init_nig_pri_tc_map_entry pri[NUM_OF_VLAN_PRIORITIES];
};


/*
 * QM per-port init parameters
 */
struct init_qm_port_params
{
	u8 active /* Indicates if this port is active */;
	u8 active_phys_tcs /* Vector of valid bits for active TCs used by this port */;
	__le16 num_pbf_cmd_lines /* number of PBF command lines that can be used by this port */;
	__le16 num_btb_blocks /* number of BTB blocks that can be used by this port */;
	__le16 reserved;
};


/*
 * QM per-PQ init parameters
 */
struct init_qm_pq_params
{
	u8 vport_id /* VPORT ID */;
	u8 tc_id /* TC ID */;
	u8 wrr_group /* WRR group */;
	u8 rl_valid /* Indicates if a rate limiter should be allocated for the PQ (0/1) */;
};


/*
 * QM per-vport init parameters
 */
struct init_qm_vport_params
{
	__le32 vport_rl /* rate limit in Mb/sec units. a value of 0 means dont configure. ignored if VPORT RL is globally disabled. */;
	__le16 vport_wfq /* WFQ weight. A value of 0 means dont configure. ignored if VPORT WFQ is globally disabled. */;
	__le16 first_tx_pq_id[NUM_OF_TCS] /* the first Tx PQ ID associated with this VPORT for each TC. */;
};

#endif /* __ECORE_HSI_INIT_FUNC__ */
