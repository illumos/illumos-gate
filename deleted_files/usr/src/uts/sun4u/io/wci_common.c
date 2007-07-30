/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/async.h>
#include <sys/cheetahregs.h>

#include <sys/wci_offsets.h>
#include <sys/wci_regs.h>
#include <sys/wci_common.h>

/* busstat-style kstats support */
/* Use predefined strings to name the kstats from this driver. */
#define	WCI_KSTAT_NAME	"%s"
#define	WCI_LPBK_KSTAT_NAME	"%slpbk"
#define	WCI_LINK_KSTAT_NAME	"%slink"
#define	WCI_SFI_KSTAT_NAME	"%ssfi"

#define	EOSTR	"\0"

/*
 * Function prototypes
 */
static void wci_add_misc_kstats(struct wci_common_soft_state *, char *);
static void wci_add_lpbk_kstats(struct wci_common_soft_state *, char *);
static void wci_add_link_kstats(struct wci_common_soft_state *, char *);
static void wci_add_sfi_kstats(struct wci_common_soft_state *, char *);

static void wci_add_misc_pic_kstats(char *);
static void wci_add_lpbk_pic_kstats(char *);
static void wci_add_link_pic_kstats(char *);
static void wci_add_sfi_pic_kstats(char *);

static int wci_misc_kstat_update(kstat_t *, int);
static int wci_lpbk_kstat_update(kstat_t *, int);
static int wci_link_kstat_update(kstat_t *, int);
static int wci_sfi_kstat_update(kstat_t *, int);

/* this varible is used in wci_link_kstat_update() routine */
static int wci_link_kstat_modlen;

/* Wildcat ECC error handling support */
void
wci_log_ce_error(struct async_flt *ecc, char *unum)
{
	uint64_t t_afsr;
	uint64_t t_afar;
	ushort_t id = ecc->flt_bus_id;
	ushort_t inst = ecc->flt_inst;

	t_afsr = ecc->flt_stat;
	t_afar = ecc->flt_addr;

	if (t_afsr == RA_ECC_MTAG_CE) {
		cmn_err(CE_CONT, "WCI%d CE RA MTAG ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == RA_ECC_DATA_CE) {
		cmn_err(CE_CONT, "WCI%d CE RA DATA ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == HA_ECC_MTAG_CE) {
		cmn_err(CE_CONT, "WCI%d CE HA MTAG ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == HA_ECC_DATA_CE) {
		cmn_err(CE_CONT, "WCI%d CE HA DATA ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == SA_ECC_MTAG_CE) {
		cmn_err(CE_CONT, "WCI%d CE SA MTAG ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == SA_ECC_DATA_CE) {
		cmn_err(CE_CONT, "WCI%d CE SA DATA ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == CA_ECC_MTAG_CE) {
		cmn_err(CE_CONT, "WCI%d CE CA MTAG ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
	if (t_afsr == CA_ECC_DATA_CE) {
		cmn_err(CE_CONT, "WCI%d CE CA DATA ERROR: "
		    "AFSR 0x%08x.%08x AFAR 0x%08x.%08x MemMod %s "
		    "Id %d\n",
		    inst, (uint32_t)(t_afsr>>32), (uint32_t)t_afsr,
		    (uint32_t)(t_afar>>32), (uint32_t)t_afar, unum, id);
	}
}


/*
 * WCI Performance Events.
 *
 * For each pic there is an array of event-names and event-masks.
 * The num of events in this array is WCI_NUM_EVENTS + 1
 * (num of WCI events) + (clear_pic event)
 *
 */

/* Misc Counter */
static wci_event_mask_t
    wci_misc_events_arr[WCI_NUM_PICS][WCI_MISC_NUM_EVENTS] = {
/* pic 0 */
	{
		/* SFI agent */
		{"sfi_sfi_histogram0", SFI_SFI_HISTOGRAM0},
		{"sfi_sfi_histogram1", SFI_SFI_HISTOGRAM1},
		{"sfi_atransid_alloc_1", SFI_ATRANSID_ALLOC_1},
		{"sfi_atransid_alloc_4", SFI_ATRANSID_ALLOC_4},
		{"sfi_atransid_alloc_8", SFI_ATRANSID_ALLOC_8},
		{"sfi_atransid_alloc_10", SFI_ATRANSID_ALLOC_10},
		{"sfi_atransid_alloc_12", SFI_ATRANSID_ALLOC_12},
		{"sfi_atransid_dealloc", SFI_ATRANSID_DEALLOC},
		{"sfi_targid_alloc_0", SFI_TARGID_ALLOC_0},
		{"sfi_targid_alloc_2", SFI_TARGID_ALLOC_2},
		{"sfi_targid_alloc_8", SFI_TARGID_ALLOC_8},
		{"sfi_targid_dealloc", SFI_TARGID_DEALLOC},
		{"sfi_p0_req_valid", SFI_P0_REQ_VALID},
		{"sfi_p1_req_valid", SFI_P1_REQ_VALID},
		{"sfi_p2_req_valid", SFI_P2_REQ_VALID},
		{"sfi_p3_req_valid", SFI_P3_REQ_VALID},
		{"sfi_p4_req_valid", SFI_P4_REQ_VALID},
		{"sfi_p5_req_valid", SFI_P5_REQ_VALID},
		{"sfi_p6_req_valid", SFI_P6_REQ_VALID},
		{"sfi_p7_req_valid", SFI_P7_REQ_VALID},
		{"sfi_p8_req_valid", SFI_P8_REQ_VALID},
		{"sfi_p9_req_valid", SFI_P9_REQ_VALID},
		{"sfi_p10_req_valid", SFI_P10_REQ_VALID},
		{"sfi_p11_req_valid", SFI_P11_REQ_VALID},
		{"sfi_p12_req_valid", SFI_P12_REQ_VALID},
		{"sfi_p0_grant", SFI_P0_GRANT},
		{"sfi_p1_grant", SFI_P1_GRANT},
		{"sfi_p2_grant", SFI_P2_GRANT},
		{"sfi_p3_grant", SFI_P3_GRANT},
		{"sfi_p4_grant", SFI_P4_GRANT},
		{"sfi_p5_grant", SFI_P5_GRANT},
		{"sfi_p6_grant", SFI_P6_GRANT},
		{"sfi_p7_grant", SFI_P7_GRANT},
		{"sfi_p8_grant", SFI_P8_GRANT},
		{"sfi_p9_grant", SFI_P9_GRANT},
		{"sfi_p10_grant", SFI_P10_GRANT},
		{"sfi_p11_grant", SFI_P11_GRANT},
		{"sfi_p12_grant", SFI_P12_GRANT},
		{"sfi_sfi_pull_req", SFI_SFI_PULL_REQ},
		{"sfi_sfi_pull_grant", SFI_SFI_PULL_GRANT},
		/* cnt0 duration */
		{"sfi_atransid_dealloc_duration",
		    SFI_ATRANSID_DEALLOC_DURATION},
		{"sfi_targid_dealloc_duration", SFI_TARGID_DEALLOC_DURATION},
		/* DC agent */
		{"dc_dif_output_valid", DC_DIF_OUTPUT_VALID},
		{"dc_sfi_data_grant", DC_SFI_DATA_GRANT},
		/* LC agent */
		{"lc_dif_push", LC_DIF_PUSH},
		{"lc_com_valid_links_dif_full", LC_COM_VALID_LINKS_DIF_FULL},
		{"lc_data_pkt_fr_node", LC_DATA_PKT_FR_NODE},
		{"lc_sfi_data_cancle", LC_SFI_DATA_CANCEL},
		/* SFQ agent */
		{"sfq_piq_push", SFQ_PIQ_PUSH},
		{"sfq_piq_pop", SFQ_PIQ_POP},
		{"sfq_niq_push", SFQ_NIQ_PUSH},
		{"sfq_niq_pop", SFQ_NIQ_POP},
		{"sfq_siq_push", SFQ_SIQ_PUSH},
		{"sfq_siq_pop", SFQ_SIQ_POP},
		/* HLI agent */
		{"hli_slq_push", HLI_SLQ_PUSH},
		{"hli_slq_pop", HLI_SLQ_POP},
		{"hli_chq_push", HLI_CHQ_PUSH},
		{"hli_chq_pop", HLI_CHQ_POP},
		{"hli_phq_push", HLI_PHQ_PUSH},
		{"hli_phq_pop", HLI_PHQ_POP},
		/* Cache Control agent */
		{"cachectl_clust0", CACHECTL_CLUST0},
		{"cachectl_clust1", CACHECTL_CLUST1},
		/* pic0, cluster event 0 */
		{"cachectl_clust0_cwr", CACHECTL_CLUST_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_crd", CACHECTL_CLUST_CRD | CACHECTL_CLUST0},
		{"cachectl_clust0_crd_cwr",
		    CACHECTL_CLUST_CRD_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_at", CACHECTL_CLUST_AT | CACHECTL_CLUST0},
		{"cachectl_clust0_at_cwr",
		    CACHECTL_CLUST_AT_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_at_crd",
		    CACHECTL_CLUST_AT_CRD | CACHECTL_CLUST0},
		{"cachectl_clust0_at_crd_cwr",
		    CACHECTL_CLUST_AT_CRD_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_int",
		    CACHECTL_CLUST_INT | CACHECTL_CLUST0},
		{"cachectl_clust0_int_cwr",
		    CACHECTL_CLUST_INT_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_int_crd",
		    CACHECTL_CLUST_INT_CRD | CACHECTL_CLUST0},
		{"cachectl_clust0_int_crd_cwr",
		    CACHECTL_CLUST_INT_CRD_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_int_at",
		    CACHECTL_CLUST_INT_AT | CACHECTL_CLUST0},
		{"cachectl_clust0_int_at_cwr",
		    CACHECTL_CLUST_INT_AT_CWR | CACHECTL_CLUST0},
		{"cachectl_clust0_int_at_crd",
		    CACHECTL_CLUST_INT_AT_CRD | CACHECTL_CLUST0},
		{"cachectl_clust0_int_at_crd_cwr",
		    CACHECTL_CLUST_INT_AT_CRD_CWR | CACHECTL_CLUST0},
		/* pic0, cluster event 1 */
		{"cachectl_clust1_cwr", CACHECTL_CLUST_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_crd", CACHECTL_CLUST_CRD | CACHECTL_CLUST1},
		{"cachectl_clust1_crd_cwr",
		    CACHECTL_CLUST_CRD_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_at",
		    CACHECTL_CLUST_AT | CACHECTL_CLUST1},
		{"cachectl_clust1_at_cwr",
		    CACHECTL_CLUST_AT_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_at_crd",
		    CACHECTL_CLUST_AT_CRD | CACHECTL_CLUST1},
		{"cachectl_clust1_at_crd_cwr",
		    CACHECTL_CLUST_AT_CRD_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_int",
		    CACHECTL_CLUST_INT | CACHECTL_CLUST1},
		{"cachectl_clust1_int_cwr",
		    CACHECTL_CLUST_INT_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_int_crd",
		    CACHECTL_CLUST_INT_CRD | CACHECTL_CLUST1},
		{"cachectl_clust1_int_crd_cwr",
		    CACHECTL_CLUST_INT_CRD_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_int_at",
		    CACHECTL_CLUST_INT_AT | CACHECTL_CLUST1},
		{"cachectl_clust1_int_at_cwr",
		    CACHECTL_CLUST_INT_AT_CWR | CACHECTL_CLUST1},
		{"cachectl_clust1_int_at_crd",
		    CACHECTL_CLUST_INT_AT_CRD | CACHECTL_CLUST1},
		{"cachectl_clust1_int_at_crd_cwr",
		    CACHECTL_CLUST_INT_AT_CRD_CWR | CACHECTL_CLUST1},
		{"cachectl_cache_cyl_used", CACHECTL_CACHE_CYL_USED},
		{"cachectl_lpa2ga_lookup", CACHECTL_LPA2GA_LOOKUP},
		{"cachectl_ga2lpa_access", CACHECTL_GA2LPA_ACCESS},
		{"cachectl_ga2lpa_lookup", CACHECTL_GA2LPA_LOOKUP},
		{"cachectl_ga2lpa_miss", CACHECTL_GA2LPA_MISS},
		{"cachectl_dir_lookup", CACHECTL_DIR_LOOKUP},
		{"cachectl_dir_miss", CACHECTL_DIR_MISS},
		{"cachectl_dir_wrtbk", CACHECTL_DIR_WRTBK},
		{"cachectl_cmmu_access", CACHECTL_CMMU_ACCESS},
		{"cachectl_cmmu_lookup", CACHECTL_CMMU_LOOKUP},
		{"cachectl_csr_lookup", CACHECTL_CSR_LOOKUP},
		{"cachectl_cnt_alwys", CACHECTL_CNT_ALWYS},
		{"cachectl_hag_req_valid", CACHECTL_HAG_REQ_VALID},
		{"cachectl_ciq_req_valid", CACHECTL_CIQ_REQ_VALID},
		{"cachectl_slq_req_valid", CACHECTL_SLQ_REQ_VALID},
		/* Cluster agent */
		{"clust_agent_alloc", CLUSTER_AGENT_ALLOC},
		{"clust_agent_retired", CLUSTER_AGENT_RETIRED},
		{"clust_sfi_grant_rd", CLUSTER_SFI_GRANT_RD},
		{"clust_sfi_grant_wr", CLUSTER_SFI_GRANT_WR},
		{"clust_pull_seen", CLUSTER_PULL_SEEN},
		{"clust_1dc_rcv_ack", CLUSTER_1DC_RCV_ACK},
		{"clust_2dc_snd_ack", CLUSTER_2DC_SND_ACK},
		{"clust_1_cpi_rcv_ack", CLUSTER_1_CPI_RCV_ACK},
		{"clust_2_cpi_rcv_ack", CLUSTER_2_CPI_RCV_ACK},
		{"clust_pkt_que_odd", CLUSTER_PKT_QUE_ODD},
		{"clust_pkt_que_even", CLUSTER_PKT_QUE_EVEN},
		{"clust_pkt_sent_odd", CLUSTER_PKT_SENT_ODD},
		{"clust_pkt_sent_even", CLUSTER_PKT_SENT_EVEN},
		{"clust_hli_req_0", CLUSTER_HLI_REQ_0},
		{"clust_hli_req_1", CLUSTER_HLI_REQ_1},
		{"clust_hli_req_2", CLUSTER_HLI_REQ_2},
		{"clust_hli_req_3", CLUSTER_HLI_REQ_3},
		{"clust_hli_req_4", CLUSTER_HLI_REQ_4},
		{"clust_hli_req_5", CLUSTER_HLI_REQ_5},
		{"clust_hli_grant_0", CLUSTER_HLI_GRANT_0},
		{"clust_hli_grant_1", CLUSTER_HLI_GRANT_1},
		{"clust_hli_grant_2", CLUSTER_HLI_GRANT_2},
		{"clust_hli_grant_3", CLUSTER_HLI_GRANT_3},
		{"clust_hli_grant_4", CLUSTER_HLI_GRANT_4},
		{"clust_hli_grant_5", CLUSTER_HLI_GRANT_5},

		/* cnt 0 duration */
		{"clust_agent_retired_duration",
		    CLUSTER_AGENT_RETIRED | WCI_DURATION_BIT},
		{"clust_pull_seen_duration",
		    CLUSTER_PULL_SEEN | WCI_DURATION_BIT},
		{"clust_1dc_rcv_ack_duration",
		    CLUSTER_1DC_RCV_ACK | WCI_DURATION_BIT},
		{"clust_2dc_snd_ack_duration",
		    CLUSTER_2DC_SND_ACK | WCI_DURATION_BIT},
		{"clust_pkt_sent_odd_duration",
		    CLUSTER_PKT_SENT_ODD | WCI_DURATION_BIT},
		{"clust_pkt_sent_even_duration",
		    CLUSTER_PKT_SENT_EVEN | WCI_DURATION_BIT},
		{"clust_1_cpi_rcv_ack_duration",
		    CLUSTER_1_CPI_RCV_ACK | WCI_DURATION_BIT},
		{"clust_2_cpi_rcv_ack_duration",
		    CLUSTER_2_CPI_RCV_ACK | WCI_DURATION_BIT},
		/* Request agent */
		{"req_agent_alloc", REQ_AGENT_ALLOC},
		{"req_agent_retired", REQ_AGENT_RETIRED},
		{"req_sfi_grant_p2", REQ_SFI_GRANT_P2},
		{"req_1dc_rcv_ack", REQ_1DC_RCV_ACK},
		{"req_2dc_snd_ack", REQ_2DC_SND_ACK},
		{"req_1_cpi_rcv_ack", REQ_1_CPI_RCV_ACK},
		{"req_2_cpi_rcv_ack", REQ_2_CPI_RCV_ACK},
		{"req_pkt_que", REQ_PKT_QUE},
		{"req_pkt_sent", REQ_PKT_SENT},
		{"req_pkt_sent_clust_rd", REQ_PKT_SENT_CLUST_RD},
		{"req_pkt_sent_clust_wr", REQ_PKT_SENT_CLUST_WR},
		{"req_hli_req_0", REQ_HLI_REQ_0},
		{"req_hli_req_1", REQ_HLI_REQ_1},
		{"req_hli_req_2", REQ_HLI_REQ_2},
		{"req_hli_req_3", REQ_HLI_REQ_3},
		{"req_hli_req_4", REQ_HLI_REQ_4},
		{"req_hli_req_5", REQ_HLI_REQ_5},
		{"req_hli_grant_0", REQ_HLI_GRANT_0},
		{"req_hli_grant_1", REQ_HLI_GRANT_1},
		{"req_hli_grant_2", REQ_HLI_GRANT_2},
		{"req_hli_grant_3", REQ_HLI_GRANT_3},
		{"req_hli_grant_4", REQ_HLI_GRANT_4},
		{"req_hli_grant_5", REQ_HLI_GRANT_5},
		{"req_last_reply_rcvd", REQ_LAST_REPLY_RCVD},
		{"req_sent_clust_rd", REQ_SENT_CLUST_RD},
		{"req_sent_clust_wr", REQ_SENT_CLUST_WR},
		{"req_piq_valid", REQ_PIQ_VALID},
		{"req_piq_dispatch", REQ_PIQ_DISPATCH},
		{"req_ciq_valid", REQ_CIQ_VALID},
		{"req_ciq_dispatch", REQ_CIQ_DISPATCH},
		{"req_niq_valid", REQ_NIQ_VALID},
		{"req_niq_dispatch", REQ_NIQ_DISPATCH},
		{"req_numa_bypass_dispatch", REQ_NUMA_BYPASS_DISPATCH},
		/* cnt 0 duration */
		{"req_agent_retired_duration",
		    REQ_AGENT_RETIRED | WCI_DURATION_BIT},
		{"req_1dc_rcv_ack_duration",
		    REQ_1DC_RCV_ACK | WCI_DURATION_BIT},
		{"req_2dc_snd_ack_duration",
		    REQ_2DC_SND_ACK | WCI_DURATION_BIT},
		{"req_1_cpi_rcv_ack_duration",
		    REQ_1_CPI_RCV_ACK | WCI_DURATION_BIT},
		{"req_2_cpi_rcv_ack_duration",
		    REQ_2_CPI_RCV_ACK | WCI_DURATION_BIT},
		{"req_pkt_sent_duration", REQ_PKT_SENT | WCI_DURATION_BIT},
		{"req_last_reply_rcvd_duration",
		    REQ_LAST_REPLY_RCVD | WCI_DURATION_BIT},
		/* Home Agent */
		{"home_agent_alloc", HOME_AGENT_ALLOC},
		{"home_agent_retired", HOME_AGENT_RETIRED},
		{"home_sfi_p8_rd_aux", HOME_SFI_P8_RD_AUX},
		{"home_sfi_p8_rd_main", HOME_SFI_P8_RD_MAIN},
		{"home_sfi_p8_wr", HOME_SFI_P8_WR},
		{"home_sfi_p9_wr", HOME_SFI_P9_WR},
		{"home_sfi_p10_wr", HOME_SFI_P10_WR},
		{"home_1dc_rcv_ack_aux", HOME_1DC_RCV_ACK_AUX},
		{"home_1dc_rcv_ack_main", HOME_1DC_RCV_ACK_MAIN},
		{"home_2dc_snd_ack", HOME_2DC_SND_ACK},
		{"home_sfi_pull_seen", HOME_SFI_PULL_SEEN},
		{"home_last_demrep_sent", HOME_LAST_DEMREP_SENT},
		{"home_comp_pkt_seen", HOME_COMP_PKT_SEEN},
		{"home_hli_req_link_0_a", HOME_HLI_REQ_LINK_0_A},
		{"home_hli_req_link_0_b", HOME_HLI_REQ_LINK_0_B},
		{"home_hli_req_link_1_a", HOME_HLI_REQ_LINK_1_A},
		{"home_hli_req_link_1_b", HOME_HLI_REQ_LINK_1_B},
		{"home_hli_req_link_2_a", HOME_HLI_REQ_LINK_2_A},
		{"home_hli_req_link_2_b", HOME_HLI_REQ_LINK_2_B},
		{"home_hli_req_link_3_a", HOME_HLI_REQ_LINK_3_A},
		{"home_hli_req_link_3_b", HOME_HLI_REQ_LINK_3_B},
		{"home_hli_req_link_4_a", HOME_HLI_REQ_LINK_4_A},
		{"home_hli_req_link_4_b", HOME_HLI_REQ_LINK_4_B},
		{"home_hli_req_link_5_a", HOME_HLI_REQ_LINK_5_A},
		{"home_hli_req_link_5_b", HOME_HLI_REQ_LINK_5_B},
		{"home_hli_grant_link_0_a", HOME_HLI_GRANT_LINK_0_A},
		{"home_hli_grant_link_0_b", HOME_HLI_GRANT_LINK_0_B},
		{"home_hli_grant_link_1_a", HOME_HLI_GRANT_LINK_1_A},
		{"home_hli_grant_link_1_b", HOME_HLI_GRANT_LINK_1_B},
		{"home_hli_grant_link_2_a", HOME_HLI_GRANT_LINK_2_A},
		{"home_hli_grant_link_2_b", HOME_HLI_GRANT_LINK_2_B},
		{"home_hli_grant_link_3_a", HOME_HLI_GRANT_LINK_3_A},
		{"home_hli_grant_link_3_b", HOME_HLI_GRANT_LINK_3_B},
		{"home_hli_grant_link_4_a", HOME_HLI_GRANT_LINK_4_A},
		{"home_hli_grant_link_4_b", HOME_HLI_GRANT_LINK_4_B},
		{"home_hli_grant_link_5_a", HOME_HLI_GRANT_LINK_5_A},
		{"home_hli_grant_link_5_b", HOME_HLI_GRANT_LINK_5_B},
		{"home_blk_cam_hit", HOME_BLK_CAM_HIT},
		{"home_dir_rtned-before_rd_grant",
		    HOME_DIR_RTNED_BEFORE_RD_GRANT},
		{"home_dir_rtned_before_rd_order",
		    HOME_DIR_RTNED_BEFORE_RD_ORDER},
		{"home_dir_rtned_before_rd_data",
		    HOME_DIR_RTNED_BEFORE_RD_DATA},
		{"home_dir_rtned_after_rd_data",
		    HOME_DIR_RTNED_AFTER_RD_DATA},
		{"home_req_home", HOME_REQ_HOME},
		{"home_req_same_box", HOME_REQ_SAME_BOX},
		{"home_ref_data_back_home", HOME_REF_DATA_BACK_HOME},
		{"home_dir_miss_alloc", HOME_DIR_MISS_ALLOC},
		{"home_dir_hit_gi", HOME_DIR_HIT_GI},
		{"home_dir_hit_gs", HOME_DIR_HIT_GS},
		{"home_dir_hit_gm", HOME_DIR_HIT_GM},
		{"home_dir_hit_rto_gm", HOME_DIR_HIT_RTO_GM},
		{"home_dir_hit_rts_gms", HOME_DIR_HIT_RTS_GMS},
		{"home_dir_miss_rts_gi", HOME_DIR_MISS_RTS_GI},
		{"home_dir_miss_rts", HOME_DIR_MISS_RTS},
		{"home_dir_miss_rto_gs_gi", HOME_DIR_MISS_RTO_GS_GI},
		{"home_dir_miss_rto", HOME_DIR_MISS_RTO},
		/* cnt 0 duration */
		{"home_agent_retired_duration",
		    HOME_AGENT_RETIRED | WCI_DURATION_BIT},
		{"home_1dc_rcv_ack_aux_duration",
		    HOME_1DC_RCV_ACK_AUX | WCI_DURATION_BIT},
		{"home_1dc_rcv_ack_main_duration",
		    HOME_1DC_RCV_ACK_MAIN | WCI_DURATION_BIT},
		{"home_2dc_snd_ack_duration",
		    HOME_2DC_SND_ACK | WCI_DURATION_BIT},
		{"home_sfi_pull_seen_duration",
		    HOME_SFI_PULL_SEEN | WCI_DURATION_BIT},
		{"home_comp_pkt_seen_duration",
		    HOME_COMP_PKT_SEEN | WCI_DURATION_BIT},
		/* Slave agent */
		{"slave_agent_alloc", SLAVE_AGENT_ALLOC},
		{"slave_agent_alloc_lpa", SLAVE_AGENT_ALLOC_LPA},
		{"slave_agent_alloc_ga", SLAVE_AGENT_ALLOC_GA},
		{"slave_agent_alloc_h_lpa", SLAVE_AGENT_ALLOC_H_LPA},
		{"slave_agent_alloc_h_ga", SLAVE_AGENT_ALLOC_H_GA},
		{"slave_agent_alloc_h_mlpa", SLAVE_AGENT_ALLOC_H_MLPA},
		{"slave_agent_alloc_h_mga", SLAVE_AGENT_ALLOC_H_MGA},
		{"slave_agent_alloc_h_m", SLAVE_AGENT_ALLOC_H_M},
		{"slave_agent_alloc_h_inv_lpa", SLAVE_AGENT_ALLOC_H_INV_LPA},
		{"slave_agent_alloc_h_inv_ga", SLAVE_AGENT_ALLOC_H_INV_GA},
		{"slave_agent_retired", SLAVE_AGENT_RETIRED},
		{"slave_reply_sent", SLAVE_REPLY_SENT},
		{"slave_sfi_p6_grant_wr", SLAVE_SFI_P6_GRANT_WR},
		{"slave_sfi_p12gt_rlpa", SLAVE_SFI_P12GT_RLPA},
		{"slave_sfi_p12gt_rga", SLAVE_SFI_P12GT_RGA},
		{"slave_sfi_p12gt_rhlpa",
		    SLAVE_SFI_P12GT_RHLPA},
		{"slave_sfi_p12gt_rhga", SLAVE_SFI_P12GT_RHGA},
		{"slave_sfi_p12gt_rhmlpa",
		    SLAVE_SFI_P12GT_RHMLPA},
		{"slave_sfi_p12gt_rhmga",
		    SLAVE_SFI_P12GT_RHMGA},
		{"slave_sfi_p12gt_wr", SLAVE_SFI_P12GT_WR},
		{"slave_1dc_rcv_ack", SLAVE_1DC_RCV_ACK},
		{"slave_2dc_snd_ack", SLAVE_2DC_SND_ACK},
		{"slave_2dc_snd_ack_refl", SLAVE_2DC_SND_ACK_REFL},
		{"slave_4dc_snd_ack", SLAVE_4DC_SND_ACK},
		{"slave_pull_seen", SLAVE_PULL_SEEN},
		{"slave_h_m_ga_not_ownd", SLAVE_H_M_GA_NOT_OWND},
		{"slave_h_m_no_state_change", SLAVE_H_M_NO_STATE_CHANGE},
		{"slave_hli_req_0", SLAVE_HLI_REQ_0},
		{"slave_hli_req_1", SLAVE_HLI_REQ_1},
		{"slave_hli_req_2", SLAVE_HLI_REQ_2},
		{"slave_hli_req_3", SLAVE_HLI_REQ_3},
		{"slave_hli_req_4", SLAVE_HLI_REQ_4},
		{"slave_hli_req_5", SLAVE_HLI_REQ_5},
		{"slave_hli_grant_0", SLAVE_HLI_GRANT_0},
		{"slave_hli_grant_1", SLAVE_HLI_GRANT_1},
		{"slave_hli_grant_2", SLAVE_HLI_GRANT_2},
		{"slave_hli_grant_3", SLAVE_HLI_GRANT_3},
		{"slave_hli_grant_4", SLAVE_HLI_GRANT_4},
		{"slave_hli_grant_5", SLAVE_HLI_GRANT_5},
		/* cnt0 duration */
		{"slave_agent_retired_duration",
		    SLAVE_AGENT_RETIRED | WCI_DURATION_BIT},
		{"slave_1dc_rcv_ack_c0_duration",
		    SLAVE_1DC_RCV_ACK | WCI_DURATION_BIT},
		{"slave_2dc_snd_ack_duration",
		    SLAVE_2DC_SND_ACK | WCI_DURATION_BIT},
		{"slave_pull_seen_duration",
		    SLAVE_PULL_SEEN | WCI_DURATION_BIT},
		{"slave_reply_sent_duration",
		    SLAVE_REPLY_SENT | WCI_DURATION_BIT},
		{"slave_4dc_snd_ack_duration",
		    SLAVE_4DC_SND_ACK | WCI_DURATION_BIT},
		{"clear_pic", MISC_CLEAR_PIC0},
		{EOSTR, 0}
	},

/* pic 1 */
	{
		/* SFI agent */
		{"sfi_sfi_histogram0", SFI_SFI_HISTOGRAM0<<10},
		{"sfi_sfi_histogram1", SFI_SFI_HISTOGRAM1<<10},
		{"sfi_atransid_alloc_1", SFI_ATRANSID_ALLOC_1<<10},
		{"sfi_atransid_alloc_4", SFI_ATRANSID_ALLOC_4<<10},
		{"sfi_atransid_alloc_8", SFI_ATRANSID_ALLOC_8<<10},
		{"sfi_atransid_alloc_10", SFI_ATRANSID_ALLOC_10<<10},
		{"sfi_atransid_alloc_12", SFI_ATRANSID_ALLOC_12<<10},
		{"sfi_atransid_dealloc", SFI_ATRANSID_DEALLOC<<10},
		{"sfi_targid_alloc_0", SFI_TARGID_ALLOC_0<<10},
		{"sfi_targid_alloc_2", SFI_TARGID_ALLOC_2<<10},
		{"sfi_targid_alloc_8", SFI_TARGID_ALLOC_8<<10},
		{"sfi_targid_dealloc", SFI_TARGID_DEALLOC<<10},
		{"sfi_p0_req_valid", SFI_P0_REQ_VALID<<10},
		{"sfi_p1_req_valid", SFI_P1_REQ_VALID<<10},
		{"sfi_p2_req_valid", SFI_P2_REQ_VALID<<10},
		{"sfi_p3_req_valid", SFI_P3_REQ_VALID<<10},
		{"sfi_p4_req_valid", SFI_P4_REQ_VALID<<10},
		{"sfi_p5_req_valid", SFI_P5_REQ_VALID<<10},
		{"sfi_p6_req_valid", SFI_P6_REQ_VALID<<10},
		{"sfi_p7_req_valid", SFI_P7_REQ_VALID<<10},
		{"sfi_p8_req_valid", SFI_P8_REQ_VALID<<10},
		{"sfi_p9_req_valid", SFI_P9_REQ_VALID<<10},
		{"sfi_p10_req_valid", SFI_P10_REQ_VALID<<10},
		{"sfi_p11_req_valid", SFI_P11_REQ_VALID<<10},
		{"sfi_p12_req_valid", SFI_P12_REQ_VALID<<10},
		{"sfi_p0_grant", SFI_P0_GRANT<<10},
		{"sfi_p1_grant", SFI_P1_GRANT<<10},
		{"sfi_p2_grant", SFI_P2_GRANT<<10},
		{"sfi_p3_grant", SFI_P3_GRANT<<10},
		{"sfi_p4_grant", SFI_P4_GRANT<<10},
		{"sfi_p5_grant", SFI_P5_GRANT<<10},
		{"sfi_p6_grant", SFI_P6_GRANT<<10},
		{"sfi_p7_grant", SFI_P7_GRANT<<10},
		{"sfi_p8_grant", SFI_P8_GRANT<<10},
		{"sfi_p9_grant", SFI_P9_GRANT<<10},
		{"sfi_p10_grant", SFI_P10_GRANT<<10},
		{"sfi_p11_grant", SFI_P11_GRANT<<10},
		{"sfi_p12_grant", SFI_P12_GRANT<<10},
		{"sfi_sfi_pull_req", SFI_SFI_PULL_REQ<<10},
		{"sfi_sfi_pull_grant", SFI_SFI_PULL_GRANT<<10},
		/* cnt1 duration  */
		{"sfi_atransid_alloc_1_duration",
		    SFI_ATRANSID_ALLOC_1_DURATION},
		{"sfi_atransid_alloc_4_duration",
		    SFI_ATRANSID_ALLOC_4_DURATION},
		{"sfi_atransid_alloc_8_duration",
		    SFI_ATRANSID_ALLOC_8_DURATION},
		{"sfi_atransid_alloc_10_duration",
		    SFI_ATRANSID_ALLOC_10_DURATION},
		{"sfi_atransid_alloc_12_duration",
		    SFI_ATRANSID_ALLOC_12_DURATION},
		{"sfi_targid_alloc_0_duration",
		    SFI_TARGID_ALLOC_0_DURATION},
		{"sfi_targid_alloc_2_duration",
		    SFI_TARGID_ALLOC_2_DURATION},
		{"sfi_targid_alloc_8_duration",
		    SFI_TARGID_ALLOC_8_DURATION},
		/* DC agent */
		{"dc_dif_output_valid", DC_DIF_OUTPUT_VALID<<10},
		{"dc_sfi_data_grant", DC_SFI_DATA_GRANT<<10},
		/* LC agent */
		{"lc_dif_push", LC_DIF_PUSH<<10},
		{"lc_com_valid_links_dif_full",
		    LC_COM_VALID_LINKS_DIF_FULL<<10},
		{"lc_data_pkt_fr_node", LC_DATA_PKT_FR_NODE<<10},
		{"lc_sfi_data_cancle", LC_SFI_DATA_CANCEL<<10},
		/* SFQ agent */
		{"sfq_piq_push", SFQ_PIQ_PUSH<<10},
		{"sfq_piq_pop", SFQ_PIQ_POP<<10},
		{"sfq_niq_push", SFQ_NIQ_PUSH<<10},
		{"sfq_niq_pop", SFQ_NIQ_POP<<10},
		{"sfq_siq_push", SFQ_SIQ_PUSH<<10},
		{"sfq_siq_pop", SFQ_SIQ_POP<<10},
		/* HLI agent */
		{"hli_slq_push", HLI_SLQ_PUSH<<10},
		{"hli_slq_pop", HLI_SLQ_POP<<10},
		{"hli_chq_push", HLI_CHQ_PUSH<<10},
		{"hli_chq_pop", HLI_CHQ_POP<<10},
		{"hli_phq_push", HLI_PHQ_PUSH<<10},
		{"hli_phq_pop", HLI_PHQ_POP<<10},
		/* Cache Control agent */
		{"cachectl_clust0", CACHECTL_CLUST0<<10},
		{"cachectl_clust1", CACHECTL_CLUST1<<10},
		/* pic1, cluster event 0 */
		{"cachectl_clust0_cwr",
		    (CACHECTL_CLUST_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_crd",
		    (CACHECTL_CLUST_CRD<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_crd_cwr",
		    (CACHECTL_CLUST_CRD_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_at",
		    (CACHECTL_CLUST_AT<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_at_cwr",
		    (CACHECTL_CLUST_AT_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_at_crd",
		    (CACHECTL_CLUST_AT_CRD<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_at_crd_cwr",
		    (CACHECTL_CLUST_AT_CRD_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int",
		    (CACHECTL_CLUST_INT<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_cwr",
		    (CACHECTL_CLUST_INT_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_crd",
		    (CACHECTL_CLUST_INT_CRD<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_crd_cwr",
		    (CACHECTL_CLUST_INT_CRD_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_at",
		    (CACHECTL_CLUST_INT_AT<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_at_cwr",
		    (CACHECTL_CLUST_INT_AT_CWR<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_at_crd",
		    (CACHECTL_CLUST_INT_AT_CRD<<4) | (CACHECTL_CLUST0<<10)},
		{"cachectl_clust0_int_at_crd_cwr",
		    (CACHECTL_CLUST_INT_AT_CRD_CWR<<4) |
		    (CACHECTL_CLUST0<<10)},
		/* pic1, clust event 1 */
		{"cachectl_clust1_cwr",
		    (CACHECTL_CLUST_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_crd",
		    (CACHECTL_CLUST_CRD<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_crd_cwr",
		    (CACHECTL_CLUST_CRD_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_at",
		    (CACHECTL_CLUST_AT<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_at_cwr",
		    (CACHECTL_CLUST_AT_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_at_crd",
		    (CACHECTL_CLUST_AT_CRD<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_at_crd_cwr",
		    (CACHECTL_CLUST_AT_CRD_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int",
		    (CACHECTL_CLUST_INT<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_cwr",
		    (CACHECTL_CLUST_INT_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_crd",
		    (CACHECTL_CLUST_INT_CRD<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_crd_cwr",
		    (CACHECTL_CLUST_INT_CRD_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_at",
		    (CACHECTL_CLUST_INT_AT<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_at_cwr",
		    (CACHECTL_CLUST_INT_AT_CWR<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_at_crd",
		    (CACHECTL_CLUST_INT_AT_CRD<<4) | (CACHECTL_CLUST1<<10)},
		{"cachectl_clust1_int_at_crd_cwr",
		    (CACHECTL_CLUST_INT_AT_CRD_CWR<<4) |
		    (CACHECTL_CLUST1<<10)},
		{"cachectl_cache_cyl_used", CACHECTL_CACHE_CYL_USED<<10},
		{"cachectl_lpa2ga_lookup", CACHECTL_LPA2GA_LOOKUP<<10},
		{"cachectl_ga2lpa_access", CACHECTL_GA2LPA_ACCESS<<10},
		{"cachectl_ga2lpa_lookup", CACHECTL_GA2LPA_LOOKUP<<10},
		{"cachectl_ga2lpa_miss", CACHECTL_GA2LPA_MISS<<10},
		{"cachectl_dir_lookup", CACHECTL_DIR_LOOKUP<<10},
		{"cachectl_dir_miss", CACHECTL_DIR_MISS<<10},
		{"cachectl_dir_wrtbk", CACHECTL_DIR_WRTBK<<10},
		{"cachectl_cmmu_access", CACHECTL_CMMU_ACCESS<<10},
		{"cachectl_cmmu_lookup", CACHECTL_CMMU_LOOKUP<<10},
		{"cachectl_csr_lookup", CACHECTL_CSR_LOOKUP<<10},
		{"cachectl_cnt_alwys", CACHECTL_CNT_ALWYS<<10},
		{"cachectl_hag_req_valid", CACHECTL_HAG_REQ_VALID<<10},
		{"cachectl_ciq_req_valid", CACHECTL_CIQ_REQ_VALID<<10},
		{"cachectl_slq_req_valid", CACHECTL_SLQ_REQ_VALID<<10},
		/* Cluster agent */
		{"clust_agent_alloc", CLUSTER_AGENT_ALLOC<<10},
		{"clust_agent_retired", CLUSTER_AGENT_RETIRED<<10},
		{"clust_sfi_grant_rd", CLUSTER_SFI_GRANT_RD<<10},
		{"clust_sfi_grant_wr", CLUSTER_SFI_GRANT_WR<<10},
		{"clust_pull_seen", CLUSTER_PULL_SEEN<<10},
		{"clust_1dc_rcv_ack", CLUSTER_1DC_RCV_ACK<<10},
		{"clust_2dc_snd_ack", CLUSTER_2DC_SND_ACK<<10},
		{"clust_1_cpi_rcv_ack", CLUSTER_1_CPI_RCV_ACK<<10},
		{"clust_2_cpi_rcv_ack", CLUSTER_2_CPI_RCV_ACK<<10},
		{"clust_pkt_que_odd", CLUSTER_PKT_QUE_ODD<<10},
		{"clust_pkt_que_even", CLUSTER_PKT_QUE_EVEN<<10},
		{"clust_pkt_sent_odd", CLUSTER_PKT_SENT_ODD<<10},
		{"clust_pkt_sent_even", CLUSTER_PKT_SENT_EVEN<<10},
		{"clust_hli_req_0", CLUSTER_HLI_REQ_0<<10},
		{"clust_hli_req_1", CLUSTER_HLI_REQ_1<<10},
		{"clust_hli_req_2", CLUSTER_HLI_REQ_2<<10},
		{"clust_hli_req_3", CLUSTER_HLI_REQ_3<<10},
		{"clust_hli_req_4", CLUSTER_HLI_REQ_4<<10},
		{"clust_hli_req_5", CLUSTER_HLI_REQ_5<<10},
		{"clust_hli_grant_0", CLUSTER_HLI_GRANT_0<<10},
		{"clust_hli_grant_1", CLUSTER_HLI_GRANT_1<<10},
		{"clust_hli_grant_2", CLUSTER_HLI_GRANT_2<<10},
		{"clust_hli_grant_3", CLUSTER_HLI_GRANT_3<<10},
		{"clust_hli_grant_4", CLUSTER_HLI_GRANT_4<<10},
		{"clust_hli_grant_5", CLUSTER_HLI_GRANT_5<<10},
		/* cnt1 duration */
		{"clust_agent_alloc_duration",
		    CLUSTER_AGENT_ALLOC<<10 | WCI_DURATION_BIT},
		{"clust_sfi_grant_wr_duration",
		    CLUSTER_SFI_GRANT_WR<<10 | WCI_DURATION_BIT},
		{"clust_sfi_grant_rd_duration",
		    CLUSTER_SFI_GRANT_RD<<10 | WCI_DURATION_BIT},
		{"clust_1dc_rcv_ack_duration",
		    CLUSTER_1DC_RCV_ACK<<10 | WCI_DURATION_BIT},
		{"clust_pkt_que_odd_duration",
		    CLUSTER_PKT_QUE_ODD<<10 | WCI_DURATION_BIT},
		{"clust_pkt_que_even_duration",
		    CLUSTER_PKT_QUE_EVEN<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_0_duration",
		    CLUSTER_HLI_GRANT_0<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_1_duration",
		    CLUSTER_HLI_GRANT_1<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_2_duration",
		    CLUSTER_HLI_GRANT_2<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_3_duration",
		    CLUSTER_HLI_GRANT_3<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_4_duration",
		    CLUSTER_HLI_GRANT_4<<10 | WCI_DURATION_BIT},
		{"clust_hli_grant_5_duration",
		    CLUSTER_HLI_GRANT_5<<10 | WCI_DURATION_BIT},
		{"clust_1_cpi_rcv_ack_duration",
		    CLUSTER_1_CPI_RCV_ACK<<10 | WCI_DURATION_BIT},
		/* Request agent */
		{"req_agent_alloc", REQ_AGENT_ALLOC<<10},
		{"req_agent_retired", REQ_AGENT_RETIRED<<10},
		{"req_sfi_grant_p2", REQ_SFI_GRANT_P2<<10},
		{"req_1dc_rcv_ack", REQ_1DC_RCV_ACK<<10},
		{"req_2dc_snd_ack", REQ_2DC_SND_ACK<<10},
		{"req_1_cpi_rcv_ack", REQ_1_CPI_RCV_ACK<<10},
		{"req_2_cpi_rcv_ack", REQ_2_CPI_RCV_ACK<<10},
		{"req_pkt_que", REQ_PKT_QUE<<10},
		{"req_pkt_sent", REQ_PKT_SENT<<10},
		{"req_pkt_sent_clust_rd", REQ_PKT_SENT_CLUST_RD<<10},
		{"req_pkt_sent_clust_wr", REQ_PKT_SENT_CLUST_WR<<10},
		{"req_hli_req_0", REQ_HLI_REQ_0<<10},
		{"req_hli_req_1", REQ_HLI_REQ_1<<10},
		{"req_hli_req_2", REQ_HLI_REQ_2<<10},
		{"req_hli_req_3", REQ_HLI_REQ_3<<10},
		{"req_hli_req_4", REQ_HLI_REQ_4<<10},
		{"req_hli_req_5", REQ_HLI_REQ_5<<10},
		{"req_hli_grant_0", REQ_HLI_GRANT_0<<10},
		{"req_hli_grant_1", REQ_HLI_GRANT_1<<10},
		{"req_hli_grant_2", REQ_HLI_GRANT_2<<10},
		{"req_hli_grant_3", REQ_HLI_GRANT_3<<10},
		{"req_hli_grant_4", REQ_HLI_GRANT_4<<10},
		{"req_hli_grant_5", REQ_HLI_GRANT_5<<10},
		{"req_last_reply_rcvd", REQ_LAST_REPLY_RCVD<<10},
		{"req_sent_clust_rd", REQ_SENT_CLUST_RD<<10},
		{"req_sent_clust_wr", REQ_SENT_CLUST_WR<<10},
		{"req_piq_valid", REQ_PIQ_VALID<<10},
		{"req_piq_dispatch", REQ_PIQ_DISPATCH<<10},
		{"req_ciq_valid", REQ_CIQ_VALID<<10},
		{"req_ciq_dispatch", REQ_CIQ_DISPATCH<<10},
		{"req_niq_valid", REQ_NIQ_VALID<<10},
		{"req_niq_dispatch", REQ_NIQ_DISPATCH<<10},
		{"req_numa_bypass_dispatch", REQ_NUMA_BYPASS_DISPATCH<<10},
		/* cnt1 duration */
		{"req_agent_alloc_duration",
		    REQ_AGENT_ALLOC<<10 | WCI_DURATION_BIT},
		{"req_sfi_grant_p2_duration",
		    REQ_SFI_GRANT_P2<<10 | WCI_DURATION_BIT},
		{"req_1dc_rcv_ack_duration",
		    REQ_1DC_RCV_ACK<<10 | WCI_DURATION_BIT},
		{"req_pkt_sent_clust_rd_duration",
		    REQ_PKT_SENT_CLUST_RD<<10 | WCI_DURATION_BIT},
		{"req_1_cpi_rcv_ack_duration",
		    REQ_1_CPI_RCV_ACK<<10 | WCI_DURATION_BIT},
		{"req_pkt_que_duration", REQ_PKT_QUE<<10 | WCI_DURATION_BIT},
		{"req_pkt_sent_duration",
		    REQ_PKT_SENT<<10 | WCI_DURATION_BIT},
		/* Home Agent */
		{"home_agent_alloc", HOME_AGENT_ALLOC<<10},
		{"home_agent_retired", HOME_AGENT_RETIRED<<10},
		{"home_sfi_p8_rd_aux", HOME_SFI_P8_RD_AUX<<10},
		{"home_sfi_p8_rd_main", HOME_SFI_P8_RD_MAIN<<10},
		{"home_sfi_p8_wr", HOME_SFI_P8_WR<<10},
		{"home_sfi_p9_wr", HOME_SFI_P9_WR<<10},
		{"home_sfi_p10_wr", HOME_SFI_P10_WR<<10},
		{"home_1dc_rcv_ack_aux", HOME_1DC_RCV_ACK_AUX<<10},
		{"home_1dc_rcv_ack_main", HOME_1DC_RCV_ACK_MAIN<<10},
		{"home_2dc_snd_ack", HOME_2DC_SND_ACK<<10},
		{"home_sfi_pull_seen", HOME_SFI_PULL_SEEN<<10},
		{"home_last_demrep_sent", HOME_LAST_DEMREP_SENT<<10},
		{"home_comp_pkt_seen", HOME_COMP_PKT_SEEN<<10},
		{"home_hli_req_link_0_a", HOME_HLI_REQ_LINK_0_A<<10},
		{"home_hli_req_link_0_b", HOME_HLI_REQ_LINK_0_B<<10},
		{"home_hli_req_link_1_a", HOME_HLI_REQ_LINK_1_A<<10},
		{"home_hli_req_link_1_b", HOME_HLI_REQ_LINK_1_B<<10},
		{"home_hli_req_link_2_a", HOME_HLI_REQ_LINK_2_A<<10},
		{"home_hli_req_link_2_b", HOME_HLI_REQ_LINK_2_B<<10},
		{"home_hli_req_link_3_a", HOME_HLI_REQ_LINK_3_A<<10},
		{"home_hli_req_link_3_b", HOME_HLI_REQ_LINK_3_B<<10},
		{"home_hli_req_link_4_a", HOME_HLI_REQ_LINK_4_A<<10},
		{"home_hli_req_link_4_b", HOME_HLI_REQ_LINK_4_B<<10},
		{"home_hli_req_link_5_a", HOME_HLI_REQ_LINK_5_A<<10},
		{"home_hli_req_link_5_b", HOME_HLI_REQ_LINK_5_B<<10},
		{"home_hli_grant_link_0_a", HOME_HLI_GRANT_LINK_0_A<<10},
		{"home_hli_grant_link_0_b", HOME_HLI_GRANT_LINK_0_B<<10},
		{"home_hli_grant_link_1_a", HOME_HLI_GRANT_LINK_1_A<<10},
		{"home_hli_grant_link_1_b", HOME_HLI_GRANT_LINK_1_B<<10},
		{"home_hli_grant_link_2_a", HOME_HLI_GRANT_LINK_2_A<<10},
		{"home_hli_grant_link_2_b", HOME_HLI_GRANT_LINK_2_B<<10},
		{"home_hli_grant_link_3_a", HOME_HLI_GRANT_LINK_3_A<<10},
		{"home_hli_grant_link_3_b", HOME_HLI_GRANT_LINK_3_B<<10},
		{"home_hli_grant_link_4_a", HOME_HLI_GRANT_LINK_4_A<<10},
		{"home_hli_grant_link_4_b", HOME_HLI_GRANT_LINK_4_B<<10},
		{"home_hli_grant_link_5_a", HOME_HLI_GRANT_LINK_5_A<<10},
		{"home_hli_grant_link_5_b", HOME_HLI_GRANT_LINK_5_B<<10},
		{"home_blk_cam_hit", HOME_BLK_CAM_HIT<<10},
		{"home_dir_rtned_before_rd_grant",
		    HOME_DIR_RTNED_BEFORE_RD_GRANT<<10},
		{"home_dir_rtned_before_rd_order",
		    HOME_DIR_RTNED_BEFORE_RD_ORDER<<10},
		{"home_dir_rtned_before_rd_data",
		    HOME_DIR_RTNED_BEFORE_RD_DATA<<10},
		{"home_dir_rtned_after_rd_data",
		    HOME_DIR_RTNED_AFTER_RD_DATA<<10},
		{"home_req_home", HOME_REQ_HOME<<10},
		{"home_req_same_box", HOME_REQ_SAME_BOX<<10},
		{"home_ref_data_back_home", HOME_REF_DATA_BACK_HOME<<10},
		{"home_dir_miss_alloc", HOME_DIR_MISS_ALLOC<<10},
		{"home_dir_hit_gi", HOME_DIR_HIT_GI<<10},
		{"home_dir_hit_gs", HOME_DIR_HIT_GS<<10},
		{"home_dir_hit_gm", HOME_DIR_HIT_GM<<10},
		{"home_dir_hit_rto_gm", HOME_DIR_HIT_RTO_GM<<10},
		{"home_dir_hit_rts_gms", HOME_DIR_HIT_RTS_GMS<<10},
		{"home_dir_miss_rts_gi", HOME_DIR_MISS_RTS_GI<<10},
		{"home_dir_miss_rts", HOME_DIR_MISS_RTS<<10},
		{"home_dir_miss_rto_gs_gi", HOME_DIR_MISS_RTO_GS_GI<<10},
		{"home_dir_miss_rto", HOME_DIR_MISS_RTO<<10},
		/* cnt1 duration */
		{"home_agent_alloc_duration",
		    HOME_AGENT_ALLOC<<10 | WCI_DURATION_BIT},
		{"home_sfi_p8_rd_aux_duration",
		    HOME_SFI_P8_RD_AUX<<10 | WCI_DURATION_BIT},
		{"home_sfi_p8_rd_main_duration",
		    HOME_SFI_P8_RD_MAIN<<10 | WCI_DURATION_BIT},
		{"home_1dc_rcv_ack_aux_duration",
		    HOME_1DC_RCV_ACK_AUX<<10 | WCI_DURATION_BIT},
		{"home_1dc_rcv_ack_main_duration",
		    HOME_1DC_RCV_ACK_MAIN<<10 | WCI_DURATION_BIT},
		{"home_sfi_p8_wr_duration",
		    HOME_SFI_P8_WR<<10 | WCI_DURATION_BIT},
		{"home_sfi_p9_wr_duration",
		    HOME_SFI_P9_WR<<10 | WCI_DURATION_BIT},
		{"home_sfi_p10_wr_duration",
		    HOME_SFI_P10_WR<<10 | WCI_DURATION_BIT},
		{"home_last_demrep_sent_duration",
		    HOME_LAST_DEMREP_SENT<<10 | WCI_DURATION_BIT},
		/* Slave agent */
		{"slave_agent_alloc", SLAVE_AGENT_ALLOC<<10},
		{"slave_agent_alloc_lpa", SLAVE_AGENT_ALLOC_LPA<<10},
		{"slave_agent_alloc_ga", SLAVE_AGENT_ALLOC_GA<<10},
		{"slave_agent_alloc_h_lpa", SLAVE_AGENT_ALLOC_H_LPA<<10},
		{"slave_agent_alloc_h_ga", SLAVE_AGENT_ALLOC_H_GA<<10},
		{"slave_agent_alloc_h_mlpa", SLAVE_AGENT_ALLOC_H_MLPA<<10},
		{"slave_agent_alloc_h_mga", SLAVE_AGENT_ALLOC_H_MGA<<10},
		{"slave_agent_alloc_h_m", SLAVE_AGENT_ALLOC_H_M<<10},
		{"slave_agent_alloc_h_inv_lpa",
		    SLAVE_AGENT_ALLOC_H_INV_LPA<<10},
		{"slave_agent_alloc_h_inv_ga",
		    SLAVE_AGENT_ALLOC_H_INV_GA<<10},
		{"slave_agent_retired", SLAVE_AGENT_RETIRED<<10},
		{"slave_reply_sent", SLAVE_REPLY_SENT<<10},
		{"slave_sfi_p6_grant_wr", SLAVE_SFI_P6_GRANT_WR<<10},
		{"slave_sfi_p12gt_rlpa",
		    SLAVE_SFI_P12GT_RLPA<<10},
		{"slave_sfi_p12gt_rga",
		    SLAVE_SFI_P12GT_RGA<<10},
		{"slave_sfi_p12gt_rhlpa",
		    SLAVE_SFI_P12GT_RHLPA<<10},
		{"slave_sfi_p12gt_rhga",
		    SLAVE_SFI_P12GT_RHGA<<10},
		{"slave_sfi_p12gt_rhmlpa",
		    SLAVE_SFI_P12GT_RHMLPA<<10},
		{"slave_sfi_p12gt_rhmga",
		    SLAVE_SFI_P12GT_RHMGA<<10},
		{"slave_sfi_p12gt_wr", SLAVE_SFI_P12GT_WR<<10},
		{"slave_1dc_rcv_ack", SLAVE_1DC_RCV_ACK<<10},
		{"slave_2dc_snd_ack", SLAVE_2DC_SND_ACK<<10},
		{"slave_2dc_snd_ack_refl", SLAVE_2DC_SND_ACK_REFL<<10},
		{"slave_4dc_snd_ack", SLAVE_4DC_SND_ACK<<10},
		{"slave_pull_seen", SLAVE_PULL_SEEN<<10},
		{"slave_h_m_ga_not_ownd", SLAVE_H_M_GA_NOT_OWND<<10},
		{"slave_h_m_no_state_change", SLAVE_H_M_NO_STATE_CHANGE<<10},
		{"slave_hli_req_0", SLAVE_HLI_REQ_0<<10},
		{"slave_hli_req_1", SLAVE_HLI_REQ_1<<10},
		{"slave_hli_req_2", SLAVE_HLI_REQ_2<<10},
		{"slave_hli_req_3", SLAVE_HLI_REQ_3<<10},
		{"slave_hli_req_4", SLAVE_HLI_REQ_4<<10},
		{"slave_hli_req_5", SLAVE_HLI_REQ_5<<10},
		{"slave_hli_grant_0", SLAVE_HLI_GRANT_0<<10},
		{"slave_hli_grant_1", SLAVE_HLI_GRANT_1<<10},
		{"slave_hli_grant_2", SLAVE_HLI_GRANT_2<<10},
		{"slave_hli_grant_3", SLAVE_HLI_GRANT_3<<10},
		{"slave_hli_grant_4", SLAVE_HLI_GRANT_4<<10},
		{"slave_hli_grant_5", SLAVE_HLI_GRANT_5<<10},
		/* cnt1 duration */
		{"slave_agent_alloc_duration",
		    SLAVE_AGENT_ALLOC<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_rlpa_duration",
		    SLAVE_SFI_P12GT_RLPA<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_rga_duration",
		    SLAVE_SFI_P12GT_RGA<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_rhlpa_duration",
		    SLAVE_SFI_P12GT_RHLPA<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_rhga_duration",
		    SLAVE_SFI_P12GT_RHGA<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gtrhmlpa_duration",
		    SLAVE_SFI_P12GT_RHMLPA<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_rhmga_duration",
		    SLAVE_SFI_P12GT_RHMGA<<10 | WCI_DURATION_BIT},
		{"slave_1dc_rcv_ack_c1_duration",
		    SLAVE_1DC_RCV_ACK<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p6_grant_wr_duration",
		    SLAVE_SFI_P6_GRANT_WR<<10 | WCI_DURATION_BIT},
		{"slave_sfi_p12gt_wr_duration",
		    SLAVE_SFI_P12GT_WR<<10 | WCI_DURATION_BIT},
		{"slave_2dc_sndack_refl_duration",
		    SLAVE_2DC_SND_ACK_REFL<<10 | WCI_DURATION_BIT},
		{"clear_pic", 	MISC_CLEAR_PIC1},
		{EOSTR, 0}
	}

};


/* Loopback Counter */
static wci_event_mask_t
    wci_lpbk_events_arr[WCI_NUM_PICS][WCI_LPBK_NUM_EVENTS+1] = {
/* pic 0 */
	{
	{"lpbk_rcvd_data_pkt", LPBK_RCVD_DATA_PKT},
	{"lpbk_rcvd_addr_2_pkt", LPBK_RCVD_ADDR_2_PKT},
	{"lpbk_raddr2_rdata", LPBK_RADDR2_RDATA},
	{"lpbk_rcvd_addr_1_pkt", LPBK_RCVD_ADDR_1_PKT},
	{"lpbk_raddr1_rdata", LPBK_RADDR1_RDATA},
	{"lpbk_data_lpbk_full", LPBK_DATA_LPBK_FULL},
	{"lpbk_dfull_rdata", LPBK_DFULL_RDATA},
	{"lpbk_dfull_raddr2", LPBK_DFULL_RADDR2},
	{"lpbk_dfull_raddr2_rdata", LPBK_DFULL_RADDR2_RDATA},
	{"lpbk_dfull_raddr1", LPBK_DFULL_RADDR1},
	{"lpbk_dfull_raddr1_rdata", LPBK_DFULL_RADDR1_RDATA},
	{"lpbk_addr_lpbk_full", LPBK_ADDR_LPBK_FULL},
	{"lpbk_afull_rdata", LPBK_AFULL_RDATA},
	{"lpbk_afull_raddr2", LPBK_AFULL_RADDR2},
	{"lpbk_afull_raddr2_rdata", LPBK_AFULL_RADDR2_RDATA},
	{"lpbk_afull_raddr1", LPBK_AFULL_RADDR1},
	{"lpbk_afull_raddr1_rdata", LPBK_AFULL_RADDR1_RDATA},
	{"lpbk_afull_dfull", LPBK_AFULL_DFULL},
	{"lpbk_afull_dfull_rdata", LPBK_AFULL_DFULL_RDATA},
	{"lpbk_afull_dfull_raddr2", LPBK_AFULL_DFULL_RADDR2},
	{"lpbk_afull_dfull_raddr2_rdata", LPBK_AFULL_DFULL_RADDR2_RDATA},
	{"lpbk_afull_dfull_raddr1", LPBK_AFULL_DFULL_RADDR1},
	{"lpbk_afull_dfull_raddr1_rdata", LPBK_AFULL_DFULL_RADDR1_RDATA},
	{"clear_pic", LPBK_CLEAR_PIC0}
	},
/* pic 1 */
	{
	{"lpbk_rcvd_data_pkt", LPBK_RCVD_DATA_PKT<<16},
	{"lpbk_rcvd_addr_2_pkt", LPBK_RCVD_ADDR_2_PKT<<16},
	{"lpbk_raddr2_rdata", LPBK_RADDR2_RDATA<<16},
	{"lpbk_rcvd_addr_1_pkt", LPBK_RCVD_ADDR_1_PKT<<16},
	{"lpbk_raddr1_rdata", LPBK_RADDR1_RDATA<<16},
	{"lpbk_data_lpbk_full", LPBK_DATA_LPBK_FULL<<16},
	{"lpbk_dfull_rdata", LPBK_DFULL_RDATA<<16},
	{"lpbk_dfull_raddr2", LPBK_DFULL_RADDR2<<16},
	{"lpbk_dfull_raddr2_rdata", LPBK_DFULL_RADDR2_RDATA<<16},
	{"lpbk_dfull_raddr1", LPBK_DFULL_RADDR1<<16},
	{"lpbk_dfull_raddr1_rdata", LPBK_DFULL_RADDR1_RDATA<<16},
	{"lpbk_addr_lpbk_full", LPBK_ADDR_LPBK_FULL<<16},
	{"lpbk_afull_rdata", LPBK_AFULL_RDATA<<16},
	{"lpbk_afull_raddr2", LPBK_AFULL_RADDR2<<16},
	{"lpbk_afull_raddr2_rdata", LPBK_AFULL_RADDR2_RDATA<<16},
	{"lpbk_afull_raddr1", LPBK_AFULL_RADDR1<<16},
	{"lpbk_afull_raddr1_rdata", LPBK_AFULL_RADDR1_RDATA<<16},
	{"lpbk_afull_dfull", LPBK_AFULL_DFULL<<16},
	{"lpbk_afull_dfull_rdata", LPBK_AFULL_DFULL_RDATA<<16},
	{"lpbk_afull_dfull_raddr2", LPBK_AFULL_DFULL_RADDR2<<16},
	{"lpbk_afull_dfull_raddr2_rdata", LPBK_AFULL_DFULL_RADDR2_RDATA<<16},
	{"lpbk_afull_dfull_raddr1", LPBK_AFULL_DFULL_RADDR1<<16},
	{"lpbk_afull_dfull_raddr1_rdata", LPBK_AFULL_DFULL_RADDR1_RDATA<<16},
	{"clear_pic", LPBK_CLEAR_PIC1}
	}
};



/* Link Counter */
/* one event list per counter, per link */
static wci_event_mask_t
    wci_link_events_arr[WCI_NUM_PICS][WCI_LINK_NUM_EVENTS+1] = {
/* pic 0 */
	{
	{"link_sending_admin_pkts", LINK_SENDING_ADMIN_PKTS},
	{"link_rcvd_mh_data_pkt", LINK_RCVD_MH_DATA_PKT},
	{"link_sadm_rmhdp", LINK_RMHDP_SADM},
	{"link_rcvd_data_pkt", LINK_RCVD_DATA_PKT},
	{"link_sadm_rdp", LINK_RDP_SADM},
	{"link_rdp_rmhdp", LINK_RDP_RMHDP},
	{"link_rejected_flit", LINK_REJECTED_FLIT},
	{"link_rejflit_sadm", LINK_REJFLIT_SADM},
	{"link_rejflit_rmhdp", LINK_REJFLIT_RMHDP},
	{"link_rejflit_rmhdp_sadm", LINK_REJFLIT_RMHDP_SADM},
	{"link_rejflit_rdp", LINK_REJFLIT_RDP},
	{"link_rejflit_rdp_sadm", LINK_REJFLIT_RDP_SADM},
	{"link_rcvd_admin_pkt", LINK_RCVD_ADMIN_PKT},
	{"link_radmp_sadm", LINK_RADMP_SADM},
	{"link_radmp_rmhdp", LINK_RADMP_RMHDP},
	{"link_radmp_rmhdp_sadm", LINK_RADMP_RMHDP_SADM},
	{"link_radmp_rdp", LINK_RADMP_RDP},
	{"link_radmp_rdp_sadm", LINK_RADMP_RDP_SADM},
	{"link_radmp_rejflit", LINK_RADMP_REJFLIT},
	{"clear_pic", LINK_CLEAR_PIC0},
	},
/* pic 1 */
	{
	{"link_sending_admin_pkts", LINK_SENDING_ADMIN_PKTS<<16},
	{"link_rcvd_mh_data_pkt", LINK_RCVD_MH_DATA_PKT<<16},
	{"link_sadm_rmhdp", LINK_RMHDP_SADM<<16},
	{"link_rcvd_data_pkt", LINK_RCVD_DATA_PKT<<16},
	{"link_sadm_rdp", LINK_RDP_SADM<<16},
	{"link_rdp_rmhdp", LINK_RDP_RMHDP<<16},
	{"link_rejected_flit", LINK_REJECTED_FLIT<<16},
	{"link_rejflit_sadm", LINK_REJFLIT_SADM<<16},
	{"link_rejflit_rmhdp", LINK_REJFLIT_RMHDP<<16},
	{"link_rejflit_rmhdp_sadm", LINK_REJFLIT_RMHDP_SADM<<16},
	{"link_rejflit_rdp", LINK_REJFLIT_RDP<<16},
	{"link_rejflit_rdp_sadm", LINK_REJFLIT_RDP_SADM<<16},
	{"link_rcvd_admin_pkt", LINK_RCVD_ADMIN_PKT<<16},
	{"link_radmp_sadm", LINK_RADMP_SADM<<16},
	{"link_radmp_rmhdp", LINK_RADMP_RMHDP<<16},
	{"link_radmp_rmhdp_sadm", LINK_RADMP_RMHDP_SADM<<16},
	{"link_radmp_rdp", LINK_RADMP_RDP<<16},
	{"link_radmp_rdp_sadm", LINK_RADMP_RDP_SADM<<16},
	{"link_radmp_rejflit", LINK_RADMP_REJFLIT<<16},
	{"clear_pic", LINK_CLEAR_PIC1}
	}
};

/*
 * WCI Safari Histogramming Counter
 * One event list per pic counter.
 */
static wci_event_mask_t
    wci_sfi_events_arr[WCI_NUM_PICS][WCI_SFI_NUM_EVENTS + 1] = {
/* pic 0 */
	{
		{"sfi_hstgrm_all_trans",
		    SFI_HSTGRM_ALL_TRANS | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_int", SFI_HSTGRM_INT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_local_int",
		    SFI_HSTGRM_LOCAL_INT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_clu_incm_int",
		    SFI_HSTGRM_RMT_CLU_INCM_INT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_ssm_incm_int",
		    SFI_HSTGRM_RMT_SSM_INCM_INT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_io", SFI_HSTGRM_IO | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_ssm_incm_io",
		    SFI_HSTGRM_RMT_SSM_INCM_IO | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_cohrnt", SFI_HSTGRM_COHRNT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_clu_incm_cohrnt",
		    SFI_HSTGRM_RMT_CLU_INCM_COHRNT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_ssm_otg_cohrnt",
		    SFI_HSTGRM_RMT_SSM_OTG_COHRNT | SFI_SFI_HISTOGRAM0},
		{"sfi_hstgrm_rmt_ssm_incm_cohrnt",
		    SFI_HSTGRM_RMT_SSM_INCM_COHRNT | SFI_SFI_HISTOGRAM0},
		{"clear_pic", WCI_SFI_CLEAR_PIC0}
	},
/* pic 1 */
	{
		{"sfi_hstgrm_all_trans",
		    SFI_HSTGRM_ALL_TRANS<<4 | SFI_SFI_HISTOGRAM1<< 10},
		{"sfi_hstgrm_int", SFI_HSTGRM_INT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_local_int",
		    SFI_HSTGRM_LOCAL_INT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_clu_incm_int",
		    SFI_HSTGRM_RMT_CLU_INCM_INT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_ssm_incm_int",
		    SFI_HSTGRM_RMT_SSM_INCM_INT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_io", SFI_HSTGRM_IO<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_ssm_incm_io",
		    SFI_HSTGRM_RMT_SSM_INCM_IO<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_cohrnt",
		    SFI_HSTGRM_COHRNT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_clu_incm_cohrnt",
		    SFI_HSTGRM_RMT_CLU_INCM_COHRNT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_ssm_otg_cohrnt",
		    SFI_HSTGRM_RMT_SSM_OTG_COHRNT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"sfi_hstgrm_rmt_ssm_incm_cohrnt",
		    SFI_HSTGRM_RMT_SSM_INCM_COHRNT<<4 | SFI_SFI_HISTOGRAM1<<10},
		{"clear_pic", 	WCI_SFI_CLEAR_PIC1}
	}
};

static wci_sfi_regs_value_t wci_sfi_ctr_regs_tab[WCI_SFI_NUM_EVENTS] = {
	{ 0x0000000000000000ULL, 0x0000000000000000ULL, 0x000000000007FFFFULL },
	{ 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000200ULL },
	{ 0x00000000000F8000ULL, 0x00000000000F8000ULL, 0x0000000000000200ULL },
	{ 0x0000F80000000000ULL, 0x0000F80000000000ULL, 0x0000000000000200ULL },
	{ 0x0000F80000000000ULL, 0x0000F80000000000ULL, 0x0000000000000200ULL },
	{ 0x0000000000000000ULL, 0x0000000000000000ULL, 0x000000000000000FULL },
	{ 0x0000F80000000000ULL, 0x0000F80000000000ULL, 0x000000000000000FULL },
	{ 0x0000000000000000ULL, 0x0000000000000000ULL, 0x000000000007FDF0ULL },
	{ 0x0000F80000000000ULL, 0x0000F80000000000ULL, 0x0000000000018060ULL },
	{ 0x0000000000000000ULL, 0x0000000000000000ULL, 0x00000000000001F0ULL },
	{ 0x0000F80000000000ULL, 0x0000F80000000000ULL, 0x000000000007FC00ULL }
};


/*
 * Driver globals
 */
static kstat_t  *wci_misc_pic_ksp[WCI_NUM_PICS];  /* Misc picN kstats */
static kstat_t  *wci_lpbk_pic_ksp[WCI_NUM_PICS];  /* Lpbk picN kstats */
static kstat_t  *wci_link_pic_ksp[WCI_NUM_LINKS][WCI_NUM_PICS]; /* link */
static kstat_t	*wci_sfi_pic_ksp[WCI_NUM_PICS];	/* SFI histogram picN kstats */

void
wci_add_counters_kstats(struct wci_common_soft_state *softsp, char *drvname)
{
	wci_add_misc_kstats(softsp, drvname);
	wci_add_lpbk_kstats(softsp, drvname);
	wci_add_link_kstats(softsp, drvname);
	wci_add_sfi_kstats(softsp, drvname);
}

void
wci_add_picN_kstats(char *drvname)
{
	wci_add_misc_pic_kstats(drvname);
	wci_add_lpbk_pic_kstats(drvname);
	wci_add_link_pic_kstats(drvname);
	wci_add_sfi_pic_kstats(drvname);
}


static void
wci_add_misc_kstats(struct wci_common_soft_state *softsp, char *drvname)
{
	struct kstat *wci_misc_ksp;
	struct wci_counters_kstat *wci_misc_named_ksp;
	char drvmod[15];

	/*
	 * A "counter" kstat is created for each WCI
	 * instance that provides access to the %pcr and %pic
	 * registers for that instance.
	 */
	(void) sprintf(drvmod, WCI_KSTAT_NAME, drvname);
	if ((wci_misc_ksp = kstat_create(drvmod, softsp->instance,
	    "counters", "bus", KSTAT_TYPE_NAMED,
	    sizeof (struct wci_counters_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "wci%d: kstat_create failed",
		    softsp->instance);
		return;
	}

	wci_misc_named_ksp =
	    (struct wci_counters_kstat *)(wci_misc_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&wci_misc_named_ksp->wci_ctr_ctl,
	    WCI_CTRCTL_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);
	kstat_named_init(&wci_misc_named_ksp->wci_ctr0,
	    WCI_CTR0_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);
	kstat_named_init(&wci_misc_named_ksp->wci_ctr1,
	    WCI_CTR1_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);
	wci_misc_ksp->ks_update = wci_misc_kstat_update;
	wci_misc_ksp->ks_private = (void *)softsp;
	kstat_install(wci_misc_ksp);
	/* update the common softstate */
	softsp->wci_misc_counters_ksp = wci_misc_ksp;
}

/*
 * called from wci_add_picN_kstats() to create a kstat for each %pic that
 * the WCI Misc counter supports. These (read-only) kstats export the
 * event names that each %pic supports.
 *
 * wci_misc_events_arr is an array of (event_name, pcr_mask) records
 * for each (pic, event) pair.
 */
static void
wci_add_misc_pic_kstats(char *drvname)
{
	struct kstat_named *wci_misc_pic_named_data;
	int  event, pic;
	char pic_name[30];
	int i = 0;
	int num_events = 0;
	char drvmod[15];

	for (pic = 0; pic < WCI_NUM_PICS; pic++) {
		(void) sprintf(pic_name, "pic%d", pic);
		/*
		 * calculate the actual number of events for
		 * each misc picN, since they are different for each picN
		 * Note: make sure {NULL, 0 } is the last event
		 */
		for (i = 0; i < WCI_MISC_NUM_EVENTS; i++) {
			if (strcmp(wci_misc_events_arr[pic][i].event_name,
			    EOSTR) == 0)
				break;
		}
		num_events = i;
		/*
		 * create the picN kstat. The size of this kstat is
		 * WCI_NUM_EVENTS + 1 for the clear_event_mask
		 */
		(void) sprintf(drvmod, WCI_KSTAT_NAME, drvname);
		if ((wci_misc_pic_ksp[pic] = kstat_create(drvmod, 0,
		    pic_name, "bus", KSTAT_TYPE_NAMED,
		    num_events, NULL)) == NULL) {
			cmn_err(CE_WARN, "wci misc %s: kstat_create failed",
			    pic_name);
			/*
			 * remove all picN kstat from 0 to pic-1
			 * if current picN kstat create fails
			 */
			for (i = 0; i < pic; i++) {
				kstat_delete(wci_misc_pic_ksp[i]);
				wci_misc_pic_ksp[i] = NULL;
			}
			return;
		}
		wci_misc_pic_named_data =
		    (struct kstat_named *)(wci_misc_pic_ksp[pic]->ks_data);
		/*
		 * for each picN event we need to write a kstat record
		 * (name = EVENT, value.ui64 = PCR_MASK)
		 */
		for (event = 0; event < num_events; event ++) {
			/* pcr_mask */
			wci_misc_pic_named_data[event].value.ui64 =
			    wci_misc_events_arr[pic][event].pcr_mask;
			/* event-name */
			kstat_named_init(&wci_misc_pic_named_data[event],
			    wci_misc_events_arr[pic][event].event_name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(wci_misc_pic_ksp[pic]);
	}
}


static int wci_misc_kstat_update(kstat_t *ksp, int rw)
{
	struct wci_counters_kstat *wci_misc_ksp;
	struct wci_common_soft_state *softsp;
	uint64_t wci_cluster_ctr;

	wci_misc_ksp = (struct wci_counters_kstat *)ksp->ks_data;
	softsp = (struct wci_common_soft_state *)ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		/*
		 * can only write the wci_misc_ctr_ctl register
		 */
		*(softsp->wci_misc_ctr_ctl_vaddr) =
		    (uint64_t)wci_misc_ksp->wci_ctr_ctl.value.ui64;
		/*
		 * The misc counters can be used to count cluster
		 * related events related to incoming transactions
		 * as they are processed by the CMMU.
		 * The wci_cluster_ctr_ctl register has bits <3:0>
		 * specifying 4 different events that are counted
		 * if a misc counter is programmed with event
		 * "cluster event 0", and bits <7:4> specifying 4
		 * different events that are counted if a misc
		 * counter is programmed with event "cluster event 1".
		 * For counter 0, bits <27:24> of the
		 * wci_misc_ksp->wci_ctr_ctl represent the setting of
		 * the either the cnt0 or the cnt1 wci_cluster_ctr_ctl
		 * register fields.  For counter 1, bits <31:28> of
		 * the wci_misc_ksp->wci_ctr_ctl represent the setting
		 * of the either the cnt0 or the cnt1 wci_cluster_ctr_ctl
		 * register fields. Selecting a pic0 or pic1 event type
		 * which specifies the CACHE-CTR agent and the event type
		 * of "cluster event 0" or "cluster event 1" causes the
		 * cnt0 or cnt1 events (respectively) in the
		 * wci_cluster_ctr_ctl register to be set as specified in
		 * bits <27:24> or <31:28>, respectively.  If one or more
		 * of bits <31:24> of wci_misc_ksp->wci_ctr_ctl are
		 * non-zero, we need to write those bits in
		 * wci_cluster_ctr_ctl registers to set and enable
		 * the corresponding fields.
		 * Hence, the cluster counter fields are contained in the
		 * wci_misc_ksp->wci_ctr_ctl. We need to write these bits
		 * to the misc control register wci_misc_ctr_ctl_vaddr.
		 * Since for all the other misc counter event masks,
		 * the bits <31:24> are set to 0, these bits are never
		 * used by any events other than those with Cacthe-control
		 * agent and  "cluster event 0" or "cluster event 1" set.
		 * Thus, It does not matter that we also write these bits
		 * to the misc control register. Also, for `busstat` support,
		 * we must keep consistent misc control register (pcr) values.
		 */
		wci_cluster_ctr = (uint64_t)
		    (wci_misc_ksp->wci_ctr_ctl.value.ui64 >> 24) &
		    WCI_CLUSTER_MASK;

		/* only need bits<7:0>, keep bits <63:8> original value */
		if (wci_cluster_ctr > 0)
			*(softsp->wci_cluster_ctr_ctl_vaddr) =
			    (*(softsp->wci_cluster_ctr_ctl_vaddr) &
				(~WCI_CLUSTER_MASK)) | wci_cluster_ctr;

	} else {
		/*
		 * copy the current state of the hardware into the
		 * kstat structure.
		 */
		wci_misc_ksp->wci_ctr_ctl.value.ui64 =
		    (uint64_t)*(softsp->wci_misc_ctr_ctl_vaddr);
		wci_misc_ksp->wci_ctr0.value.ui64 =
		    (*(softsp->wci_misc_ctr_vaddr)) & WCI_PIC0_MASK;
		wci_misc_ksp->wci_ctr1.value.ui64 =
		    (*(softsp->wci_misc_ctr_vaddr)) >> 32;
	}
	return (0);
}



static void
wci_add_lpbk_kstats(struct wci_common_soft_state *softsp, char *drvname)
{
	struct kstat *wci_lpbk_ksp;
	struct wci_counters_kstat *wci_lpbk_named_ksp;
	char drvmod[15];

	(void) sprintf(drvmod, WCI_LPBK_KSTAT_NAME, drvname);
	if ((wci_lpbk_ksp = kstat_create(drvmod,
	    softsp->instance, "counters", "bus", KSTAT_TYPE_NAMED,
	    sizeof (struct wci_counters_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "wci%d: kstat_create failed",
		    softsp->instance);
		return;
	}

	wci_lpbk_named_ksp = (struct wci_counters_kstat *)
	    (wci_lpbk_ksp->ks_data);
	/* initialize the named kstats */
	kstat_named_init(&wci_lpbk_named_ksp->wci_ctr_ctl,
	    WCI_CTRCTL_KSTAT_NAMED, KSTAT_DATA_UINT64);
	kstat_named_init(&wci_lpbk_named_ksp->wci_ctr0,
	    WCI_CTR0_KSTAT_NAMED, KSTAT_DATA_UINT64);
	kstat_named_init(&wci_lpbk_named_ksp->wci_ctr1,
	    WCI_CTR1_KSTAT_NAMED, KSTAT_DATA_UINT64);

	wci_lpbk_ksp->ks_update = wci_lpbk_kstat_update;
	wci_lpbk_ksp->ks_private = (void *)softsp;
	kstat_install(wci_lpbk_ksp);
	/* update the common softstate */
	softsp->wci_lpbk_counters_ksp = wci_lpbk_ksp;
}


static void
wci_add_lpbk_pic_kstats(char *drvname)
{
	struct kstat_named *wci_lpbk_pic_named_data;
	int event, pic;
	char pic_name[30];
	char drvmod[15];

	(void) sprintf(drvmod, WCI_LPBK_KSTAT_NAME, drvname);
	for (pic = 0; pic < WCI_NUM_PICS; pic++) {
		(void) sprintf(pic_name, "pic%d", pic);
		/*
		 * create the picN kstat. The size of this kstat is
		 * WCI_LPBK_NUM_EVENTS + 1 for the clear_event_mask
		 */
		if ((wci_lpbk_pic_ksp[pic] = kstat_create(drvmod,
		    0, pic_name, "bus", KSTAT_TYPE_NAMED,
		    WCI_LPBK_NUM_EVENTS + 1, NULL)) == NULL) {
			cmn_err(CE_WARN,
			    "wci lpbk %s: kstat_create failed", pic_name);
			/* remove pic0 kstat if pic1 create fails */
			if (pic == 1) {
				kstat_delete(wci_lpbk_pic_ksp[0]);
				wci_lpbk_pic_ksp[0] = NULL;
			}

			return;
		}
		wci_lpbk_pic_named_data =
		    (struct kstat_named *)(wci_lpbk_pic_ksp[pic]->ks_data);

		/*
		 * for each picN event we need to write a kstat record
		 * (name = EVENT, value.ui64 = PCR_MASK)
		 */
		for (event = 0; event < WCI_LPBK_NUM_EVENTS + 1; event ++) {
			/* pcr_mask */
			wci_lpbk_pic_named_data[event].value.ui64 =
			    wci_lpbk_events_arr[pic][event].pcr_mask;
			/* event_name */
			kstat_named_init(&wci_lpbk_pic_named_data[event],
			    wci_lpbk_events_arr[pic][event].event_name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(wci_lpbk_pic_ksp[pic]);
	}
}


static int wci_lpbk_kstat_update(kstat_t *ksp, int rw) {
	struct wci_counters_kstat *wci_lpbk_ksp;
	struct wci_common_soft_state *softsp;


	wci_lpbk_ksp = (struct wci_counters_kstat *)ksp->ks_data;
	softsp = (struct wci_common_soft_state *)ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		/*
		 * can only write the wci_misc_ctr_ctl register
		 */
		*(softsp->wci_lpbk_ctr_ctl_vaddr) =
		    (uint64_t)wci_lpbk_ksp->wci_ctr_ctl.value.ui64;


	} else {
		wci_lpbk_ksp->wci_ctr_ctl.value.ui64 =
		    (uint64_t)*(softsp->wci_lpbk_ctr_ctl_vaddr);
		wci_lpbk_ksp->wci_ctr0.value.ui64 =
		    *(softsp->wci_lpbk_ctr_vaddr) & WCI_PIC0_MASK;
		wci_lpbk_ksp->wci_ctr1.value.ui64 =
		    *(softsp->wci_lpbk_ctr_vaddr) >> 32;

	}
	return (0);
}




static void
wci_add_link_kstats(struct wci_common_soft_state *softsp, char *drvname)
{
	struct kstat *wci_link_ksp[WCI_NUM_LINKS];
	struct wci_counters_kstat *wci_link_named_ksp[WCI_NUM_LINKS];
	int link_no;
	char wci_link_kstat_name[30];
	char tmp[15];

	/*
	 * Calculate the link kstat name length, i.e., length of "wssmlink".
	 * This is needed in the wci_link_kstat_update() routine
	 */
	(void) sprintf(tmp, WCI_LINK_KSTAT_NAME, drvname);
	wci_link_kstat_modlen = strlen(tmp);

	for (link_no = 0; link_no < WCI_NUM_LINKS; link_no++) {
		(void) sprintf(wci_link_kstat_name, "%slink%c", drvname,
			link_no + 'a');
		if ((wci_link_ksp[link_no] = kstat_create(
			wci_link_kstat_name,
			    softsp->instance,
			    "counters", "bus", KSTAT_TYPE_NAMED,
			    sizeof (struct wci_counters_kstat) /
			    sizeof (kstat_named_t),
			    KSTAT_FLAG_WRITABLE)) == NULL) {
			cmn_err(CE_WARN, "wci%d: kstat_create failed",
			    softsp->instance);
			return;
		}

		wci_link_named_ksp[link_no] = (struct wci_counters_kstat *)
		    (wci_link_ksp[link_no]->ks_data);

		/* initialize the named kstats */

		kstat_named_init(&wci_link_named_ksp[link_no]->wci_ctr_ctl,
		    WCI_CTRCTL_KSTAT_NAMED,
		    KSTAT_DATA_UINT64);
		kstat_named_init(&wci_link_named_ksp[link_no]->wci_ctr0,
		    WCI_CTR0_KSTAT_NAMED,
		    KSTAT_DATA_UINT64);
		kstat_named_init(&wci_link_named_ksp[link_no]->wci_ctr1,
		    WCI_CTR1_KSTAT_NAMED,
		    KSTAT_DATA_UINT64);
		wci_link_ksp[link_no]->ks_update = wci_link_kstat_update;
		wci_link_ksp[link_no]->ks_private = (void *)softsp;
		kstat_install(wci_link_ksp[link_no]);

		/* update the common softstate */
		softsp->wci_link_counters_ksp[link_no] =
		    wci_link_ksp[link_no];
	}
}



static void
wci_add_link_pic_kstats(char *drvname)
{

	struct kstat_named *wci_link_pic_named_data;

	int event, pic, link_no;
	char pic_name[30];
	char wci_link_kstat_name[30];

	for (link_no = 0; link_no < WCI_NUM_LINKS; link_no++) {
		(void) sprintf(wci_link_kstat_name, "%slink%c", drvname,
			link_no + 'a');
		for (pic = 0; pic < WCI_NUM_PICS; pic++) {
			(void) sprintf(pic_name, "pic%d", pic);
			/*
			 * create the picN kstat. The size of this kstat is
			 * WCI_LINK_NUM_EVENTS + 1 for the clear_event_mask
			 */
			if ((wci_link_pic_ksp[link_no][pic] = kstat_create(
				wci_link_kstat_name, 0, pic_name, "bus",
				    KSTAT_TYPE_NAMED,
				    WCI_LINK_NUM_EVENTS + 1,
				    NULL)) == NULL) {
				cmn_err(CE_WARN,
				    "wci link%d %s: kstat_create failed",
				    link_no, pic_name);

				/* remove pic0 kstat if pic1 create fails */
				if (pic == 1) {
					kstat_delete(wci_link_pic_ksp
					    [link_no][0]);
					wci_link_pic_ksp[link_no][0] = NULL;
				}

				return;
			}
			wci_link_pic_named_data =
			    (struct kstat_named *)
			    (wci_link_pic_ksp[link_no][pic]->ks_data);

			/*
			 * for each picN event we need to write a kstat
			 * record (name = EVENT, value.ui64 = PCR_MASK)
			 */
			for (event = 0; event < WCI_LINK_NUM_EVENTS + 1;
			    event++) {
				/* pcr mask */
				wci_link_pic_named_data[event].
				    value.ui64 =
				    wci_link_events_arr[pic][event].pcr_mask;

				/* event_name */
				kstat_named_init(
					&wci_link_pic_named_data[event],
					    wci_link_events_arr[pic][event].
					    event_name,
					    KSTAT_DATA_UINT64);
			}

			kstat_install(wci_link_pic_ksp[link_no][pic]);

		}
	}
}


static int wci_link_kstat_update(kstat_t *ksp, int rw) {
	struct wci_counters_kstat *wci_link_ksp;
	struct wci_common_soft_state *softsp;
	int arr_index;

	wci_link_ksp = (struct wci_counters_kstat *)ksp->ks_data;
	ASSERT(wci_link_ksp != NULL);
	softsp = (struct wci_common_soft_state *)ksp->ks_private;
	ASSERT(softsp != NULL);
	arr_index = ksp->ks_module[wci_link_kstat_modlen] - 'a';
	ASSERT(arr_index >= 0);

	if (rw == KSTAT_WRITE) {
		/*
		 * can only write the wci_link_ctr_ctl register array
		 */
		*(softsp->wci_link_ctr_ctl_vaddr[arr_index]) =
		    (uint64_t)wci_link_ksp->wci_ctr_ctl.value.ui64;

	} else {
		ASSERT(softsp->wci_link_ctr_ctl_vaddr[arr_index] != NULL);

		wci_link_ksp->wci_ctr_ctl.value.ui64 =
		    (uint64_t)*(softsp->wci_link_ctr_ctl_vaddr[arr_index]);
		wci_link_ksp->wci_ctr0.value.ui64 = (uint64_t)
		    *(softsp->wci_link_ctr_vaddr[arr_index]) & WCI_PIC0_MASK;
		wci_link_ksp->wci_ctr1.value.ui64 = (uint64_t)
		    *(softsp->wci_link_ctr_vaddr[arr_index]) >> 32;
	}
	return (0);
}

static void
wci_add_sfi_kstats(struct wci_common_soft_state *softsp, char *drvname)
{
	struct kstat *wci_sfi_ksp;
	struct wci_counters_kstat *wci_sfi_named_ksp;
	char drvmod[15];

	(void) sprintf(drvmod, WCI_SFI_KSTAT_NAME, drvname);
	if ((wci_sfi_ksp = kstat_create(drvmod,
	    softsp->instance, "counters", "bus", KSTAT_TYPE_NAMED,
	    sizeof (struct wci_counters_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "wci%d: kstat_create failed for sfi histogram",
		    softsp->instance);
		return;
	}

	wci_sfi_named_ksp = (struct wci_counters_kstat *)
	    (wci_sfi_ksp->ks_data);
	/* initialize the named kstats */
	kstat_named_init(&wci_sfi_named_ksp->wci_ctr_ctl,
	    WCI_CTRCTL_KSTAT_NAMED, KSTAT_DATA_UINT64);
	kstat_named_init(&wci_sfi_named_ksp->wci_ctr0,
	    WCI_CTR0_KSTAT_NAMED, KSTAT_DATA_UINT64);
	kstat_named_init(&wci_sfi_named_ksp->wci_ctr1,
	    WCI_CTR1_KSTAT_NAMED, KSTAT_DATA_UINT64);

	wci_sfi_ksp->ks_update = wci_sfi_kstat_update;
	wci_sfi_ksp->ks_private = (void *)softsp;
	kstat_install(wci_sfi_ksp);
	/* update the common softstate */
	softsp->wci_sfi_counters_ksp = wci_sfi_ksp;
}

static void
wci_add_sfi_pic_kstats(char *drvname)
{
	struct kstat_named *wci_sfi_pic_named_data;
	int event, pic;
	char pic_name[30];
	char drvmod[15];

	(void) sprintf(drvmod, WCI_SFI_KSTAT_NAME, drvname);
	for (pic = 0; pic < WCI_NUM_PICS; pic++) {
		(void) sprintf(pic_name, "pic%d", pic);
		/*
		 * create the picN kstat. The size of this kstat is
		 * WCI_SFI_NUM_EVENTS + 1 for the clear_event_mask
		 */
		if ((wci_sfi_pic_ksp[pic] = kstat_create(drvmod,
		    0, pic_name, "bus", KSTAT_TYPE_NAMED,
		    WCI_SFI_NUM_EVENTS + 1, NULL)) == NULL) {
			cmn_err(CE_WARN,
			    "wci sfi %s: kstat_create failed", pic_name);
			/* remove pic0 kstat if pic1 create fails */
			if (pic == 1) {
				kstat_delete(wci_sfi_pic_ksp[0]);
				wci_sfi_pic_ksp[0] = NULL;
			}

			return;
		}
		wci_sfi_pic_named_data =
		    (struct kstat_named *)(wci_sfi_pic_ksp[pic]->ks_data);

		/*
		 * for each picN event we need to write a kstat record
		 * (name = EVENT, value.ui64 = PCR_MASK)
		 */
		for (event = 0; event < WCI_SFI_NUM_EVENTS + 1; event ++) {
			/* pcr_mask */
			wci_sfi_pic_named_data[event].value.ui64 =
			    wci_sfi_events_arr[pic][event].pcr_mask;
			/* event_name */
			kstat_named_init(&wci_sfi_pic_named_data[event],
			    wci_sfi_events_arr[pic][event].event_name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(wci_sfi_pic_ksp[pic]);
	}
}

static int wci_sfi_kstat_update(kstat_t *ksp, int rw)
{
	struct wci_counters_kstat *wci_sfi_ksp;
	struct wci_common_soft_state *softsp;
	uint64_t evt0, evt1;
	uint_t id0, id1;

	wci_sfi_ksp = (struct wci_counters_kstat *)ksp->ks_data;
	softsp = (struct wci_common_soft_state *)ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		/* write to virtual sfi counter control */
		softsp->wci_sfi_sw_ctr_ctl =
		    wci_sfi_ksp->wci_ctr_ctl.value.ui64;
		/* write to wci_misc_ctr_ctl register bit <19:0> */
		*softsp->wci_misc_ctr_ctl_vaddr =
		    wci_sfi_ksp->wci_ctr_ctl.value.ui64 &
		    WCI_SFI_SW_CTR_CTL_MASK;

		evt0 = (softsp->wci_sfi_sw_ctr_ctl & WCI_SFI_CTR0_EVENT_MASK);
		id0 = (uint_t)(evt0 >> WCI_SFI_CTR0_EVENT_SHIFT);
		if (evt0 > 0) {
			/* safri histogramming counter 0 */
			*softsp->wci_sfi_ctr0_mask_vaddr =
			    wci_sfi_ctr_regs_tab[id0-1].wci_sfi_ctr_mask_val;
			*softsp->wci_sfi_ctr0_match_transaction_vaddr =
			    wci_sfi_ctr_regs_tab[id0-1].
			    wci_sfi_ctr_match_trans_val;

			switch (evt0) {
			case SFI_HSTGRM_LOCAL_INT:
				*softsp->wci_sfi_ctr0_match_vaddr =
				    (softsp->node_id <<
				    WCI_SFI_ADDR_TNID_SHIFT) &
				    wci_sfi_ctr_regs_tab[id0-1].
				    wci_sfi_ctr_match_val;
				break;
			case SFI_HSTGRM_RMT_CLU_INCM_INT:
			case SFI_HSTGRM_RMT_SSM_INCM_INT:
			case SFI_HSTGRM_RMT_SSM_INCM_IO:
			case SFI_HSTGRM_RMT_CLU_INCM_COHRNT:
			case SFI_HSTGRM_RMT_SSM_INCM_COHRNT:
				*softsp->wci_sfi_ctr0_match_vaddr =
				    ((uint64_t)(softsp->node_id)
				    << WCI_SFI_ATRANS_DEVID_SHIFT) &
				    wci_sfi_ctr_regs_tab[id0-1].
				    wci_sfi_ctr_match_val;
				break;
			default:
				*softsp->wci_sfi_ctr0_match_vaddr =
				    wci_sfi_ctr_regs_tab[id0-1].
				    wci_sfi_ctr_match_val;
				break;
			}
		}

		evt1 = softsp->wci_sfi_sw_ctr_ctl & WCI_SFI_CTR1_EVENT_MASK;
		id1 = (uint_t)(evt1 >> WCI_SFI_CTR1_EVENT_SHIFT);
		if (evt1 > 0) {
			/* safri histogramming counter 1 */
			*softsp->wci_sfi_ctr1_mask_vaddr =
			    wci_sfi_ctr_regs_tab[id1-1].wci_sfi_ctr_mask_val;
			*softsp->wci_sfi_ctr1_match_transaction_vaddr =
			    wci_sfi_ctr_regs_tab[id1-1].
			    wci_sfi_ctr_match_trans_val;

			switch (evt1 >> 4) {
			case SFI_HSTGRM_LOCAL_INT:
				*softsp->wci_sfi_ctr1_match_vaddr =
				    (softsp->node_id <<
					WCI_SFI_ADDR_TNID_SHIFT) &
				    wci_sfi_ctr_regs_tab[id1-1].
				    wci_sfi_ctr_match_val;
				break;
			case SFI_HSTGRM_RMT_CLU_INCM_INT:
			case SFI_HSTGRM_RMT_SSM_INCM_INT:
			case SFI_HSTGRM_RMT_SSM_INCM_IO:
			case SFI_HSTGRM_RMT_CLU_INCM_COHRNT:
			case SFI_HSTGRM_RMT_SSM_INCM_COHRNT:
				*softsp->wci_sfi_ctr1_match_vaddr =
				    ((uint64_t)(softsp->node_id)
					<< WCI_SFI_ATRANS_DEVID_SHIFT) &
				    wci_sfi_ctr_regs_tab[id1-1].
				    wci_sfi_ctr_match_val;
				break;
			default:
				*softsp->wci_sfi_ctr1_match_vaddr =
				    wci_sfi_ctr_regs_tab[id1-1].
				    wci_sfi_ctr_match_val;
				break;
			}
		}
	} else {
		/*
		 * Copy the current state of the hardware into the kstat
		 * structure. Here for safari histogram counter control, we
		 * need to copy the combination of wci_misc_ctr_ctl bits
		 * <19:0> and wci_sfi_sw_ctr_ctl bits <27:20> because the
		 * busstat needs a way to find out whether another process
		 * has changed wci_misc_ctr_ctl to count other events. When
		 * using safari histogramming counter, wci_misc_ctr_ctl must
		 * select agent 0, and event 0 or 1. If another process choose
		 * other agent or event by manipulating misc device, then the
		 * user who is monitoring sfi device should be notified.
		 */
		wci_sfi_ksp->wci_ctr_ctl.value.ui64 =
		    ((((uint64_t)*(softsp->wci_misc_ctr_ctl_vaddr)) &
			WCI_SFI_SW_CTR_CTL_MASK) |
			(softsp->wci_sfi_sw_ctr_ctl &
			    (~WCI_SFI_SW_CTR_CTL_MASK)));
		wci_sfi_ksp->wci_ctr0.value.ui64 =
		    (*(softsp->wci_misc_ctr_vaddr)) & WCI_PIC0_MASK;
		wci_sfi_ksp->wci_ctr1.value.ui64 =
		    (*(softsp->wci_misc_ctr_vaddr)) >> 32;
	}

	return (0);
}


void wci_del_counters_kstats(struct wci_common_soft_state *softsp) {

	struct kstat *wci_ksp;
	int link_no;

	/* remove "link" counters kstat */
	for (link_no = 0; link_no < WCI_NUM_LINKS; link_no++) {
		wci_ksp = softsp->wci_link_counters_ksp[link_no];
		softsp->wci_link_counters_ksp[link_no] = NULL;
		if (wci_ksp != NULL) {
			ASSERT(wci_ksp->ks_private == (void *)softsp);
			kstat_delete(wci_ksp);
		}
	}

	/* remove "lpbk" counters kstat */
	wci_ksp = softsp->wci_lpbk_counters_ksp;
	softsp->wci_lpbk_counters_ksp = NULL;
	if (wci_ksp != NULL) {
		ASSERT(wci_ksp->ks_private == (void *)softsp);
		kstat_delete(wci_ksp);
	}

	/* remove "misc" counters kstat */
	wci_ksp = softsp->wci_misc_counters_ksp;
	softsp->wci_misc_counters_ksp = NULL;
	if (wci_ksp != NULL) {
		ASSERT(wci_ksp->ks_private == (void *)softsp);
		kstat_delete(wci_ksp);
	}

	/* remove "sfi" counters kstat */
	wci_ksp = softsp->wci_sfi_counters_ksp;
	softsp->wci_sfi_counters_ksp = NULL;
	if (wci_ksp != NULL) {
		ASSERT(wci_ksp->ks_private == (void *)softsp);
		kstat_delete(wci_ksp);
	}
}

void wci_del_picN_kstats() {

	int pic, link_no;

	/* remove "link" picN kstat */
	for (link_no = 0; link_no < WCI_NUM_LINKS; link_no++) {
		for (pic = 0; pic < WCI_NUM_PICS; pic++) {
			if (wci_link_pic_ksp[link_no][pic] !=
			    (kstat_t *)NULL) {
				kstat_delete(wci_link_pic_ksp[link_no][pic]);
				wci_link_pic_ksp[link_no][pic] = NULL;
			}
		}
	}

	for (pic = 0; pic < WCI_NUM_PICS; pic++) {
		/* remove "lpbk" picN kstat */
		if (wci_lpbk_pic_ksp[pic] != (kstat_t *)NULL) {
			kstat_delete(wci_lpbk_pic_ksp[pic]);
			wci_lpbk_pic_ksp[pic] = NULL;
		}
		/* remove "misc" picN kstat */
		if (wci_misc_pic_ksp[pic] != (kstat_t *)NULL) {
			kstat_delete(wci_misc_pic_ksp[pic]);
			wci_misc_pic_ksp[pic] = NULL;
		}
		/* remove "sfi" picN kstat */
		if (wci_sfi_pic_ksp[pic] != (kstat_t *)NULL) {
			kstat_delete(wci_sfi_pic_ksp[pic]);
			wci_sfi_pic_ksp[pic] = NULL;
		}
	}
}
