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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _WCI_COMMON_H
#define	_WCI_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/kstat.h>
#include <sys/wci_offsets.h>

/*
 * From PRM, 0 indicates a paroli that is present. This is set in
 * Wci register:  wci_sw_link_status, field: paroli_present
 * such that, when paroli_present == 0 the paroli IS present.
 */
#define	WCI_PAROLI_PRESENT	0

#define	WCI_ID_WCI1		0x14776049
#define	WCI_ID_WCI2		0x14147049
#define	WCI_ID_WCI3		0x14063049
#define	WCI_ID_WCI31		0x24063049
#define	WCI_ID_WCI4		0x14478049
#define	WCI_ID_WCI41		0x24478049

/* stripe bits */
#define	WCI_OFF			0x0
#define	WCI_STRIPE_NONE		0xf
#define	WCI_STRIPE_2WAY_EVEN	0x3
#define	WCI_STRIPE_2WAY_ODD	0xc
#define	WCI_STRIPE_4WAY_0	0x1
#define	WCI_STRIPE_4WAY_1	0x2
#define	WCI_STRIPE_4WAY_2	0x4
#define	WCI_STRIPE_4WAY_3	0x8

/* For cluster mode striping, WCI uses addr bits 7 and 8, link uses 9 and 10 */
#define	WCI_CLUSTER_STRIPE_STRIDE	(1 << 7)
#define	WCI_CLUSTER_STRIPE_MASK		0x0780 /* Bits 7-10 set */

#define	WCI_ERRPAGE_CESR_OFFSET		0
#define	WCI_ERRPAGE_CLUSTER_ERROR_OFFSET 64	/* byte offset into CESR page */

/* CESR values */
#define	WCI_CESR_NO_ERRORS		0x0
#define	WCI_CESR_PASSTHRU_CAG_ERROR	0x1
#define	WCI_CESR_CMMU_ACCESS_VIOLATION	0x2
#define	WCI_CESR_DEST_CAG_BUSY		0x3
#define	WCI_CESR_USER_ERROR_BIT_SET	0x4
#define	WCI_CESR_PAUSE_REPLY		0x5
#define	WCI_CESR_PASSTHRU_RAG_ERROR	0x6
#define	WCI_CESR_TOO_MANY_PASSTHRU_HOPS	0x7
#define	WCI_CESR_INTR_DEST_BUSY		0x8
#define	WCI_CESR_INVALID_TRANSACTION	0x9
#define	WCI_CESR_RAG_READ_TIMEOUT	0xA
#define	WCI_CESR_RAG_DATA_ERROR		0xB
#define	WCI_CESR_RAG_WRITE_TIMEOUT	0xC
#define	WCI_CESR_RESERVED_13		0xD
#define	WCI_CESR_RESERVED_14		0xE
#define	WCI_CESR_RESERVED_15		0xF
#define	WCI_CESR_BUSY_TOO_LONG		(-1) /* Software can't read CESR */

#define	WCI_NUM_LINKS	ENTRIES_WCI_SW_LINK_ERROR_COUNT

/* WCI ECC error handling support */

/* this is needed for number of errors */
#define	ECC_MAX_CNT		0xff /* maximum ecc count */
/*
 * PA[42:4] represent the address fields defined in Safari interface.
 * In cacheable address space or flush address space, PA[41:38] represents
 * the SSM node id
 */
#define	SAFARI_ADDR_FIELDS_MASK	0x000007FFFFFFFFF0ULL
#define	WCI_ECC_NODE_ID_MASK	0x000003C000000000ULL

/*
 * In wci_dco_state, the following bit fields indentify Agent ID.
 *
 * mtag_ecc_error_aid  <41:35>
 * data_ecc_error_aid  <34:28>
 *
 * Agent ID for Mtag/data ecc error encoding is in
 * binary, where "nnn" denote instance id used by the agent :
 *
 * 0000000 = rsrvd
 * 0000001 = Csr_Agent
 * 0000010 = Modifier_Logic
 * 0000011-0010111 = rsrvd
 * 0011nnn = Slave_Agent
 * 01nnnnn = Request_Agent
 * 10nnnnn = Cluster_Agent
 * 11nnnnn = Home_Agent
 *
 */
#define	CSR_AGENT_MASK	0x01
#define	SLAVE_AGENT_MASK	0x18
#define	REQUEST_AGENT_MASK	0x20
#define	CLUSTER_AGENT_MASK	0x40
#define	HOME_AGENT_MASK		0x60
#define	REQ_CLUSTER_MASK	0x60

#define	CSR_AGENT	1
#define	SLAVE_AGENT	2
#define	REQUEST_AGENT	3
#define	CLUSTER_AGENT	4
#define	HOME_AGENT	5

#define	ECC_MTAG_UE	1
#define	ECC_MTAG_CE	2
#define	ECC_DATA_UE	3
#define	ECC_DATA_CE	4


/*
 * define which agent has what type of ECC error so that
 * we can log them explicitely in wci_log_ce_error().
 *
 * when calling ce_error(), cheetah has to make a distinction when decoding
 * the syndrome of the error: data or mtag. in order to comply with cheetah
 * semantics, we set the high bits of the flt_stat field similar to afsr reg:
 */

#define	RA_ECC_MTAG_UE	(0x1 | C_AFSR_EMU)
#define	RA_ECC_MTAG_CE	(0x2 | C_AFSR_EMC)
#define	RA_ECC_DATA_UE	(0x4 | C_AFSR_UE)
#define	RA_ECC_DATA_CE	(0x8 | C_AFSR_CE)

#define	HA_ECC_MTAG_UE	(0x10 | C_AFSR_EMU)
#define	HA_ECC_MTAG_CE	(0x20 | C_AFSR_EMC)
#define	HA_ECC_DATA_UE	(0x40 | C_AFSR_UE)
#define	HA_ECC_DATA_CE	(0x80 | C_AFSR_CE)

#define	SA_ECC_MTAG_UE	(0x100 | C_AFSR_EMU)
#define	SA_ECC_MTAG_CE	(0x200 | C_AFSR_EMC)
#define	SA_ECC_DATA_UE	(0x400 | C_AFSR_UE)
#define	SA_ECC_DATA_CE	(0x800 | C_AFSR_CE)

#define	CA_ECC_MTAG_UE	(0x1000 | C_AFSR_EMU)
#define	CA_ECC_MTAG_CE	(0x2000 | C_AFSR_EMC)
#define	CA_ECC_DATA_UE	(0x4000 | C_AFSR_UE)
#define	CA_ECC_DATA_CE	(0x8000 | C_AFSR_CE)

#define	CA_ECC_NOTPASS	0x10000

/*
 * define which type of SRAM error occured
 */
#define	SRAM_ECC_CE_DATA	0x20000
#define	SRAM_ECC_UE_ADDR	0x40000
#define	SRAM_ECC_UE_CAG		0x80000
#define	SRAM_ECC_UE_CSRA	0x100000
#define	SRAM_ECC_UE_RAG		0x200000
#define	SRAM_ECC_UE_SAG		0x400000
#define	SRAM_PARITY_HAG		0x800000

/*
 * need ECC error status - ecc.status for wci, plan to add in async.h,
 * for now, we just add here
 */
#define	ECC_WCI		0x80
#define	ECC_WCI_SRAM	0x200
/*
 * register wci_dco_state logs only mtag/data first CE (UE overwrites CE)
 * syndrome for all agent types. Thus, except 1st error, all other ECC
 * errors don't have a syndrome corresponding with them, thus NO_SYNDROME
 * for these NO_SYNDROME ECC errors, even we schedule scrubbing, they can't
 * be scrubbed i.e, corrected, because of no syndrome
 *
 */
#define	NO_SYNDROME	((ushort_t)-1)

/*
 * syndrome can be logged in either part of the wci_dco_state register
 * depending on which cacheline it came from
 */
#define	WCI_MTAG_SYNDROME(r) \
	(r.bit.mtag_syndrome_0 ? r.bit.mtag_syndrome_0 : r.bit.mtag_syndrome_1)
#define	WCI_DATA_SYNDROME(r) \
	(r.bit.data_syndrome_0 ? r.bit.data_syndrome_0 : r.bit.data_syndrome_1)

#define	WCI_CTRCTL_KSTAT_NAMED  "pcr"           /* "wci_ctr_ctl" */
#define	WCI_CTR0_KSTAT_NAMED    "pic0"          /* "wci_ctr0" */
#define	WCI_CTR1_KSTAT_NAMED    "pic1"          /* "wci_ctr1" */

#define	WCI_NUM_PICS    2
#define	WCI_MISC_NUM_EVENTS  350  /* Max number of events in Misc Counter */
#define	WCI_LINK_NUM_EVENTS  0x13 /* Max number of events in Link Counter */
#define	WCI_LPBK_NUM_EVENTS  0x17 /* Max number of events in Lpbk Counter */

#define	WCI_SFI_NUM_EVENTS   0xb /* Max # of evts in safari histogram counter */


#define	WCI_DURATION_BIT	0x100000

#define	WCI_PIC0_MASK	0x00000000FFFFFFFFULL  /* pic0 bits of %pic */
#define	WCI_PIC0_CTR_CTL_MASK	0x000000000000FFFFULL
#define	WCI_PIC1_CTR_CTL_MASK	0x00000000FFFF0000ULL
#define	WCI_CLUSTER_MASK	0x00000000000000FFULL

/*
 * used to build array of event-names and pcr-mask values
 */
typedef struct wci_event_mask {
	char *event_name;
	uint64_t pcr_mask;
} wci_event_mask_t;


/* common soft state hook for either wrsm or wssm */
struct wci_common_soft_state {
	int instance;  /* device instance */
	int node_id;    /* ssm node id */
	uint32_t local_aid;  /* safari local agent id */
	volatile unsigned char *wci_regs;  /* vaddr of wrsm/wssm base regs */
	/* Mapped addresses of registers */
	volatile uint64_t *wci_misc_ctr_vaddr;
	volatile uint64_t *wci_misc_ctr_ctl_vaddr;
	volatile uint64_t *wci_cluster_ctr_ctl_vaddr;
	volatile uint64_t *wci_link_ctr_vaddr[WCI_NUM_LINKS];
	volatile uint64_t *wci_link_ctr_ctl_vaddr[WCI_NUM_LINKS];
	volatile uint64_t *wci_lpbk_ctr_vaddr;
	volatile uint64_t *wci_lpbk_ctr_ctl_vaddr;
	volatile uint64_t *wci_sfi_ctr0_mask_vaddr;
	volatile uint64_t *wci_sfi_ctr0_match_vaddr;
	volatile uint64_t *wci_sfi_ctr0_match_transaction_vaddr;
	volatile uint64_t *wci_sfi_ctr1_mask_vaddr;
	volatile uint64_t *wci_sfi_ctr1_match_vaddr;
	volatile uint64_t *wci_sfi_ctr1_match_transaction_vaddr;
	/* performace counters kstat */
	kstat_t *wci_misc_counters_ksp;
	kstat_t *wci_lpbk_counters_ksp;
	kstat_t *wci_link_counters_ksp[WCI_NUM_LINKS];
	/* wci safari histogramming kstat */
	kstat_t *wci_sfi_counters_ksp;
	/*
	 * wci safari histogramming counter control value.  It is a
	 * software simulation of a hardware counter control register
	 * to make busstat happy.
	 */
	uint64_t wci_sfi_sw_ctr_ctl;


	/* A running SUM of the number of link errors since power-on */
	uint64_t wci_sw_link_error_count_sum[WCI_NUM_LINKS];

} wci_common_softstate_t;


/*
 * Global Function prototypes
 */
void wci_add_counters_kstats(struct wci_common_soft_state *, char *drvname);
void wci_add_picN_kstats(char *drvname);
void wci_del_counters_kstats(struct wci_common_soft_state *);
void wci_del_picN_kstats();
struct async_flt;
void wci_log_ce_error(struct async_flt *ecc, char *unum);

/*
 * Misc Counter
 * Agent Type -- 0: SFI, 1: Cluster Agent, 2: DC, 3: Request Agent,
 *               4: Home Agent, 5: Slave Agent, 6: Cache Controller,
 *               7: SFQ, 8: HLI, 9: LC
 */
/* SFI Event Control --- agent = 0 */
/* Safari Event Encoding */
#define	SFI_SFI_HISTOGRAM0	0x000
#define	SFI_SFI_HISTOGRAM1	0x001
#define	SFI_ATRANSID_ALLOC_1	0x002
#define	SFI_ATRANSID_ALLOC_4	0x003
#define	SFI_ATRANSID_ALLOC_8	0x004
#define	SFI_ATRANSID_ALLOC_10	0x005
#define	SFI_ATRANSID_ALLOC_12	0x006
#define	SFI_ATRANSID_DEALLOC	0x007
#define	SFI_TARGID_ALLOC_0	0x008
#define	SFI_TARGID_ALLOC_2	0x009
#define	SFI_TARGID_ALLOC_8	0x00a
#define	SFI_TARGID_DEALLOC	0x00b
#define	SFI_P0_REQ_VALID	0x00c
#define	SFI_P1_REQ_VALID	0x00d
#define	SFI_P2_REQ_VALID	0x00e
#define	SFI_P3_REQ_VALID	0x00f
#define	SFI_P4_REQ_VALID	0x010
#define	SFI_P5_REQ_VALID	0x011
#define	SFI_P6_REQ_VALID	0x012
#define	SFI_P7_REQ_VALID	0x013
#define	SFI_P8_REQ_VALID	0x014
#define	SFI_P9_REQ_VALID	0x015
#define	SFI_P10_REQ_VALID	0x016
#define	SFI_P11_REQ_VALID	0x017
#define	SFI_P12_REQ_VALID	0x018
#define	SFI_P0_GRANT	0x019
#define	SFI_P1_GRANT	0x01a
#define	SFI_P2_GRANT	0x01b
#define	SFI_P3_GRANT	0x01c
#define	SFI_P4_GRANT	0x01d
#define	SFI_P5_GRANT	0x01e
#define	SFI_P6_GRANT	0x01f
#define	SFI_P7_GRANT	0x020
#define	SFI_P8_GRANT	0x021
#define	SFI_P9_GRANT	0x022
#define	SFI_P10_GRANT	0x023
#define	SFI_P11_GRANT	0x024
#define	SFI_P12_GRANT	0x025
#define	SFI_SFI_PULL_REQ	0x026
#define	SFI_SFI_PULL_GRANT	0x027
/* Safari Durations */
/* cnt1 */
#define	SFI_ATRANSID_ALLOC_1_DURATION	0x00100800
#define	SFI_ATRANSID_ALLOC_4_DURATION	0x00100c00
#define	SFI_ATRANSID_ALLOC_8_DURATION	0x00101000
#define	SFI_ATRANSID_ALLOC_10_DURATION	0x00101400
#define	SFI_ATRANSID_ALLOC_12_DURATION	0x00101800
#define	SFI_TARGID_ALLOC_0_DURATION	0x00102000
#define	SFI_TARGID_ALLOC_2_DURATION	0x00102400
#define	SFI_TARGID_ALLOC_8_DURATION	0x00102800
/* cnt 0 */
#define	SFI_ATRANSID_DEALLOC_DURATION	0x00100007
#define	SFI_TARGID_DEALLOC_DURATION	0x0010000b

/* DC Event Control ---  agent = 2 */
/* DC Event Encoding */
#define	DC_DIF_OUTPUT_VALID	0x080
#define	DC_SFI_DATA_GRANT	0x081

/* LC Event Count --- agent = 9 */
/* LC Event Encoding */
#define	LC_DIF_PUSH	0x240
#define	LC_COM_VALID_LINKS_DIF_FULL	0x241
#define	LC_DATA_PKT_FR_NODE	0x242
#define	LC_SFI_DATA_CANCEL	0x243

/* SFQ Event Control --- agent = 7 */
/* SFQ Event Encoding */
#define	SFQ_PIQ_PUSH	0x1c0
#define	SFQ_PIQ_POP	0x1c1
#define	SFQ_NIQ_PUSH	0x1c2
#define	SFQ_NIQ_POP	0x1c3
#define	SFQ_SIQ_PUSH	0x1c4
#define	SFQ_SIQ_POP	0x1c5

/* HLI Event Control --- agent = 8 */
/* HLI Event Encoding */
#define	HLI_SLQ_PUSH	0x200
#define	HLI_SLQ_POP	0x201
#define	HLI_CHQ_PUSH	0x202
#define	HLI_CHQ_POP	0x203
#define	HLI_PHQ_PUSH	0x204
#define	HLI_PHQ_POP	0x205

/* Cacahe Controller Event Control --- agent = 6 */
/* Cache Control Event Encoding */
#define	CACHECTL_CLUST0	0x180
#define	CACHECTL_CLUST1	0x181
#define	CACHECTL_CLUST_CWR	0x01000000ULL
#define	CACHECTL_CLUST_CRD	0x02000000ULL
#define	CACHECTL_CLUST_CRD_CWR	0x03000000ULL
#define	CACHECTL_CLUST_AT	0x04000000
#define	CACHECTL_CLUST_AT_CWR	0x05000000ULL
#define	CACHECTL_CLUST_AT_CRD	0x06000000ULL
#define	CACHECTL_CLUST_AT_CRD_CWR	0x07000000ULL
#define	CACHECTL_CLUST_INT	0x08000000ULL
#define	CACHECTL_CLUST_INT_CWR	0x09000000ULL
#define	CACHECTL_CLUST_INT_CRD	0x0a000000ULL
#define	CACHECTL_CLUST_INT_CRD_CWR	0x0b000000ULL
#define	CACHECTL_CLUST_INT_AT	0x0c000000ULL
#define	CACHECTL_CLUST_INT_AT_CWR	0x0d000000ULL
#define	CACHECTL_CLUST_INT_AT_CRD	0x0e000000ULL
#define	CACHECTL_CLUST_INT_AT_CRD_CWR	0x0f000000ULL
#define	CACHECTL_CACHE_CYL_USED	0x182
#define	CACHECTL_LPA2GA_LOOKUP	0x183
#define	CACHECTL_GA2LPA_ACCESS	0x184
#define	CACHECTL_GA2LPA_LOOKUP	0x185
#define	CACHECTL_GA2LPA_MISS	0x186
#define	CACHECTL_DIR_LOOKUP	0x187
#define	CACHECTL_DIR_MISS	0x188
#define	CACHECTL_DIR_WRTBK	0x189
#define	CACHECTL_CMMU_ACCESS	0x18a
#define	CACHECTL_CMMU_LOOKUP	0x18b
#define	CACHECTL_CSR_LOOKUP	0x18c
#define	CACHECTL_CNT_ALWYS	0x18d
#define	CACHECTL_HAG_REQ_VALID	0x18e
#define	CACHECTL_CIQ_REQ_VALID	0x18f
#define	CACHECTL_SLQ_REQ_VALID	0x190

/* Cluster Agent Event Control --- agent = 1 */
/* Cluster Agent Event Encoding */
#define	CLUSTER_AGENT_ALLOC	0x040
#define	CLUSTER_AGENT_RETIRED	0x041
#define	CLUSTER_SFI_GRANT_RD	0x042
#define	CLUSTER_SFI_GRANT_WR	0x043
#define	CLUSTER_PULL_SEEN	0x044
#define	CLUSTER_1DC_RCV_ACK	0x045
#define	CLUSTER_2DC_SND_ACK	0x046
#define	CLUSTER_1_CPI_RCV_ACK	0x047
#define	CLUSTER_2_CPI_RCV_ACK	0x048
#define	CLUSTER_PKT_QUE_ODD	0x049
#define	CLUSTER_PKT_QUE_EVEN	0x04a
#define	CLUSTER_PKT_SENT_ODD	0x04b
#define	CLUSTER_PKT_SENT_EVEN	0x04c
#define	CLUSTER_HLI_REQ_0	0x04d
#define	CLUSTER_HLI_REQ_1	0x04e
#define	CLUSTER_HLI_REQ_2	0x04f
#define	CLUSTER_HLI_REQ_3	0x050
#define	CLUSTER_HLI_REQ_4	0x051
#define	CLUSTER_HLI_REQ_5	0x052
#define	CLUSTER_HLI_GRANT_0	0x053
#define	CLUSTER_HLI_GRANT_1	0x054
#define	CLUSTER_HLI_GRANT_2	0x055
#define	CLUSTER_HLI_GRANT_3	0x056
#define	CLUSTER_HLI_GRANT_4	0x057
#define	CLUSTER_HLI_GRANT_5	0x058
/* Cluster Agent Durations */
/* cnt1 */
#define	CLUSTER_AGENT_ALLOC_DURATION	0x00110000
#define	CLUSTER_SFI_GRANT_RD_DURATION	0x00110800
#define	CLUSTER_SFI_GRANT_WR_DURATION	0x00110c00
#define	CLUSTER_1DC_RCV_ACK_CNT1_DURATION	0x00111400
#define	CLUSTER_PKT_QUE_ODD_DURATION	0x00112400
#define	CLUSTER_PKT_QUE_EVEN_DURATION	0x00112800
#define	CLUSTER_HLI_GRANT_0_DURATION	0x00114c00
#define	CLUSTER_HLI_GRANT_1_DURATION	0x00115000
#define	CLUSTER_HLI_GRANT_2_DURATION	0x00115400
#define	CLUSTER_HLI_GRANT_3_DURATION	0x00115800
#define	CLUSTER_HLI_GRANT_4_DURATION	0x00115c00
#define	CLUSTER_HLI_GRANT_5_DURATION	0x00116000
#define	CLUSTER_1_CPI_RCV_ACK_CNT1_DURATION	0x00111c00
/* cnt0 */
#define	CLUSTER_AGENT_RETIRED_DURATION	0x00100041
#define	CLUSTER_PULL_SEEN_DURATION	0x00100044
#define	CLUSTER_1DC_RCV_ACK_CNT0_DURATION	0x00100045
#define	CLUSTER_2DC_SND_ACK_DURATION	0x00100046
#define	CLUSTER_PKT_SENT_ODD_DURATION	0x0010004b
#define	CLUSTER_PKT_SENT_EVEN_DURATION	0x0010004c
#define	CLUSTER_1_CPI_RCV_ACK_CNT0_DURATION	0x00100047
#define	CLUSTER_2_CPI_RCV_ACK_DURATION	0x00100048


/* Request Agent Event Control --- agent = 3 */
/* Request Agent Event Encoding */
#define	REQ_AGENT_ALLOC	0x0c0
#define	REQ_AGENT_RETIRED	0x0c1
#define	REQ_SFI_GRANT_P2	0x0c2
#define	REQ_1DC_RCV_ACK	0x0c3
#define	REQ_2DC_SND_ACK	0x0c4
#define	REQ_1_CPI_RCV_ACK	0x0c5
#define	REQ_2_CPI_RCV_ACK	0x0c6
#define	REQ_PKT_QUE	0x0c7
#define	REQ_PKT_SENT	0x0c8
#define	REQ_PKT_SENT_CLUST_RD	0x0c9
#define	REQ_PKT_SENT_CLUST_WR	0x0ca
#define	REQ_HLI_REQ_0	0x0cb
#define	REQ_HLI_REQ_1	0x0cc
#define	REQ_HLI_REQ_2	0x0cd
#define	REQ_HLI_REQ_3	0x0ce
#define	REQ_HLI_REQ_4	0x0cf
#define	REQ_HLI_REQ_5	0x0d0
#define	REQ_HLI_GRANT_0	0x0d1
#define	REQ_HLI_GRANT_1	0x0d2
#define	REQ_HLI_GRANT_2	0x0d3
#define	REQ_HLI_GRANT_3	0x0d4
#define	REQ_HLI_GRANT_4	0x0d5
#define	REQ_HLI_GRANT_5	0x0d6
#define	REQ_LAST_REPLY_RCVD	0x0d7
#define	REQ_SENT_CLUST_RD	0x0d8
#define	REQ_SENT_CLUST_WR	0x0d9
#define	REQ_PIQ_VALID	0x0da
#define	REQ_PIQ_DISPATCH	0x0db
#define	REQ_CIQ_VALID	0x0dc
#define	REQ_CIQ_DISPATCH	0x0dd
#define	REQ_NIQ_VALID	0x0de
#define	REQ_NIQ_DISPATCH	0x0df
#define	REQ_NUMA_BYPASS_DISPATCH	0x0e0
/* Request Agent Durations */
/* cnt 1 */
#define	REQ_AGNT_ALLOC_DURATION	0x00130000
#define	REQ_SFI_GRANT_P2_DURATION	0x00130800
#define	REQ_1DC_RCV_ACK_CNT1_DURATION	0x00130c00
#define	REQ_PKT_SENT_CLUST_RD_DURATION  0x00132400
#define	REQ_1_CPI_RCV_ACK_CNT1_DURATION	0x00131400
#define	REQ_PKT_QUE_DURATION	0x00131c00
#define	REQ_PKT_SENT_CNT1_DURATION	0x00132000
/* cnt 0 */
#define	REQ_AGNT_RETIRED_DURATION	0x001000c1
#define	REQ_1DC_RCV_ACK_CNT0_DURATION	0x001000c3
#define	REQ_2DC_SND_ACK_DURATION	0x001000c4
#define	REQ_1_CPI_RCV_ACK_CNT0_DURATION	0x001000c5
#define	REQ_2_CPI_RCV_ACK_DURATION	0x001000c6
#define	REQ_PKT_SENT_CNT0_DURATION	0x001000c8
#define	REQ_LAST_REPLY_RCVD_DURATION	0x001000d7


/* Home Agent Event Control --- agent = 4 */
/* Home Agent Event Encoding */
#define	HOME_AGENT_ALLOC	0x100
#define	HOME_AGENT_RETIRED	0x101
#define	HOME_SFI_P8_RD_AUX	0x102
#define	HOME_SFI_P8_RD_MAIN	0x103
#define	HOME_SFI_P8_WR	0x104
#define	HOME_SFI_P9_WR	0x105
#define	HOME_SFI_P10_WR	0x106
#define	HOME_1DC_RCV_ACK_AUX	0x107
#define	HOME_1DC_RCV_ACK_MAIN	0x108
#define	HOME_2DC_SND_ACK	0x109
#define	HOME_SFI_PULL_SEEN	0x10a
#define	HOME_LAST_DEMREP_SENT	0x10b
#define	HOME_COMP_PKT_SEEN	0x10c
#define	HOME_HLI_REQ_LINK_0_A	0x10d
#define	HOME_HLI_REQ_LINK_0_B	0x10e
#define	HOME_HLI_REQ_LINK_1_A	0x10f
#define	HOME_HLI_REQ_LINK_1_B	0x110
#define	HOME_HLI_REQ_LINK_2_A	0x111
#define	HOME_HLI_REQ_LINK_2_B	0x112
#define	HOME_HLI_REQ_LINK_3_A	0x113
#define	HOME_HLI_REQ_LINK_3_B	0x114
#define	HOME_HLI_REQ_LINK_4_A	0x115
#define	HOME_HLI_REQ_LINK_4_B	0x116
#define	HOME_HLI_REQ_LINK_5_A	0x117
#define	HOME_HLI_REQ_LINK_5_B	0x118
#define	HOME_HLI_GRANT_LINK_0_A	0x119
#define	HOME_HLI_GRANT_LINK_0_B	0x11a
#define	HOME_HLI_GRANT_LINK_1_A	0x11b
#define	HOME_HLI_GRANT_LINK_1_B	0x11c
#define	HOME_HLI_GRANT_LINK_2_A	0x11d
#define	HOME_HLI_GRANT_LINK_2_B	0x11e
#define	HOME_HLI_GRANT_LINK_3_A	0x11f
#define	HOME_HLI_GRANT_LINK_3_B	0x120
#define	HOME_HLI_GRANT_LINK_4_A	0x121
#define	HOME_HLI_GRANT_LINK_4_B	0x122
#define	HOME_HLI_GRANT_LINK_5_A	0x123
#define	HOME_HLI_GRANT_LINK_5_B	0x124
#define	HOME_BLK_CAM_HIT	0x125
#define	HOME_DIR_RTNED_BEFORE_RD_GRANT	0x126
#define	HOME_DIR_RTNED_BEFORE_RD_ORDER	0x127
#define	HOME_DIR_RTNED_BEFORE_RD_DATA	0x128
#define	HOME_DIR_RTNED_AFTER_RD_DATA	0x129
#define	HOME_REQ_HOME	0x12a
#define	HOME_REQ_SAME_BOX	0x12b
#define	HOME_REF_DATA_BACK_HOME	0x12c
#define	HOME_DIR_MISS_ALLOC	0x12d
#define	HOME_DIR_HIT_GI	0x12e
#define	HOME_DIR_HIT_GS	0x12f
#define	HOME_DIR_HIT_GM	0x130
#define	HOME_DIR_HIT_RTO_GM	0x131
#define	HOME_DIR_HIT_RTS_GMS	0x132
#define	HOME_DIR_MISS_RTS_GI	0x133
#define	HOME_DIR_MISS_RTS	0x134
#define	HOME_DIR_MISS_RTO_GS_GI	0x135
#define	HOME_DIR_MISS_RTO	0x136
/* Home Agent Metrics, Durations Mode */
/* cnt 1 */
#define	HOME_AGENT_ALLOC_DURATION	0x00140000
#define	HOME_SFI_P8_RD_AUX_DURATION	0x00140800
#define	HOME_SFI_P8_RD_MAIN_DURATION	0x00140c00
#define	HOME_1DC_RCV_ACK_AUX_CNT1_DURATION	0x00141c00
#define	HOME_1DC_RCV_ACK_MAIN_CNT1_DURATION	0x00142000
#define	HOME_SFI_P8_WR_DURATION	0x00141000
#define	HOME_SFI_P9_WR_DURATION	0x00141400
#define	HOME_SFI_P10_WR_DURATION	0x00141800
#define	HOME_LAST_DEMREP_SENT_DURATION	0x00142c00
/* cnt 0 */
#define	HOME_AGENT_RETIRED_DURATION	0x00100101
#define	HOME_1DC_RCV_ACK_AUX_CNT0_DURATION	0x00100107
#define	HOME_1DC_RCV_ACK_MAIN_CNT0_DURATION	0x00100108
#define	HOME_2DC_SND_ACK_DURATION	0x00100109
#define	HOME_SFI_PULL_SEEN_DURATION	0x0010010a
#define	HOME_COMP_PKT_SEEN_DURATION	0x0010010c


/* Slave Agent Event Control --- agent = 5 */
#define	SLAVE_AGENT_ALLOC	0x140
#define	SLAVE_AGENT_ALLOC_LPA	0x141
#define	SLAVE_AGENT_ALLOC_GA	0x142
#define	SLAVE_AGENT_ALLOC_H_LPA	0x143
#define	SLAVE_AGENT_ALLOC_H_GA	0x144
#define	SLAVE_AGENT_ALLOC_H_MLPA	0x145
#define	SLAVE_AGENT_ALLOC_H_MGA	0x146
#define	SLAVE_AGENT_ALLOC_H_M	0x147
#define	SLAVE_AGENT_ALLOC_H_INV_LPA	0x148
#define	SLAVE_AGENT_ALLOC_H_INV_GA	0x149
#define	SLAVE_AGENT_RETIRED	0x14a
#define	SLAVE_REPLY_SENT	0x14b
#define	SLAVE_SFI_P6_GRANT_WR	0x14c
#define	SLAVE_SFI_P12GT_RLPA	0x14d
#define	SLAVE_SFI_P12GT_RGA	0x14e
#define	SLAVE_SFI_P12GT_RHLPA	0x14f
#define	SLAVE_SFI_P12GT_RHGA	0x150
#define	SLAVE_SFI_P12GT_RHMLPA	0x151
#define	SLAVE_SFI_P12GT_RHMGA	0x152
#define	SLAVE_SFI_P12GT_WR	0x153
#define	SLAVE_1DC_RCV_ACK	0x154
#define	SLAVE_2DC_SND_ACK	0x155
#define	SLAVE_2DC_SND_ACK_REFL	0x156
#define	SLAVE_4DC_SND_ACK	0x157
#define	SLAVE_PULL_SEEN	0x158
#define	SLAVE_H_M_GA_NOT_OWND	0x159
#define	SLAVE_H_M_NO_STATE_CHANGE	0x15a
#define	SLAVE_HLI_REQ_0	0x15b
#define	SLAVE_HLI_REQ_1	0x15c
#define	SLAVE_HLI_REQ_2	0x15d
#define	SLAVE_HLI_REQ_3	0x15e
#define	SLAVE_HLI_REQ_4	0x15f
#define	SLAVE_HLI_REQ_5	0x160
#define	SLAVE_HLI_GRANT_0	0x161
#define	SLAVE_HLI_GRANT_1	0x162
#define	SLAVE_HLI_GRANT_2	0x163
#define	SLAVE_HLI_GRANT_3	0x164
#define	SLAVE_HLI_GRANT_4	0x165
#define	SLAVE_HLI_GRANT_5	0x166
/* Slave Agent Durations */
/* cnt 1 (pic1) */
#define	SLAVE_AGENT_ALLOC_DURATION	0x00150000
#define	SLAVE_SFI_P12GT_RLPA_DURATION	0x00153400
#define	SLAVE_SFI_P12GT_RGA_DURATION	0x00153800
#define	SLAVE_SFI_P12GT_RHLPA_DURATION	0x00153c00
#define	SLAVE_SFI_P12GT_RHGA_DURATION	0x00154000
#define	SLAVE_SFI_P12GT_RHMLPA_DURATION	0x00154400
#define	SLAVE_SFI_P12GT_RHMGA_DURATION	0x00154800
#define	SLAVE_1DC_RCV_ACK_CNT1_DURATION	0x00155000
#define	SLAVE_SFI_P6_GRANT_WR_DURATION	0x00153000
#define	SLAVE_SFI_P12GT_WR_DURATION	0x00154c00
#define	SLAVE_AGENT_ALLOC_LPA_DURATION	0x00150400
#define	SLAVE_AGENT_ALLOC_GA_DURATION	0x00150800
#define	SLAVE_AGENT_ALLOC_H_LPA_DURATION	0x00150c00
#define	SLAVE_AGENT_ALLOC_H_GA_DURATION	0x00151000
#define	SLAVE_AGENT_ALLOC_H_MLPA_DURATION	0x00151400
#define	SLAVE_AGENT_ALLOC_H_MGA_DURATION	0x00151800
#define	SLAVE_AGENT_ALLOC_H_M_DURATION	0x00151c00
#define	SLAVE_AGENT_ALLOC_H_INV_LPA_DURATION	0x00152000
#define	SLAVE_AGENT_ALLOC_H_INV_GA_DURATION	0x00152400
#define	SLAVE_2DC_SND_ACK_REFL_DURATION	0x00155800
/* cnt 0 (pic0) */
#define	SLAVE_AGENT_RETIRED_DURATION	0x0010014a
#define	SLAVE_1DC_RCV_ACK_CNT0_DURATION	0x00100154
#define	SLAVE_2DC_SND_ACK_DURATION	0x00100155
#define	SLAVE_PULL_SEEN_DURATION	0x00100158
#define	SLAVE_REPLY_SENT_DURATION	0x0010014b
#define	SLAVE_4DC_SND_ACK_DURATION	0x00100157

/* Misc counter pic0 clear mask */
#define	MISC_CLEAR_PIC0	~(0x0f1003ffULL)
/* Misc counter pic1 clear mask */
#define	MISC_CLEAR_PIC1	~(0xf01ffc00ULL)



/* Link Counter */
#define	LINK_SENDING_ADMIN_PKTS	0x01
#define	LINK_RCVD_MH_DATA_PKT	0x02
#define	LINK_RMHDP_SADM	0x03
#define	LINK_RCVD_DATA_PKT	0x04
#define	LINK_RDP_SADM	0x05
#define	LINK_RDP_RMHDP	0x06
#define	LINK_REJECTED_FLIT	0x08
#define	LINK_REJFLIT_SADM	0x09
#define	LINK_REJFLIT_RMHDP	0x0a
#define	LINK_REJFLIT_RMHDP_SADM	0x0b
#define	LINK_REJFLIT_RDP	0x0c
#define	LINK_REJFLIT_RDP_SADM	0x0d
#define	LINK_RCVD_ADMIN_PKT	0x10
#define	LINK_RADMP_SADM	0x11
#define	LINK_RADMP_RMHDP	0x12
#define	LINK_RADMP_RMHDP_SADM	0x13
#define	LINK_RADMP_RDP	0x14
#define	LINK_RADMP_RDP_SADM	0x15
#define	LINK_RADMP_REJFLIT	0x18
#define	LINK_CLEAR_PIC0	~(0x7fffULL)
#define	LINK_CLEAR_PIC1 ~(0x7fffULL << 16)

/* Loopback Counter */
#define	LPBK_RCVD_DATA_PKT	0x01
#define	LPBK_RCVD_ADDR_2_PKT	0x02
#define	LPBK_RADDR2_RDATA	0x03
#define	LPBK_RCVD_ADDR_1_PKT	0x04
#define	LPBK_RADDR1_RDATA	0x05
#define	LPBK_DATA_LPBK_FULL	0x08
#define	LPBK_DFULL_RDATA	0x09
#define	LPBK_DFULL_RADDR2	0x0a
#define	LPBK_DFULL_RADDR2_RDATA	0x0b
#define	LPBK_DFULL_RADDR1	0x0c
#define	LPBK_DFULL_RADDR1_RDATA	0x0d
#define	LPBK_ADDR_LPBK_FULL	0x10
#define	LPBK_AFULL_RDATA	0x11
#define	LPBK_AFULL_RADDR2	0x12
#define	LPBK_AFULL_RADDR2_RDATA	0x13
#define	LPBK_AFULL_RADDR1	0x14
#define	LPBK_AFULL_RADDR1_RDATA	0x15
#define	LPBK_AFULL_DFULL	0x18
#define	LPBK_AFULL_DFULL_RDATA	0x19
#define	LPBK_AFULL_DFULL_RADDR2	0x1a
#define	LPBK_AFULL_DFULL_RADDR2_RDATA	0x1b
#define	LPBK_AFULL_DFULL_RADDR1	0x1c
#define	LPBK_AFULL_DFULL_RADDR1_RDATA	0x1d
#define	LPBK_CLEAR_PIC0	~(0x3ffULL)
#define	LPBK_CLEAR_PIC1 ~(0x3ffULL << 16)


/*
 * WCI Safari Histogramming Counter
 *
 * NOTE : wci_sfi_sw_ctr_ctl is not a real WCI HW register. It is created
 * and manipulated by kernel software  to facilitate busstat requiremnets.
 * Unlike wci_misc, wci_link & wci_lpbk performance counters, wci_sfi
 * histogramming Counter is not a real busstat-style performance counter.
 * What we do here is a SW hack to add wci_sfi histogramming Counter support
 * into busstat, as requested by Wildcat perfomance group people.
 *
 * Bits of wci_sfi_sw_ctr_ctl.
 *
 * +--------------+--------------+--------------------+--------------------+
 * | sfi_hstgrm 1 | sfi_hstgrm 0 | misc_ctr_ctl cnt1  | misc_ctr_ctl cnt0  |
 * +--------------+--------------+--------------------+--------------------+
 * 27           24 23          20 19                10 9                   0
 *
 *
 * When user select WCI Safari Histogramming Counter pic0 through busstat,
 * the corresponding wci_misc_ctr_ctl <9:0> should be set to :
 *	wci_misc_ctr_ctl.cnt0_agent_select = 0
 *	wci_misc_ctr_ctl.cnt0_event_select = 0 (safari histogram 0)
 * the counter value should be read out from wci_misc_ctr.count0.
 *
 * When user select WCI Safari Histogramming Counter pic1 through busstat,
 * the corresponding wci_misc_ctr_ctl <19:10> should be set to :
 *	wci_misc_ctr_ctl.cnt1_agent_select = 0
 *	wci_misc_ctr_ctl.cnt1_event_select = 1 (safari histogram 1)
 * the counter value should be read out from wci_misc_ctr.count1.
 *
 * Note: The event encoding values of Bit <23:20> of wci_sfi_sw_str_ctl
 * should start from 1 instead of 0 to avoid the confusion.  When user
 * selects Safari Histogram Counter pic0, the corresponding misc_ctr_ctl
 * register bits <9:0>is 0, as it represents agent 0, event 0. If
 * wci_sfi_sw_ctr_ctl bit<23:20> encoding starts from 0, then both
 * wci_sfi_sw_ctr_ctl bits <23:20> & <9:0> are all set to 0.  This could
 * be mis-understood as NO Event Selected. It is also inconvenient for us to
 * determine whether a pic counter is selected or not.
 *
 * WCI Safari Histogramming Counter Event Mask Encoding :
 *
 */
#define	SFI_HSTGRM_ALL_TRANS	0x00100000ULL
#define	SFI_HSTGRM_INT	0x00200000ULL
#define	SFI_HSTGRM_LOCAL_INT	0x00300000ULL
#define	SFI_HSTGRM_RMT_CLU_INCM_INT	0x00400000ULL
#define	SFI_HSTGRM_RMT_SSM_INCM_INT	0x00500000ULL
#define	SFI_HSTGRM_IO	0x00600000ULL
#define	SFI_HSTGRM_RMT_SSM_INCM_IO	0x00700000ULL
#define	SFI_HSTGRM_COHRNT	0x00800000ULL
#define	SFI_HSTGRM_RMT_CLU_INCM_COHRNT	0x00900000ULL
#define	SFI_HSTGRM_RMT_SSM_OTG_COHRNT	0x00a00000ULL
#define	SFI_HSTGRM_RMT_SSM_INCM_COHRNT	0x00b00000ULL
/* WCI Safari Histogramming Counter pic0 clear mask */
#define	WCI_SFI_CLEAR_PIC0 ~(0x00f003ffULL)
/* WCI Safari Histogramming Counter pic1 clear mask */
#define	WCI_SFI_CLEAR_PIC1 ~(0x0f0ffc00ULL)

/*
 * The following mask is used to obtain wci_misc_ctr_ctl bits <19:0>
 * and is also used to mask the wci_sfi_sw_ctr_ctl bits <19:0> by
 * complementing the same mask.
 */
#define	WCI_SFI_SW_CTR_CTL_MASK	0x000FFFFFULL
#define	WCI_SFI_CTR0_EVENT_SHIFT	20
#define	WCI_SFI_CTR1_EVENT_SHIFT	24
#define	WCI_SFI_CTR0_EVENT_MASK	0x00F00000ULL
#define	WCI_SFI_CTR1_EVENT_MASK	0x0F000000ULL
/*
 * wci_sfi_ctr0/1_mask, wci_sfi_ctr0/1_match bits
 *
 * E.g., For interrupt transaction type,
 *
 * Address Field <42:4> definition  <---->  Address Field <38:0> definition
 * INT :    <38:29> sender                     <34:25> sender
 *          <23:14> target                     <19:10> target
 *
 * 57   48 47 atransid   39 38             address                            0
 * +------+-------+--------+------+------+------+------+------+------+--------+
 * | mask | devID | Seq.ID |      | SNID | SAID |      | TNID | TAID |        |
 * +------+-------+--------+------+------+------+------+------+------+--------+
 * 57   48 47   43 42    39 38  35 34  30 29  25 24  20 19  15 14  10 9       0
 *
 */
#define	WCI_SFI_ADDR_TNID_SHIFT	15
#define	WCI_SFI_ATRANS_DEVID_SHIFT	43

/*
 * The following structure is used to define register wci_sfi_ctr#_mask,
 * wci_sfi_ctr#_match and wci_sfi_ctr#_match_transaction settings
 * for wci safari histogramming counters.
 */
	typedef struct wci_sfi_regs_value {
		uint64_t wci_sfi_ctr_mask_val;
		uint64_t wci_sfi_ctr_match_val;
		uint64_t wci_sfi_ctr_match_trans_val;
	} wci_sfi_regs_value_t;

/*
 * kstat structures used by wci to pass data to user programs.
 * wci_misc_counters_kstat - Misc counters (busstat support)
 *
 */

	struct wci_counters_kstat {
		kstat_named_t	wci_ctr_ctl;	/* ctr ctl reg */
		kstat_named_t	wci_ctr0;	/* ctr0 reg    */
		kstat_named_t	wci_ctr1;	/* ctr1 reg    */
	};


#ifdef	__cplusplus
}
#endif

#endif /* _WCI_COMMON_H */
