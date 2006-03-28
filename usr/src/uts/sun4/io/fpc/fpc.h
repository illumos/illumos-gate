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

#ifndef	_FPC_H
#define	_FPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SUCCESS	0
#define	FAILURE	-1

#define	NUM_LEAVES	2

extern int fpc_debug;
#define	FPC_DBG1 if (fpc_debug >= 1) printf
#define	FPC_DBG2 if (fpc_debug >= 2) printf

/*
 * Defs for fpc-kstat.c.  Put'em here for now even though they don't
 * have to do with the lower-level implementation.
 */
extern int fpc_kstat_init(dev_info_t *dip);
extern void fpc_kstat_fini(dev_info_t *dip);

typedef enum fire_perfcnt {
	jbc = 0,
	imu,
	mmu,
	tlu,
	lpu
} fire_perfcnt_t;

/* Set to the last entry in fire_perfcnt_t. */
#define	MAX_REG_TYPES		((int)lpu + 1)

#define	NUM_JBC_COUNTERS	2
#define	NUM_IMU_COUNTERS	2
#define	NUM_MMU_COUNTERS	2
#define	NUM_TLU_COUNTERS	3
#define	NUM_LPU_COUNTERS	2

/* Sum of all NUM_xxx_COUNTERS above. */
#define	NUM_TOTAL_COUNTERS	11

/* largest group of counters */
#define	NUM_MAX_COUNTERS	NUM_TLU_COUNTERS

/* Event mask related. */

/* How much an event for a given PIC is shifted within the event mask. */

#define	PIC0_EVT_SEL_SHIFT	0
#define	PIC1_EVT_SEL_SHIFT	8
#define	PIC2_EVT_SEL_SHIFT	16

/* Width or mask of a single event within an event mask. */

#define	JBC01_EVT_MASK		0xFF
#define	IMU01_EVT_MASK		0xFF
#define	MMU01_EVT_MASK		0xFF
#define	TLU01_EVT_MASK		0xFF
#define	TLU2_EVT_MASK		0x3
#define	LPU12_EVT_MASK		0xFFFF

/* Positioned masks for different event fields within an event mask. */

#define	JBC_PIC0_EVT_MASK	((uint64_t)JBC01_EVT_MASK << PIC0_EVT_SEL_SHIFT)
#define	JBC_PIC1_EVT_MASK	((uint64_t)JBC01_EVT_MASK << PIC1_EVT_SEL_SHIFT)
#define	IMU_PIC0_EVT_MASK	((uint64_t)IMU01_EVT_MASK << PIC0_EVT_SEL_SHIFT)
#define	IMU_PIC1_EVT_MASK	((uint64_t)IMU01_EVT_MASK << PIC1_EVT_SEL_SHIFT)
#define	MMU_PIC0_EVT_MASK	((uint64_t)MMU01_EVT_MASK << PIC0_EVT_SEL_SHIFT)
#define	MMU_PIC1_EVT_MASK	((uint64_t)MMU01_EVT_MASK << PIC1_EVT_SEL_SHIFT)
#define	TLU_PIC0_EVT_MASK	((uint64_t)TLU01_EVT_MASK << PIC0_EVT_SEL_SHIFT)
#define	TLU_PIC1_EVT_MASK	((uint64_t)TLU01_EVT_MASK << PIC1_EVT_SEL_SHIFT)
#define	TLU_PIC2_EVT_MASK	((uint64_t)TLU2_EVT_MASK << PIC2_EVT_SEL_SHIFT)
#define	LPU_PIC0_EVT_MASK	((uint64_t)LPU12_EVT_MASK << PIC0_EVT_SEL_SHIFT)
#define	LPU_PIC1_EVT_MASK	((uint64_t)LPU12_EVT_MASK << PIC2_EVT_SEL_SHIFT)

/*
 * Take a dip to define the device...
 *   sun4v: can convert dip to a dev_hdl needed for hyp. perf ctr interface.
 *   sun4u: can convert dip to an ldi_ident_t I can use for a layered PCItool
 *	ioctl.
 *
 * Define which of JBUS, PCIE_A and PCIE_B regs are available.  HW partitioning
 * may make some register sets unavailable to certain virtual nodes.
 */

#define	JBUS_REGS_AVAIL		0x1	/* JBUS regs avail */
#define	PCIE_A_REGS_AVAIL	0x2
#define	PCIE_B_REGS_AVAIL	0x4

/* For checking platform from _init before installing module */
extern int fpc_init_platform_check();

/* Low level module initialization done at attach time. */
extern int fpc_perfcnt_module_init(dev_info_t *dip, int *avail);
extern int fpc_perfcnt_module_fini(dev_info_t *dip);

/*
 * Program a performance counter.
 *
 * reggroup is which type of counter.
 * counter is the counter number.
 * event is the event to program for that counter.
 */
extern int fpc_perfcnt_program(int devnum, fire_perfcnt_t reggroup,
    uint64_t event);

/*
 * Read a performance counter.
 *
 * reggroup is which type of counter.
 * counter is the counter number.
 * event_p returns the event programmed for that counter.
 * value_p returns the counter value.
 */
extern int fpc_perfcnt_read(int devnum, fire_perfcnt_t reggroup,
    uint64_t *event_p, uint64_t values[NUM_MAX_COUNTERS]);

/*
 * Definitions of the different types of events.
 *
 * The first part says which registers these events are for.
 * For example, JBC01 means the JBC performance counters 0 and 1
 */

#define	JBC01_S_EVT_NONE		"event_none"
#define	JBC01_S_EVT_CLK			"clock_cyc"
#define	JBC01_S_EVT_IDLE		"idle_cyc"
#define	JBC01_S_EVT_FIRE		"fire_jbus_cyc"
#define	JBC01_S_EVT_READ_LATENCY	"rd_latency_cyc"
#define	JBC01_S_EVT_READ_SAMPLE		"rd_sample"
#define	JBC01_S_EVT_I2C_PIO		"pios_i2c"
#define	JBC01_S_EVT_EBUS_PIO		"pios_ebus"
#define	JBC01_S_EVT_RINGA_PIO		"pios_ringA"
#define	JBC01_S_EVT_RINGB_PIO		"pios_ringB"
#define	JBC01_S_EVT_PARTIAL_WR		"partial_wr"
#define	JBC01_S_EVT_TOTAL_WR		"total_wr"
#define	JBC01_S_EVT_TOTAL_RD		"total_rd"
#define	JBC01_S_EVT_AOKOFF		"aokoff"
#define	JBC01_S_EVT_DOKOFF		"dokoff"
#define	JBC01_S_EVT_DAOKOFF		"daokoff"
#define	JBC01_S_EVT_JBUS_COH_XACT	"jbus_coh_tr"
#define	JBC01_S_EVT_FIRE_COH_XACT	"fire_coh_tr"
#define	JBC01_S_EVT_JBUS_NCOH_XACT	"jbus_ncoh_tr"
#define	JBC01_S_EVT_FGN_IO_HIT		"fgn_pio_hit"
#define	JBC01_S_EVT_FIRE_WBS		"fire_wb"
#define	JBC01_S_EVT_PCIEA_PIO_WR	"pio_wr_pcieA"
#define	JBC01_S_EVT_PCIEA_PIO_RD	"pio_rd_pcieA"
#define	JBC01_S_EVT_PCIEB_PIO_WR	"pio_wr_pcieB"
#define	JBC01_S_EVT_PCIEB_PIO_RD	"pio_rd_pcieB"

#define	JBC01_EVT_NONE			0x0
#define	JBC01_EVT_CLK			0x1
#define	JBC01_EVT_IDLE			0x2
#define	JBC01_EVT_FIRE			0x3
#define	JBC01_EVT_READ_LATENCY		0x4
#define	JBC01_EVT_READ_SAMPLE		0x5
#define	JBC01_EVT_I2C_PIO		0x6
#define	JBC01_EVT_EBUS_PIO		0x7
#define	JBC01_EVT_RINGA_PIO		0x8
#define	JBC01_EVT_RINGB_PIO		0x9
#define	JBC01_EVT_PARTIAL_WR		0xA
#define	JBC01_EVT_TOTAL_WR		0xB
#define	JBC01_EVT_TOTAL_RD		0xC
#define	JBC01_EVT_AOKOFF		0xD
#define	JBC01_EVT_DOKOFF		0xE
#define	JBC01_EVT_DAOKOFF		0xF
#define	JBC01_EVT_JBUS_COH_XACT		0x10
#define	JBC01_EVT_FIRE_COH_XACT		0x11
#define	JBC01_EVT_JBUS_NCOH_XACT	0x12
#define	JBC01_EVT_FGN_IO_HIT		0x13
#define	JBC01_EVT_FIRE_WBS		0x14
#define	JBC01_EVT_PCIEA_PIO_WR		0x15
#define	JBC01_EVT_PCIEA_PIO_RD		0x16
#define	JBC01_EVT_PCIEB_PIO_WR		0x17
#define	JBC01_EVT_PCIEB_PIO_RD		0x18

#define	IMU01_S_EVT_NONE		"event_none"
#define	IMU01_S_EVT_CLK			"clock_cyc"
#define	IMU01_S_EVT_MONDO		"mondos_iss"
#define	IMU01_S_EVT_MSI			"msi_iss"
#define	IMU01_S_EVT_MONDO_NAKS		"mondos_nacks"
#define	IMU01_S_EVT_EQ_WR		"eq_wr"
#define	IMU01_S_EVT_EQ_MONDO		"eq_mondos"

#define	IMU01_EVT_NONE			0x0
#define	IMU01_EVT_CLK			0x1
#define	IMU01_EVT_MONDO			0x2
#define	IMU01_EVT_MSI			0x3
#define	IMU01_EVT_MONDO_NAKS		0x4
#define	IMU01_EVT_EQ_WR			0x5
#define	IMU01_EVT_EQ_MONDO		0x6

#define	MMU01_S_EVT_NONE		"event_none"
#define	MMU01_S_EVT_CLK			"clock_cyc"
#define	MMU01_S_EVT_TRANS		"total_transl"
#define	MMU01_S_EVT_STALL		"total_stall_cyc"
#define	MMU01_S_EVT_TRANSL_MISS		"total_tranl_miss"
#define	MMU01_S_EVT_TBLWLK_STALL	"tblwlk_stall_cyc"
#define	MMU01_S_EVT_BYPASS_TRANSL	"bypass_transl"
#define	MMU01_S_EVT_TRANSL_TRANSL	"transl_transl"
#define	MMU01_S_EVT_FLOW_CNTL_STALL	"flow_stall_cyc"
#define	MMU01_S_EVT_FLUSH_CACHE_ENT	"cache_entr_flush"

#define	MMU01_EVT_NONE			0x0
#define	MMU01_EVT_CLK			0x1
#define	MMU01_EVT_TRANSL		0x2
#define	MMU01_EVT_STALL			0x3
#define	MMU01_EVT_TRANSL_MISS		0x4
#define	MMU01_EVT_TBLWLK_STALL		0x5
#define	MMU01_EVT_BYPASS_TRANSL		0x6
#define	MMU01_EVT_TRANSL_TRANSL		0x7
#define	MMU01_EVT_FLOW_CNTL_STALL	0x8
#define	MMU01_EVT_FLUSH_CACHE_ENT	0x9

#define	TLU01_S_EVT_NONE		"event_none"
#define	TLU01_S_EVT_CLK			"clock_cyc"
#define	TLU01_S_EVT_COMPL		"compl_recvd"
#define	TLU01_S_EVT_XMT_POST_CR_UNAV	"post_cr_unav_cyc"
#define	TLU01_S_EVT_XMT_NPOST_CR_UNAV	"npost_cr_unav_cyc"
#define	TLU01_S_EVT_XMT_CMPL_CR_UNAV	"compl_cr_unav_cyc"
#define	TLU01_S_EVT_XMT_ANY_CR_UNAV	"trans_cr_any_unav"
#define	TLU01_S_EVT_RETRY_CR_UNAV	"retry_cr_unav"
#define	TLU01_S_EVT_MEMRD_PKT_RCVD	"recvd_mem_rd_pkt"
#define	TLU01_S_EVT_MEMWR_PKT_RCVD	"recvd_mem_wr_pkt"
#define	TLU01_S_EVT_RCV_CR_THRESH	"recv_cr_thresh"
#define	TLU01_S_EVT_RCV_PST_HDR_CR_EXH	"recv_hdr_cr_exh_cyc"
#define	TLU01_S_EVT_RCV_PST_DA_CR_MPS	"recv_post_da_cr_mps"
#define	TLU01_S_EVT_RCV_NPST_HDR_CR_EXH	"recv_npost_hdr_cr_exh"
#define	TLU01_S_EVT_RCVR_L0S		"recvr_l0s_cyc"
#define	TLU01_S_EVT_RCVR_L0S_TRANS	"recvr_l0s_trans"
#define	TLU01_S_EVT_XMTR_L0S		"trans_l0s_cyc"
#define	TLU01_S_EVT_XMTR_L0S_TRANS	"trans_l0s_trans"
#define	TLU01_S_EVT_RCVR_ERR		"recvr_err"
#define	TLU01_S_EVT_BAD_TLP		"bad_tlp"
#define	TLU01_S_EVT_BAD_DLLP		"bad_dllp"
#define	TLU01_S_EVT_REPLAY_ROLLOVER	"replay_rollover"
#define	TLU01_S_EVT_REPLAY_TMO		"replay_to"

#define	TLU01_EVT_NONE			0x0
#define	TLU01_EVT_CLK			0x1
#define	TLU01_EVT_COMPL			0x2
#define	TLU01_EVT_XMT_POST_CR_UNAV	0x10
#define	TLU01_EVT_XMT_NPOST_CR_UNAV	0x11
#define	TLU01_EVT_XMT_CMPL_CR_UNAV	0x12
#define	TLU01_EVT_XMT_ANY_CR_UNAV	0x13
#define	TLU01_EVT_RETRY_CR_UNAV		0x14
#define	TLU01_EVT_MEMRD_PKT_RCVD	0x20
#define	TLU01_EVT_MEMWR_PKT_RCVD	0x21
#define	TLU01_EVT_RCV_CR_THRESH		0x22
#define	TLU01_EVT_RCV_PST_HDR_CR_EXH	0x23
#define	TLU01_EVT_RCV_PST_DA_CR_MPS	0x24
#define	TLU01_EVT_RCV_NPST_HDR_CR_EXH	0x25
#define	TLU01_EVT_RCVR_L0S		0x30
#define	TLU01_EVT_RCVR_L0S_TRANS	0x31
#define	TLU01_EVT_XMTR_L0S		0x32
#define	TLU01_EVT_XMTR_L0S_TRANS	0x33
#define	TLU01_EVT_RCVR_ERR		0x40
#define	TLU01_EVT_BAD_TLP		0x42
#define	TLU01_EVT_BAD_DLLP		0x43
#define	TLU01_EVT_REPLAY_ROLLOVER	0x44
#define	TLU01_EVT_REPLAY_TMO		0x47

#define	TLU2_S_EVT_NONE			"event_none"
#define	TLU2_S_EVT_NON_POST_COMPL_TIME	"non_post_compl"
#define	TLU2_S_EVT_XMT_DATA_WORD	"trans_data_words"
#define	TLU2_S_EVT_RCVD_DATA_WORD	"recvd_data_words"

#define	TLU2_EVT_NONE			0x0
#define	TLU2_EVT_NON_POST_COMPL_TIME	0x1
#define	TLU2_EVT_XMT_DATA_WORD		0x2
#define	TLU2_EVT_RCVD_DATA_WORD		0x3

#define	LPU12_S_EVT_RESET		"event_reset"
#define	LPU12_S_EVT_TLP_RCVD		"tlp_recvd"
#define	LPU12_S_EVT_DLLP_RCVD		"dllp_recvd"
#define	LPU12_S_EVT_ACK_DLLP_RCVD	"ack_dllp_recvd"
#define	LPU12_S_EVT_NAK_DLLP_RCVD	"nak_dllp_recvd"
#define	LPU12_S_EVT_RETRY_START		"retries_started"
#define	LPU12_S_EVT_REPLAY_TMO		"replay_timer_to"
#define	LPU12_S_EVT_ACK_NAK_LAT_TMO	"ack_nak_lat_to"
#define	LPU12_S_EVT_BAD_DLLP		"bad_dllp"
#define	LPU12_S_EVT_BAD_TLP		"bad_tlp"
#define	LPU12_S_EVT_NAK_DLLP_SENT	"nak_dllp_sent"
#define	LPU12_S_EVT_ACK_DLLP_SENT	"ack_dllp_sent"
#define	LPU12_S_EVT_RCVR_ERROR		"recvr_err"
#define	LPU12_S_EVT_LTSSM_RECOV_ENTRY	"ltssm_recov_entr"
#define	LPU12_S_EVT_REPLAY_IN_PROG	"replay_prog_cyc"
#define	LPU12_S_EVT_TLP_XMT_IN_PROG	"tlp_trans_prog_cyc"
#define	LPU12_S_EVT_CLK_CYC		"clock_cyc"
#define	LPU12_S_EVT_TLP_DLLP_XMT_PROG	"tlp_dllp_trans_cyc"
#define	LPU12_S_EVT_TLP_DLLP_RCV_PROG	"tlp_dllp_recv_cyc"

#define	LPU12_EVT_RESET			0x0
#define	LPU12_EVT_TLP_RCVD		0x1
#define	LPU12_EVT_DLLP_RCVD		0x2
#define	LPU12_EVT_ACK_DLLP_RCVD		0x3
#define	LPU12_EVT_NAK_DLLP_RCVD		0x4
#define	LPU12_EVT_RETRY_START		0x5
#define	LPU12_EVT_REPLAY_TMO		0x6
#define	LPU12_EVT_ACK_NAK_LAT_TMO	0x7
#define	LPU12_EVT_BAD_DLLP		0x8
#define	LPU12_EVT_BAD_TLP		0x9
#define	LPU12_EVT_NAK_DLLP_SENT		0xA
#define	LPU12_EVT_ACK_DLLP_SENT		0xB
#define	LPU12_EVT_RCVR_ERROR		0xC
#define	LPU12_EVT_LTSSM_RECOV_ENTRY	0xD
#define	LPU12_EVT_REPLAY_IN_PROG	0xE
#define	LPU12_EVT_TLP_XMT_IN_PROG	0xF
#define	LPU12_EVT_CLK_CYC		0x10
#define	LPU12_EVT_TLP_DLLP_XMT_PROG	0x11
#define	LPU12_EVT_TLP_DLLP_RCV_PROG	0x12

#define	COMMON_S_CLEAR_PIC		"clear_pic"

#ifdef	__cplusplus
}
#endif

#endif	/* _FPC_H */
