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
 * Copyright 2024 Oxide Comptuer Company
 */

#ifndef _IGC_H
#define	_IGC_H

/*
 * Primary illumos igc(4D) header file.
 */

#include <sys/types.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/list.h>

#include <core/igc_hw.h>
#include <core/igc_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The name of our module for MAC, kstats, etc.
 */
#define	IGC_MOD_NAME	"igc"

/*
 * The igc hardware appears to use BAR 0, which is regs[1].
 */
#define	IGC_PCI_BAR	1

/*
 * Maximum number of RX and TX rings that it appears the hardware supports. The
 * strict maximum segment size that the device can take is basically 9 KiB
 * (9216). However, we limit this to 9k so we don't have to worry about the
 * margin or related bits. The I225/6 datasheet that we have access to doesn't
 * explicitly state the maximum MTU. Various drivers and the I210 (which has a
 * rather similar MAC) do have similar values. Our assumption is that this
 * allows for us to still receive VLAN tagged packets and that we can set the
 * margin appropriately for mac.
 */
#define	IGC_MAX_RX_RINGS_I225	4
#define	IGC_MAX_TX_RINGS_I225	4
#define	IGC_MAX_MTU_I225	9216

/*
 * These are the default auto-negotiation values the device supports which is
 * 10/100 Half and Full duplex and then 1000/2500 full duplex.
 */
#define	IGC_DEFAULT_ADV	IGC_ALL_SPEED_DUPLEX_2500

/*
 * This is the default PAUSE frame time that we use. This value comes from
 * igb/e1000g and is 858 usec.
 */
#define	IGC_FC_PAUSE_TIME	0x0680

/*
 * Default values for ring sizes and related. We'll let an interrupt drain up to
 * half the ring by default. These are all things that could reasonably be made
 * into dladm private properties of the driver. We picked the 256 byte bind
 * threshold for rx mostly by surveying others. For tx, we picked 512 as that's
 * what igb, ixgbe, and e1000g use today, though i40e and qede use 256. These
 * numbers are pretty arbitrary.
 */
#define	IGC_DEF_RX_RING_SIZE	512
#define	IGC_DEF_TX_RING_SIZE	512
#define	IGC_DEF_RX_RING_INTR_LIMIT	256
#define	IGC_DEF_RX_BIND		256
#define	IGC_DEF_TX_BIND		512

/*
 * These numbers deal with the tx ring, blocking, recycling, and notification
 * thresholds. The first thing we need to pick is how many descriptors we
 * require before we tell MAC that the ring is blocked.  This number is picked
 * somewhat arbitrarily.  Because we could always fall back to a copy, this
 * could be as small as 2 (context and related) descriptors; however, the driver
 * can chain a fair bit together so we basically chose 4, which is a bit less
 * than 1% of the default ring size.  We picked a default recycle threshold
 * check during tx of 32, which is about 6.25% of the default ring size.
 *
 * We opt to keep a two descriptor gap as that's what igb has always done and
 * other drivers we've surveyed do the same.
 */
#define	IGC_DEF_TX_NOTIFY_MIN	4
#define	IGC_DEF_TX_RECYCLE_MIN	32
#define	IGC_DEF_TX_GAP		2

/*
 * This is the maximum number of cookies that we'll use in a transmit. This
 * number has been used across the igb/e1000g drivers over the years and comes
 * from the idea of taking a maximum sized LSO packet (64 KiB) plus its header
 * data, and dividing that by a 4 KiB page size, plus an extra descriptor in
 * case things end up split across pages.
 */
#define	IGC_MAX_TX_COOKIES	18

/*
 * Extra alignment that we use to offset RX buffers so that way IP's header is
 * 4-byte aligned.
 */
#define	IGC_RX_BUF_IP_ALIGN	2

/*
 * The buffer sizes that hardware uses for rx and tx are required to be 1 KiB
 * aligned.
 */
#define	IGC_BUF_ALIGN	0x400

/*
 * This value is used to indicate that we're grabbing the ring from the
 * interrupt and therefore should only take a single pass.
 */
#define	IGC_RX_POLL_INTR	-1

/*
 * This is a value in microseconds that hardware will guarantee as a gap between
 * interrupts. This value is just a borrowed default from other drivers.
 */
#define	IGC_DEF_EITR	200

/*
 * Because we never use the offset and address for syncing, we want to cast the
 * DMA sync call to void, but lets be paranoid on debug.
 */
#ifdef	DEBUG
#define	IGC_DMA_SYNC(buf, flag)		ASSERT0(ddi_dma_sync((buf)->idb_hdl, \
					    0, 0, flag))
#else
#define	IGC_DMA_SYNC(buf, flag)		(void) ddi_dma_sync((buf)->idb_hdl, \
					    0, 0, flag)
#endif	/* DEBUG */

typedef enum igc_attach {
	IGC_ATTACH_REGS		= 1 << 0,
	IGC_ATTACH_INTR_ALLOC	= 1 << 1,
	IGC_ATTACH_MUTEX	= 1 << 2,
	IGC_ATTACH_INTR_HANDLER	= 1 << 3,
	IGC_ATTACH_LED		= 1 << 4,
	IGC_ATTACH_STATS	= 1 << 5,
	IGC_ATTACH_MAC		= 1 << 6,
	IGC_ATTACH_INTR_EN	= 1 << 7,
	/*
	 * The rest of these represent state that is allocated and transformed
	 * after the device's mc_start(9E) entry point, igc_m_start(), is called
	 * by MAC.
	 */
	IGC_ATTACH_MAC_START	= 1 << 8,
	IGC_ATTACH_RX_DATA	= 1 << 9,
	IGC_ATTACH_TX_DATA	= 1 << 10
} igc_attach_t;

/*
 * Hardware-specific limits.
 */
typedef struct igc_limits {
	uint32_t il_max_rx_rings;
	uint32_t il_max_tx_rings;
	uint32_t il_max_mtu;
} igc_limits_t;

typedef struct igc_dma_buffer {
	caddr_t idb_va;
	ddi_acc_handle_t idb_acc;
	ddi_dma_handle_t idb_hdl;
	size_t idb_size;
	size_t idb_alloc_len;
} igc_dma_buffer_t;

typedef struct igc_rx_buffer {
	struct igc_rx_ring *irb_ring;
	mblk_t *irb_mp;
	igc_dma_buffer_t irb_dma;
	frtn_t irb_free_rtn;
	bool irb_loaned;
} igc_rx_buffer_t;

typedef enum igc_rx_ring_flags {
	/*
	 * Indicates we're currently polling and therefore shouldn't process an
	 * interrupt in case we're racing.
	 */
	IGC_RXR_F_POLL	= 1 << 0
} igc_rx_ring_flags_t;

typedef struct igc_rx_stats {
	kstat_named_t irs_rbytes;
	kstat_named_t irs_ipackets;
	kstat_named_t irs_desc_error;
	kstat_named_t irs_copy_nomem;
	kstat_named_t irs_bind_nobuf;
	kstat_named_t irs_bind_nomp;
	kstat_named_t irs_nbind;
	kstat_named_t irs_ncopy;
	kstat_named_t irs_ixsm;
	kstat_named_t irs_l3cksum_err;
	kstat_named_t irs_l4cksum_err;
	kstat_named_t irs_hcksum_miss;
	kstat_named_t irs_hcksum_hit;
} igc_rx_stats_t;

typedef struct igc_rx_ring {
	struct igc *irr_igc;
	igc_rx_ring_flags_t irr_flags;
	/*
	 * The ring's index on the device and the corresponding index that
	 * should be used for manipulating it in the EIMS, which generally is
	 * just which single MSI-X it has.
	 */
	uint32_t irr_idx;
	uint32_t irr_intr_idx;
	mac_ring_handle_t irr_rh;
	kmutex_t irr_lock;

	/*
	 * Stats for the ring, along with the current mac generation, which is
	 * needed for receiving data.
	 */
	uint64_t irr_gen;
	igc_rx_stats_t irr_stat;
	kstat_t *irr_kstat;

	/*
	 * Data for the rx descriptor ring itself.
	 */
	igc_dma_buffer_t irr_desc_dma;
	union igc_adv_rx_desc *irr_ring;
	uint32_t irr_next;

	/*
	 * RX descriptors and related. The arena contains every allocated rx
	 * buffer. The rx buffers are split between the work list and the free
	 * list. The work list is 1:1 mapped to the descriptor ring. The free
	 * list contains extra buffers. The total number of buffers is static
	 * and is set to igc_rx_nbuf. igc_rx_ndesc go into the work list and
	 * then the remaining ones are in the free list.
	 */
	igc_rx_buffer_t *irr_arena;
	igc_rx_buffer_t **irr_work_list;
	igc_rx_buffer_t **irr_free_list;
	kmutex_t irr_free_lock;
	kcondvar_t irr_free_cv;
	uint32_t irr_nfree;
} igc_rx_ring_t;

typedef struct igc_tx_buffer {
	list_node_t itb_node;
	mblk_t *itb_mp;
	igc_dma_buffer_t itb_dma;
	ddi_dma_handle_t itb_bind_hdl;
	/*
	 * This flag indicates that this is the first tx buffer for a packet and
	 * therefore its last descriptor for the packet is valid. See 'TX Data
	 * Path Design' in the theory statement for more information.
	 */
	bool itb_first;
	/*
	 * When set to true this tx buffer is being used to represent DMA
	 * binding. Othewrise, it's being used to represent copying.
	 */
	bool itb_bind;
	/*
	 * This indicates the last descriptor used for an entire packet and
	 * therefore what we will garbage collect.
	 */
	uint32_t itb_last_desc;
	/*
	 * This tracks how much data is currently valid in the buffer.
	 */
	size_t itb_len;
} igc_tx_buffer_t;

/*
 * This represents data that we have saved and goes into the tx context
 * descriptor. If the information has changed, then we likely need to reset the
 * context descriptor.
 */
typedef struct igc_tx_context_data {
	uint8_t itc_l2hlen;
	uint8_t itc_l3hlen;
	uint8_t itc_l4hlen;
	uint8_t itc_l4proto;
	uint16_t itc_l3proto;
	uint32_t itc_mss;
	uint32_t itc_cksum;
	uint32_t itc_lso;
} igc_tx_context_data_t;

typedef struct igc_tx_stats {
	kstat_named_t its_obytes;
	kstat_named_t its_opackets;
	kstat_named_t its_bad_meo;
	kstat_named_t its_ring_full;
	kstat_named_t its_no_tx_bufs;
	kstat_named_t its_tx_copy;
	kstat_named_t its_tx_bind;
	kstat_named_t its_tx_bind_fail;
} igc_tx_stats_t;

typedef struct igc_tx_ring {
	struct igc *itr_igc;
	uint32_t itr_idx;
	uint32_t itr_intr_idx;
	mac_ring_handle_t itr_rh;
	kmutex_t itr_lock;

	/*
	 * Stats for the ring.
	 */
	igc_tx_stats_t itr_stat;
	kstat_t *itr_kstat;

	/*
	 * Data for the TX descriptors.
	 */
	igc_dma_buffer_t itr_desc_dma;
	union igc_adv_tx_desc *itr_ring;
	uint32_t itr_ring_head;
	uint32_t itr_ring_tail;
	uint32_t itr_ring_free;
	bool itr_mac_blocked;
	bool itr_recycle;
	igc_tx_context_data_t itr_tx_ctx;

	/*
	 * Transmit Buffers
	 */
	igc_tx_buffer_t *itr_arena;
	igc_tx_buffer_t **itr_work_list;
	list_t itr_free_list;

} igc_tx_ring_t;

typedef struct igc_addr {
	uint8_t ia_mac[ETHERADDRL];
	bool ia_valid;
} igc_addr_t;

/*
 * Running counters that are used for MAC. These are named after the
 * corresponding hardware registers.
 */
typedef struct igc_stats {
	kstat_named_t is_crcerrs;
	kstat_named_t is_algnerrc;
	kstat_named_t is_mpc;
	kstat_named_t is_scc;
	kstat_named_t is_ecol;
	kstat_named_t is_mcc;
	kstat_named_t is_latecol;
	kstat_named_t is_colc;
	kstat_named_t is_rerc;
	kstat_named_t is_dc;
	kstat_named_t is_tncrs;
	kstat_named_t is_htdpmc;
	kstat_named_t is_rlec;
	kstat_named_t is_xonrxc;
	kstat_named_t is_xontxc;
	kstat_named_t is_xoffrxc;
	kstat_named_t is_xofftxc;
	kstat_named_t is_fcruc;
	kstat_named_t is_prc64;
	kstat_named_t is_prc127;
	kstat_named_t is_prc255;
	kstat_named_t is_prc1023;
	kstat_named_t is_prc1522;
	kstat_named_t is_gprc;
	kstat_named_t is_bprc;
	kstat_named_t is_mprc;
	kstat_named_t is_gptc;
	kstat_named_t is_gorc;
	kstat_named_t is_gotc;
	kstat_named_t is_rnbc;
	kstat_named_t is_ruc;
	kstat_named_t is_rfc;
	kstat_named_t is_roc;
	kstat_named_t is_rjc;
	kstat_named_t is_mgtprc;
	kstat_named_t is_mgtpdc;
	kstat_named_t is_mgtptc;
	kstat_named_t is_tor;
	kstat_named_t is_tot;
	kstat_named_t is_tpr;
	kstat_named_t is_tpt;
	kstat_named_t is_ptc64;
	kstat_named_t is_ptc127;
	kstat_named_t is_ptc255;
	kstat_named_t is_ptc511;
	kstat_named_t is_ptc1023;
	kstat_named_t is_ptc1522;
	kstat_named_t is_mptc;
	kstat_named_t is_bptc;
	kstat_named_t is_tsctc;
	kstat_named_t is_iac;
	kstat_named_t is_rxdmtc;
} igc_stats_t;

typedef struct igc {
	dev_info_t *igc_dip;
	igc_attach_t igc_attach;
	/*
	 * Register access settings.
	 */
	ddi_acc_handle_t igc_cfgspace;
	caddr_t igc_regs_base;
	off_t igc_regs_size;
	ddi_acc_handle_t igc_regs_hdl;
	/*
	 * Interrupt Management
	 */
	uint_t igc_intr_pri;
	int igc_intr_cap;
	uint_t igc_intr_type;
	size_t igc_intr_size;
	int igc_nintrs;
	ddi_intr_handle_t *igc_intr_handles;
	uint32_t igc_eims;
	/*
	 * Common code structures.
	 */
	struct igc_hw igc_hw;
	/*
	 * Limits and device-specific data. All data in this section after the
	 * igc_lock is protected by it.
	 */
	igc_limits_t igc_limits;
	uint32_t igc_nrx_rings;
	uint32_t igc_ntx_rings;
	uint32_t igc_rx_ndesc;
	uint32_t igc_tx_ndesc;
	uint32_t igc_rx_nbuf;
	uint32_t igc_tx_nbuf;
	uint32_t igc_rx_nfree;
	uint32_t igc_rx_intr_nframes;
	uint32_t igc_rx_bind_thresh;
	uint32_t igc_tx_bind_thresh;
	uint32_t igc_tx_notify_thresh;
	uint32_t igc_tx_recycle_thresh;
	uint32_t igc_tx_gap;
	uint32_t igc_eitr;

	kmutex_t igc_lock;
	uint32_t igc_mtu;
	uint32_t igc_max_frame;
	uint32_t igc_rx_buf_size;
	uint32_t igc_tx_buf_size;
	uint16_t igc_nucast;
	uint16_t igc_nmcast;
	igc_addr_t *igc_ucast;
	igc_addr_t *igc_mcast;
	ether_addr_t *igc_mcast_raw;
	link_state_t igc_link_state;
	link_duplex_t igc_link_duplex;
	uint16_t igc_link_speed;
	mac_led_mode_t igc_led_mode;
	bool igc_promisc;

	/*
	 * Ring structures.
	 */
	igc_rx_ring_t *igc_rx_rings;
	igc_tx_ring_t *igc_tx_rings;

	/*
	 * GLDv3 glue
	 */
	mac_handle_t igc_mac_hdl;
	mac_group_handle_t igc_rxg_hdl;

	/*
	 * LED register values.
	 */
	uint32_t igc_ledctl;
	uint32_t igc_ledctl_on;
	uint32_t igc_ledctl_off;
	uint32_t igc_ledctl_blink;

	/*
	 * Stats
	 */
	kstat_t *igc_ksp;
	igc_stats_t igc_stats;

	/*
	 * PHY Information
	 */
	uint16_t igc_phy_ctrl;
	uint16_t igc_phy_status;
	uint16_t igc_phy_an_adv;
	uint16_t igc_phy_an_exp;
	uint16_t igc_phy_lp;
	uint16_t igc_phy_1000t_ctrl;
	uint16_t igc_phy_1000t_status;
	uint16_t igc_phy_ext_status;
	uint16_t igc_phy_mmd_ctrl;
	uint16_t igc_phy_mmd_sts;
} igc_t;

/*
 * Register read and write functions.
 */
extern uint32_t igc_read32(igc_t *igc, uint32_t);
extern void igc_write32(igc_t *igc, uint32_t, uint32_t);

/*
 * Misc. functions related to updating and initializing hardware state.
 */
extern void igc_hw_buf_update(igc_t *);
extern bool igc_hw_common_init(igc_t *);
extern void igc_multicast_sync(igc_t *);
extern void igc_hw_intr_enable(igc_t *igc);
extern void igc_hw_intr_disable(igc_t *igc);

/*
 * Buffer, data allocation, and rings.
 */
extern bool igc_rx_data_alloc(igc_t *);
extern void igc_rx_data_free(igc_t *);
extern void igc_rx_hw_init(igc_t *);
extern mblk_t *igc_ring_rx(igc_rx_ring_t *, int);
extern void igc_rx_drain(igc_t *);
extern mblk_t *igc_ring_tx(void *, mblk_t *);
extern void igc_tx_recycle(igc_t *, igc_tx_ring_t *);

extern bool igc_tx_data_alloc(igc_t *);
extern void igc_tx_data_free(igc_t *);
extern void igc_tx_hw_init(igc_t *);

/*
 * Stats related functions.
 */
extern bool igc_stats_init(igc_t *);
extern void igc_stats_fini(igc_t *);
extern bool igc_rx_ring_stats_init(igc_t *, igc_rx_ring_t *);
extern void igc_rx_ring_stats_fini(igc_rx_ring_t *);
extern bool igc_tx_ring_stats_init(igc_t *, igc_tx_ring_t *);
extern void igc_tx_ring_stats_fini(igc_tx_ring_t *);
extern void igc_stats_update_u64(igc_t *, kstat_named_t *, uint32_t);

/*
 * MAC registration related APIs.
 */
extern bool igc_mac_register(igc_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IGC_H */
