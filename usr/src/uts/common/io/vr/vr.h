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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VR_H
#define	_VR_H

#ifdef __cplusplus
	extern "C" {
#endif

/*
 * Number of descriptor entries for each ring. The no. of descriptors is bound
 * to 4K per ring (256 entries a 16 bytes).
 */
#define	VR_TX_N_DESC		128
#define	VR_RX_N_DESC		256

/*
 * The number of TX interrupts to "schedule" on the ring.
 */
#define	VR_TX_INTRS_RING	3

/*
 * The the periodic check interval of 2 seconds, in nano seconds
 */
#define	VR_CHECK_INTERVAL	(2000 * 1000 * 1000)

/*
 * The number of TX checks that must pass without progress before we decide
 * to reset the adapter.
 */
#define	VR_MAXTXCHECKS		12

/*
 * All possible interrupts with the unwanted commented.
 */
#define	VR_ICR0_CFG	(VR_ICR0_RX_DONE	| \
			    VR_ICR0_TX_DONE	| \
			    VR_ICR0_RX_ERR	| \
			    VR_ICR0_TX_ERR	| \
			    VR_ICR0_TX_BUF_UFLOW| \
			    VR_ICR0_RX_LINKERR	| \
			    VR_ICR0_BUSERR	| \
			    /* VR_ICR0_STATSMAX	| */ \
			    /* VR_ICR0_RX_EARLY	| */ \
			    VR_ICR0_TX_FIFO_UFLOW	| \
			    VR_ICR0_RX_FIFO_OFLOW	| \
			    VR_ICR0_RX_DROPPED	| \
			    VR_ICR0_RX_NOBUF  	| \
			    VR_ICR0_TX_ABORT	| \
			    VR_ICR0_LINKSTATUS	| \
			    VR_ICR0_GENERAL)

#define	VR_ICR1_CFG	(/* VR_ICR1_TIMER0	| */ \
			    /* VR_ICR1_TIMER1	| */ \
			    /* VR_ICR1_PHYEVENT	| */ \
			    /* VR_ICR1_TDERR	| */ \
			    /* VR_ICR1_SSRCI	| */ \
			    /* VR_ICR1_UINTR_SET| */ \
			    /* VR_ICR1_UINTR_CLR| */ \
			    /* VR_ICR1_PWEI */)

/*
 * Our definitions of RX and TX errors.
 */
#define	VR_ISR_TX_ERR_BITS	(VR_ICR0_TX_ERR | \
					VR_ICR0_TX_BUF_UFLOW | \
					VR_ICR0_TX_FIFO_UFLOW | \
					VR_ICR0_TX_ABORT)

#define	VR_ISR_RX_ERR_BITS	(VR_ICR0_RX_ERR | \
					VR_ICR0_RX_LINKERR | \
					VR_ICR0_RX_FIFO_OFLOW | \
					VR_ICR0_RX_DROPPED | \
					VR_ICR0_RX_NOBUF)

#define	VR_ISR_SYS_ERR_BITS	(VR_ICR0_BUSERR)

#define	VR_ISR_ERR_BITS		(VR_ISR_TX_ERR_BITS | \
					VR_ISR_RX_ERR_BITS | \
					VR_ISR_SYS_ERR_BITS)
#define	VR_TX_MAX_INTR_DISTANCE \
			(VR_TX_N_DESC / VR_TX_INTRS_RING)


#define	MODULENAME		"vr"	/* Our name */
#define	VR_SLOPSZ		2
#define	VR_MAX_PKTSZ		(ETHERMAX + ETHERFCSL + VLAN_TAGSZ + VR_SLOPSZ)
#define	VR_DMABUFSZ		(VR_MAX_PKTSZ)
#define	VR_MMI_WAITINCR		(10)
#define	VR_MMI_WAITMAX		(10000)
#define	VR_CAM_SZ		(32)

/*
 * PCI identification for the Rhine's.
 */
#define	VR_PCI_VIA_VENID		0x1106
#define	VR_PCI_DEVID_RHINE		0x3043
#define	VR_PCI_DEVID_RHINE_IIIM		0x3053
#define	VR_PCI_DEVID_RHINE_II2		0x3065
#define	VR_PCI_DEVID_RHINE_III		0x3106
#define	VR_PCI_DEVID_RHINE_II		0x6100

#define	VR_PCI_REVID_VT86C100A_E	0x04
#define	VR_PCI_REVID_VT6102_A		0x40
#define	VR_PCI_REVID_VT6102_C		0x42
#define	VR_PCI_REVID_VT6105_A0		0x80
#define	VR_PCI_REVID_VT6105_B0		0x83
#define	VR_PCI_REVID_VT6105_LOM		0x8A
#define	VR_PCI_REVID_VT6107_A0		0x8C
#define	VR_PCI_REVID_VT6107_A1		0x8D
#define	VR_PCI_REVID_VT6105M_A0		0x90
#define	VR_PCI_REVID_VT6105M_B1		0x94

/*
 * Feature bits for the different cards.
 */
#define	VR_FEATURE_NONE			(0)
#define	VR_FEATURE_RX_PAUSE_CAP		(1 << 0) /* can receive pauses */
#define	VR_FEATURE_TX_PAUSE_CAP		(1 << 1) /* can transmit pauses */
#define	VR_FEATURE_MRDLNMULTIPLE	(1 << 2) /* can read mult cache lines */
#define	VR_FEATURE_TXCHKSUM		(1 << 3) /* can do TX TCP checksum */
#define	VR_FEATURE_RXCHKSUM		(1 << 4) /* can do RX TCP checksum */
#define	VR_FEATURE_CAMSUPPORT		(1 << 5) /* has a CAM filter */
#define	VR_FEATURE_VLANTAGGING		(1 << 6) /* can do VLAN tagging */
#define	VR_FEATURE_MIBCOUNTER		(1 << 7) /* has a MIB counter */

/*
 * Bug bits for the different cards.
 */
#define	VR_BUG_NONE			(0)
#define	VR_BUG_TXALIGN			(1 << 0) /* needs aligned TX */
#define	VR_BUG_NEEDMODE10T		(1 << 1) /* chip needs mode10t secret */
#define	VR_BUG_NEEDMIION		(1 << 2) /* chip needs miion secret */
#define	VR_BUG_NEEDMODE2PCEROPT		(1 << 3) /* chip needs pceropt */
#define	VR_BUG_NO_TXQUEUEING		(1 << 4) /* chip cannot queue tx */
#define	VR_BUG_NO_MEMIO			(1 << 5) /* chip cannot memory space */
#define	VR_BUG_MIIPOLLSTOP		(1 << 6) /* special to stop polling */

#define	VR_GET8(acc, p)		\
		ddi_get8((acc)->hdl,	\
		    (uint8_t *)((void *)((acc)->addr + (p))))
#define	VR_GET16(acc, p)	\
		ddi_get16((acc)->hdl,	\
		    (uint16_t *)((void *)((acc)->addr + (p))))
#define	VR_GET32(acc, p)	\
		ddi_get32((acc)->hdl,	\
		    (uint32_t *)((void *)((acc)->addr + (p))))

#define	VR_PUT8(acc, p, v)	\
		ddi_put8((acc)->hdl,	\
		    (uint8_t *)((void *)((acc)->addr + (p))), v)
#define	VR_PUT16(acc, p, v)	\
		ddi_put16((acc)->hdl,	\
		    (uint16_t *)((void *)((acc)->addr + (p))), v)
#define	VR_PUT32(acc, p, v)	\
		ddi_put32((acc)->hdl,	\
		    (uint32_t *)((void *)((acc)->addr + (p))), v)

/*
 * Clear bit b in register r.
 */
#define	VR_CLRBIT8(acc, r, b)			\
		VR_PUT8(acc, r, VR_GET8(acc, r) & ~(b))
#define	VR_CLRBIT16(acc, r, b)			\
		VR_PUT16(acc, r, VR_GET16(acc, r) & ~(b))
#define	VR_CLRBIT32(acc, r, b)			\
		VR_PUT32(acc, r, VR_GET32(acc, r) & ~(b))

/*
 * Set bit b in register r.
 */
#define	VR_SETBIT8(acc, r, b)			\
		VR_PUT8(acc, r, (VR_GET8(acc, r) | (b)))
#define	VR_SETBIT16(acc, r, b)			\
		VR_PUT16(acc, r, (VR_GET16(acc, r) | (b)))
#define	VR_SETBIT32(acc, r, b)			\
		VR_PUT32(acc, r, (VR_GET32(acc, r) | (b)))

/*
 * Set bits b in register r to value v.
 */
#define	VR_SETBITS8(acc, r, b, v)			\
		VR_PUT8(acc, r, (VR_GET8(acc, r) & ~(b)) | (v))
#define	VR_SETBITS16(acc, r, b, v)			\
		VR_PUT16(acc, r, (VR_GET16(acc, r) & ~(b)) | (v))
#define	VR_SETBITS32(acc, r, b, v)			\
		VR_PUT32(acc, r, (VR_GET32(acc, r) & ~(b)) | (v))

/*
 * The descriptor as used by the MAC.
 */
typedef struct {
	uint32_t stat0;
	uint32_t stat1;
	uint32_t data;
	uint32_t next;
} vr_chip_desc_t;

/*
 * A structure describing an DMA object.
 */
typedef struct data_dma {
	ddi_dma_handle_t	handle;
	ddi_acc_handle_t	acchdl;
	uint32_t		paddr;
	char			*buf;
	size_t			bufsz;
} vr_data_dma_t;

/*
 * A descriptor as used by the host.
 */
typedef struct vr_desc {
	vr_chip_desc_t		*cdesc;
	uint32_t		paddr;		/* paddr of cdesc */
	uint32_t		offset;		/* offset to paddr */
	struct vr_desc		*next;
	vr_data_dma_t		dmabuf;
} vr_desc_t;

typedef struct vr_ring {
	vr_desc_t		*desc;
	vr_chip_desc_t		*cdesc;
	uint32_t		cdesc_paddr;
	ddi_dma_handle_t	handle;
	ddi_acc_handle_t	acchdl;
} vr_ring_t;

typedef struct {
	kmutex_t		lock;
	uint32_t		ndesc;
	uint32_t		nfree;
	uint32_t		stallticks;
	uint32_t		resched;
	uint32_t		intr_distance;
	vr_desc_t		*ring;
	vr_desc_t		*wp;			/* write pointer */
	vr_desc_t		*cp;			/* claim pointer */
} vr_tx_t;

typedef struct {
	uint32_t		ndesc;
	vr_desc_t		*ring;
	vr_desc_t		*rp;			/* read pointer */
} vr_rx_t;

typedef enum {
	VR_LINK_STATE_UNKNOWN = LINK_STATE_UNKNOWN,
	VR_LINK_STATE_DOWN = LINK_STATE_DOWN,
	VR_LINK_STATE_UP = LINK_STATE_UP
} vr_link_state_t;

typedef enum {
	VR_LINK_SPEED_UNKNOWN,
	VR_LINK_SPEED_10MBS,
	VR_LINK_SPEED_100MBS
} vr_link_speed_t;

typedef enum {
	VR_LINK_DUPLEX_UNKNOWN = LINK_DUPLEX_UNKNOWN,
	VR_LINK_DUPLEX_FULL = LINK_DUPLEX_FULL,
	VR_LINK_DUPLEX_HALF = LINK_DUPLEX_HALF
} vr_link_duplex_t;

typedef enum {
	VR_LINK_AUTONEG_UNKNOWN,
	VR_LINK_AUTONEG_OFF,
	VR_LINK_AUTONEG_ON
} vr_link_autoneg_t;

/*
 * Pause variations.
 */
typedef enum {
	VR_PAUSE_UNKNOWN,
	VR_PAUSE_NONE = LINK_FLOWCTRL_NONE,
	VR_PAUSE_TRANSMIT = LINK_FLOWCTRL_TX,
	VR_PAUSE_RECEIVE = LINK_FLOWCTRL_RX,
	VR_PAUSE_BIDIRECTIONAL = LINK_FLOWCTRL_BI
} vr_link_flowctrl_t;

/*
 * Type of medium attachement unit.
 */
typedef enum {
	VR_MAU_UNKNOWN = XCVR_UNDEFINED,
	VR_MAU_NONE = XCVR_NONE,
	VR_MAU_10 = XCVR_10,
	VR_MAU_100T4 = XCVR_100T4,
	VR_MAU_100X = XCVR_100X,
	VR_MAU_100T2 = XCVR_100T2,
	VR_MAU_1000X = XCVR_1000X,
	VR_MAU_1000T = XCVR_1000T
} vr_mau_t;

typedef struct {
	vr_link_state_t		state;
	vr_link_speed_t		speed;
	vr_link_duplex_t	duplex;
	vr_link_flowctrl_t	flowctrl;
	vr_mau_t		mau;
} vr_link_t;

typedef enum {
	CHIPSTATE_UNKNOWN,
	CHIPSTATE_INITIALIZED,
	CHIPSTATE_RUNNING,
	CHIPSTATE_STOPPED,
	CHIPSTATE_SLEEPING,
	CHIPSTATE_SUSPENDED,
	CHIPSTATE_SUSPENDED_RUNNING,
	CHIPSTATE_ERROR
} vr_chip_state_t;

typedef struct {
	uint16_t	control;
	uint16_t	status;
	uint16_t	identh;
	uint16_t	identl;
	uint16_t	anadv;
	uint16_t	lpable;
	uint16_t	anexp;
} mii_t;

/*
 * A structure defining the various types of cards and their habits.
 */
typedef struct {
	uint8_t		revmin;
	uint8_t		revmax;
	char		name[128];
	uint32_t	bugs;
	uint32_t	features;
} chip_info_t;

/*
 * A structure describing the card.
 */
typedef struct {
	uint16_t		vendor;
	uint16_t		device;
	uint8_t			revision;
	vr_chip_state_t		state;
	mii_t			mii;
	vr_link_t		link;
	chip_info_t		info;
	uint32_t		phyaddr;
} vr_chip_t;

/*
 * Operational parameters.
 */
typedef struct {
	uint16_t		anadv_en;
	uint16_t		an_phymask;
	uint16_t		an_macmask;
	vr_link_autoneg_t	an_en;
	uint32_t		mtu;
} vr_param_t;

typedef enum {
	VR_SUCCESS = 0,
	VR_FAILURE = 1
} vr_result_t;

typedef struct {
	uint64_t	ether_stat_align_errors;
	uint64_t	ether_stat_carrier_errors;
	uint64_t	ether_stat_ex_collisions;
	uint64_t	ether_stat_fcs_errors;
	uint64_t	ether_stat_first_collisions;
	uint64_t	ether_stat_macrcv_errors;
	uint64_t	ether_stat_macxmt_errors;
	uint64_t	ether_stat_multi_collisions;
	uint64_t	ether_stat_toolong_errors;
	uint64_t	ether_stat_tooshort_errors;
	uint64_t	ether_stat_tx_late_collisions;
	uint64_t	ether_stat_defer_xmts;
	uint64_t	mac_stat_brdcstrcv;
	uint64_t	mac_stat_brdcstxmt;
	uint64_t	mac_stat_multixmt;
	uint64_t	mac_stat_collisions;
	uint64_t	mac_stat_ierrors;
	uint64_t	mac_stat_ipackets;
	uint64_t	mac_stat_multircv;
	uint64_t	mac_stat_norcvbuf;
	uint64_t	mac_stat_noxmtbuf;
	uint64_t	mac_stat_obytes;
	uint64_t	mac_stat_opackets;
	uint64_t	mac_stat_rbytes;
	uint64_t	mac_stat_underflows;
	uint64_t	mac_stat_overflows;
	uint64_t	cyclics;
	uint64_t	txchecks;
	uint64_t	intr_claimed;
	uint64_t	intr_unclaimed;
	uint64_t	linkchanges;
	uint64_t	txcpybytes;
	uint64_t	txmapbytes;
	uint64_t	rxcpybytes;
	uint64_t	rxmapbytes;
	uint64_t	txreclaim0;
	uint64_t	txreclaims;
	uint32_t	txstalls;
	uint32_t	resets;
	uint32_t	allocbfail;
} vr_stats_t;

/*
 * Access attributes for the card.
 */
typedef struct {
	ddi_acc_handle_t	hdl;
	caddr_t			addr;
	pci_regspec_t		reg;
} vr_acc_t;

/*
 * Instance state structure.
 */
typedef struct {
	kmutex_t		oplock;
	dev_info_t		*devinfo;
	uint8_t			vendor_ether_addr [ETHERADDRL];
	char			ifname[12];
	mac_handle_t		machdl;
	ddi_intr_handle_t	intr_hdl;
	uint_t			intr_pri;
	kmutex_t		intrlock;
	vr_chip_t		chip;
	vr_ring_t		txring;
	vr_ring_t		rxring;
	vr_rx_t			rx;
	vr_tx_t			tx;
	ddi_periodic_t		periodic_id;
	int			nsets;
	vr_acc_t		*regset;
	vr_acc_t		*acc_mem;
	vr_acc_t		*acc_io;
	vr_acc_t		*acc_cfg;
	vr_acc_t		*acc_reg;
	vr_param_t		param;
	vr_stats_t		stats;
	struct kstat		*ksp;
	vr_param_t		defaults;
	uint32_t		promisc;
	uint32_t		mhash0;
	uint32_t		mhash1;
	uint32_t		mcount;
	uint32_t		reset;
} vr_t;

/*
 * Function prototypes.
 */
int			vr_mac_getstat(void *arg, uint_t stat, uint64_t *val);
int			vr_mac_start(void *vrp);
void			vr_mac_stop(void *vrp);
int			vr_mac_set_promisc(void *vrp, boolean_t promiscflag);
int			vr_mac_set_multicast(void *vrp, boolean_t add,
			    const uint8_t *mca);
int			vr_mac_set_ether_addr(void *vrp,
			    const uint8_t *macaddr);
mblk_t			*vr_mac_tx_enqueue_list(void *p, mblk_t *mp);
int			vr_mac_getprop(void *arg, const char *pr_name,
			    mac_prop_id_t pr_num, uint_t pr_valsize,
			    void *pr_val);
int			vr_mac_setprop(void *arg, const char *pr_name,
			    mac_prop_id_t pr_num,
			    uint_t pr_valsize, const void *pr_val);
void			vr_mac_propinfo(void *arg, const char *pr_name,
			    mac_prop_id_t pr_num, mac_prop_info_handle_t prh);
uint_t			vr_intr(caddr_t arg1, caddr_t arg2);
#ifdef __cplusplus
}
#endif
#endif	/* _VR_H */
