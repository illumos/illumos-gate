/*
 *  sfe_util.h: header to support the gem layer used by Masa Murayama
 *
 * Copyright (c) 2002-2008 Masayuki Murayama.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SFE_UTIL_H_
#define	_SFE_UTIL_H_
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

/*
 * Useful macros and typedefs
 */

#define	GEM_NAME_LEN	32

#define	GEM_TX_TIMEOUT		(drv_usectohz(5*1000000))
#define	GEM_TX_TIMEOUT_INTERVAL	(drv_usectohz(1*1000000))
#define	GEM_LINK_WATCH_INTERVAL	(drv_usectohz(1*1000000))	/* 1 sec */

/* general return code */
#define	GEM_SUCCESS	0
#define	GEM_FAILURE	(-1)

/* return code of gem_tx_done */
#define	INTR_RESTART_TX	0x80000000

typedef	int32_t		seqnum_t;

/*
 * I/O instructions
 */
#define	OUTB(dp, p, v)	\
	ddi_put8((dp)->regs_handle, \
		(void *)((caddr_t)((dp)->base_addr) + (p)), v)
#define	OUTW(dp, p, v)	\
	ddi_put16((dp)->regs_handle, \
		(void *)((caddr_t)((dp)->base_addr) + (p)), v)
#define	OUTL(dp, p, v)  \
	ddi_put32((dp)->regs_handle, \
	    (void *)((caddr_t)((dp)->base_addr) + (p)), v)
#define	OUTLINL(dp, p, v) \
	ddi_put32((dp)->regs_handle, \
	    (void *)((caddr_t)((dp)->base_addr) + (p)), v); \
	(void) INL((dp), (p))
#define	INB(dp, p)	\
	ddi_get8((dp)->regs_handle, \
		(void *)(((caddr_t)(dp)->base_addr) + (p)))
#define	INW(dp, p)	\
	ddi_get16((dp)->regs_handle, \
		(void *)(((caddr_t)(dp)->base_addr) + (p)))
#define	INL(dp, p)	\
	ddi_get32((dp)->regs_handle, \
		(void *)(((caddr_t)(dp)->base_addr) + (p)))

struct gem_stats {
	uint32_t	intr;

	uint32_t	crc;
	uint32_t	errrcv;
	uint32_t	overflow;
	uint32_t	frame;
	uint32_t	missed;
	uint32_t	runt;
	uint32_t	frame_too_long;
	uint32_t	norcvbuf;
	uint32_t	sqe;

	uint32_t	collisions;
	uint32_t	first_coll;
	uint32_t	multi_coll;
	uint32_t	excoll;
	uint32_t	xmit_internal_err;
	uint32_t	nocarrier;
	uint32_t	defer;
	uint32_t	errxmt;
	uint32_t	underflow;
	uint32_t	xmtlatecoll;
	uint32_t	noxmtbuf;
	uint32_t	jabber;

	uint64_t	rbytes;
	uint64_t	obytes;
	uint64_t	rpackets;
	uint64_t	opackets;
	uint32_t	rbcast;
	uint32_t	obcast;
	uint32_t	rmcast;
	uint32_t	omcast;
	uint32_t	rcv_internal_err;
};
#define	GEM_MAXTXSEGS		4
#define	GEM_MAXRXSEGS		1

#define	GEM_MAXTXFRAGS		8
#define	GEM_MAXRXFRAGS		4
/* TX buffer management */
struct txbuf {
	struct txbuf		*txb_next;

	/* pointer to original mblk */
	mblk_t			*txb_mp;

	/* dma mapping for current packet */
	ddi_dma_cookie_t	txb_dmacookie[GEM_MAXTXFRAGS];
	uint_t			txb_nfrags;

	/* bounce buffer management */
	ddi_dma_handle_t	txb_bdh;
	ddi_acc_handle_t	txb_bah;
	caddr_t			txb_buf;	/* vaddr of bounce buffer */
	uint64_t		txb_buf_dma;	/* paddr of bounce buffer */

	/* timeout management */
	clock_t			txb_stime;

	/* Hardware descriptor info */
	seqnum_t		txb_desc;
	int			txb_ndescs;
	uint64_t		txb_flag;
};


/* RX buffer management */
struct rxbuf {
	/* Hardware independent section */
	struct rxbuf		*rxb_next;
	struct gem_dev		*rxb_devp;

	/* dma mapping management */
	ddi_dma_handle_t	rxb_dh;
	caddr_t			rxb_buf;
	size_t			rxb_buf_len;
	ddi_dma_cookie_t	rxb_dmacookie[GEM_MAXRXFRAGS];
	uint_t			rxb_nfrags;

	/* bounce buffer management */
	ddi_acc_handle_t	rxb_bah;
};

struct mcast_addr {
	struct ether_addr	addr;
	uint32_t		hash;
};

#define	GEM_MAXMC		64
#define	GEM_MCALLOC		(sizeof (struct mcast_addr) * GEM_MAXMC)

#define	SUB(x, y)		((seqnum_t)((x) - (y)))
#define	SLOT(seqnum, size)	(((unsigned int)(seqnum)) & ((size)-1))

/*
 * mac soft state
 */
struct gem_dev {
	dev_info_t		*dip;
	mac_handle_t		mh;
	char			name[GEM_NAME_LEN];
	void			*base_addr;
	ddi_acc_handle_t	regs_handle;
	ddi_iblock_cookie_t	iblock_cookie;

	/* MAC address information */
	struct ether_addr	cur_addr;
	struct ether_addr	dev_addr;

	/* Descriptor rings, io area */
	ddi_dma_handle_t	desc_dma_handle;
	ddi_acc_handle_t	desc_acc_handle;
	caddr_t			rx_ring;
	caddr_t			tx_ring;
	caddr_t			io_area;
	/* caddr_t			rx_buf; */

	uint64_t		rx_ring_dma;
	uint64_t		tx_ring_dma;
	uint64_t		io_area_dma;

	/* RX slot ring management */
	kmutex_t		intrlock;
	boolean_t		intr_busy;
	seqnum_t		rx_active_head;
	seqnum_t		rx_active_tail;
	mac_resource_handle_t	mac_rx_ring_ha;
	/* Rx buffer management */
	struct rxbuf		*rx_buf_head;
	struct rxbuf		*rx_buf_tail;
	struct rxbuf		*rx_buf_freelist;
	int			rx_buf_allocated;
	int			rx_buf_freecnt;
	int			rx_buf_len;

	/* TX descriptor ring management */
	seqnum_t		tx_desc_head;
	seqnum_t		tx_desc_tail;
	seqnum_t		tx_desc_intr;

	/* TX buffur ring management */
	kmutex_t		xmitlock;
	kcondvar_t		tx_drain_cv;
	seqnum_t		tx_active_head;
	seqnum_t		tx_active_tail;
	seqnum_t		tx_softq_head;
	seqnum_t		tx_softq_tail;
	seqnum_t		tx_free_head;
	seqnum_t		tx_free_tail;
	int			tx_max_packets;

	/* TX buffer resource management */
	struct txbuf		*tx_buf;
	seqnum_t		tx_slots_base;

	/* TX state management */
	int			tx_busy;
	int			tx_reclaim_busy;
	clock_t			tx_blocked;

	/* NIC state */
	volatile boolean_t	mac_active;	/* tx and rx are running */
	volatile int		nic_state;	/* logical driver state */
#define	NIC_STATE_STOPPED	0
#define	NIC_STATE_INITIALIZED	1
#define	NIC_STATE_ONLINE	2
	volatile boolean_t	mac_suspended;

	/* robustness: timer and watchdog */
	volatile timeout_id_t	timeout_id;


	/* MII management */
	boolean_t		anadv_autoneg:1;
	boolean_t		anadv_1000fdx:1;
	boolean_t		anadv_1000hdx:1;
	boolean_t		anadv_100t4:1;
	boolean_t		anadv_100fdx:1;
	boolean_t		anadv_100hdx:1;
	boolean_t		anadv_10fdx:1;
	boolean_t		anadv_10hdx:1;
	boolean_t		anadv_flow_control:2;
	boolean_t		mii_advert_ro:1;

	boolean_t		full_duplex:1;
	int			speed:3;
#define		GEM_SPD_10	0
#define		GEM_SPD_100	1
#define		GEM_SPD_1000	2
#define		GEM_SPD_NUM	3
	unsigned int		flow_control:2;
#define		FLOW_CONTROL_NONE	0
#define		FLOW_CONTROL_SYMMETRIC	1
#define		FLOW_CONTROL_TX_PAUSE	2
#define		FLOW_CONTROL_RX_PAUSE	3

	boolean_t		mii_supress_msg:1;

	uint32_t		mii_phy_id;
	uint16_t		mii_status;
	uint16_t		mii_advert;
	uint16_t		mii_lpable;
	uint16_t		mii_exp;
	uint16_t		mii_ctl1000;
	uint16_t		mii_stat1000;
	uint16_t		mii_xstatus;
	int8_t			mii_phy_addr;	/* must be signed */

	uint8_t			mii_state;
#define		MII_STATE_UNKNOWN		0
#define		MII_STATE_RESETTING		1
#define		MII_STATE_AUTONEGOTIATING	2
#define		MII_STATE_AN_DONE		3
#define		MII_STATE_MEDIA_SETUP		4
#define		MII_STATE_LINKUP		5
#define		MII_STATE_LINKDOWN		6

	clock_t			mii_last_check;	/* in tick */
	clock_t			mii_timer;	/* in tick */
#define		MII_RESET_TIMEOUT	drv_usectohz(1000*1000)
#define		MII_AN_TIMEOUT		drv_usectohz(5000*1000)
#define		MII_LINKDOWN_TIMEOUT	drv_usectohz(10000*1000)
	clock_t			mii_interval;	/* in tick */
	clock_t			linkup_delay;	/* in tick */

	volatile timeout_id_t	link_watcher_id;

	ddi_softintr_t		soft_id;

	/* multcast list management */
	int16_t			mc_count;
	int16_t			mc_count_req;
	struct mcast_addr	*mc_list;
	uint32_t		rxmode;
#define		RXMODE_PROMISC		0x01
#define		RXMODE_ALLMULTI_REQ	0x02
#define		RXMODE_MULTI_OVF	0x04
#define		RXMODE_ENABLE		0x08
#define		RXMODE_ALLMULTI		(RXMODE_ALLMULTI_REQ | RXMODE_MULTI_OVF)
#define		RXMODE_BITS	\
			"\020"	\
			"\004ENABLE"	\
			"\003MULTI_OVF"	\
			"\002ALLMULTI_REQ"	\
			"\001PROMISC"

	/* statistcs */
	struct gem_stats		stats;

	/* pointer to local structure */
	void			*private;
	int			priv_size;

	/* polling mode */
	int			poll_pkt_delay;	/* in number of packets */

	/* descriptor area */
	int			tx_desc_size;
	int			rx_desc_size;

	/* configuration */
	struct gem_conf {
		/* name */
		char	gc_name[GEM_NAME_LEN];

		/* specification on tx and rx dma engine */
		long	gc_tx_buf_align;
		int	gc_tx_max_frags;
		int	gc_tx_max_descs_per_pkt;
		int	gc_tx_buf_size;
		int	gc_tx_buf_limit;
		int	gc_tx_desc_unit_shift;
		int	gc_tx_ring_size;
		int	gc_tx_ring_limit;
		int	gc_tx_copy_thresh;
		boolean_t gc_tx_auto_pad;
		boolean_t gc_tx_desc_write_oo;

		long	gc_rx_buf_align;
		int	gc_rx_max_frags;
		int	gc_rx_desc_unit_shift;
		int	gc_rx_ring_size;
		int	gc_rx_copy_thresh;
		int	gc_rx_buf_max;
		int	gc_rx_header_len;

		int	gc_io_area_size;

		/* memory mapping attributes */
		struct ddi_device_acc_attr	gc_dev_attr;
		struct ddi_device_acc_attr	gc_buf_attr;
		struct ddi_device_acc_attr	gc_desc_attr;

		/* dma attributes */
		ddi_dma_attr_t		gc_dma_attr_desc;
		ddi_dma_attr_t		gc_dma_attr_txbuf;
		ddi_dma_attr_t		gc_dma_attr_rxbuf;

		/* tx time out parameters */
		clock_t	gc_tx_timeout;
		clock_t	gc_tx_timeout_interval;

		/* auto negotiation capability */
		int		gc_flow_control;

		/* MII mode */
		int	gc_mii_mode;
#define		GEM_MODE_100BASETX	0
#define		GEM_MODE_1000BASET	1
#define		GEM_MODE_1000BASETX	2

		/* MII link state watch parameters */
		clock_t	gc_mii_linkdown_timeout;
		clock_t	gc_mii_link_watch_interval;
		clock_t	gc_mii_reset_timeout;

		clock_t	gc_mii_an_watch_interval;
		clock_t	gc_mii_an_timeout;
		clock_t	gc_mii_an_wait;
		clock_t	gc_mii_an_delay;

		/* MII configuration */
		int	gc_mii_addr_min;
		int	gc_mii_linkdown_action;
		int	gc_mii_linkdown_timeout_action;
#define		MII_ACTION_NONE		0
#define		MII_ACTION_RESET	1
#define		MII_ACTION_RSA		2
		boolean_t	gc_mii_dont_reset;
		boolean_t	gc_mii_an_oneshot;
		boolean_t	gc_mii_hw_link_detection;
		boolean_t	gc_mii_stop_mac_on_linkdown;

		/* I/O methods */

		/* mac operation */
		int	(*gc_attach_chip)(struct gem_dev *dp);
		int	(*gc_reset_chip)(struct gem_dev *dp);
		int	(*gc_init_chip)(struct gem_dev *dp);
		int	(*gc_start_chip)(struct gem_dev *dp);
		int	(*gc_stop_chip)(struct gem_dev *dp);
		uint32_t (*gc_multicast_hash)(struct gem_dev *dp, uint8_t *);
		int	(*gc_set_rx_filter)(struct gem_dev *dp);
		int	(*gc_set_media)(struct gem_dev *dp);
		int	(*gc_get_stats)(struct gem_dev *dp);
		uint_t	(*gc_interrupt)(struct gem_dev *dp);

		/* descriptor operation */
		int	(*gc_tx_desc_write)(struct gem_dev *dp, int slot,
				ddi_dma_cookie_t *dmacookie,
				int frags, uint64_t flag);
#define			GEM_TXFLAG_INTR		0x00000001ull
#define			GEM_TXFLAG_TCP		0x00000002ull
#define				GEM_TXFLAG_TCP_SHIFT		1ull
#define			GEM_TXFLAG_UDP		0x00000004ull
#define				GEM_TXFLAG_UDP_SHIFT		2ull
#define			GEM_TXFLAG_IPv4		0x00000008ull
#define				GEM_TXFLAG_IPv4_SHIFT		3ull
#define			GEM_TXFLAG_IPv6		0x00000010ull
#define				GEM_TXFLAG_IPv6_SHIFT		4ull
#define			GEM_TXFLAG_HEAD		0x00000020ull
#define			GEM_TXFLAG_TAIL		0x00000040ull
#define			GEM_TXFLAG_SWVTAG	0x00000080ull
#define			GEM_TXFLAG_PRIVATE	0x0000ff00ull
#define				GEM_TXFLAG_PRIVATE_SHIFT	8ull
#define				GEM_TXFLAG_PRIVATE_MASK	0xffull
#define			GEM_TXFLAG_VID		0x0fff0000ull
#define				GEM_TXFLAG_VID_SHIFT		16ull
#define				GEM_TXFLAG_VID_MASK		0xfffull
#define			GEM_TXFLAG_CFI		0x10000000ull
#define			GEM_TXFLAG_PRI		0xe0000000ull
#define				GEM_TXFLAG_PRI_SHIFT		29ull
#define				GEM_TXFLAG_PRI_MASK		0x7ull
#define			GEM_TXFLAG_VTAG		0xffff0000ull
#define				GEM_TXFLAG_VTAG_SHIFT		16ull
#define			GEM_TXFLAG_HCKSTART	0x000000ff00000000ull
#define				GEM_TXFLAG_HCKSTART_SHIFT	32ull
#define			GEM_TXFLAG_HCKSTUFF	0x0000ff0000000000ull
#define				GEM_TXFLAG_HCKSTUFF_SHIFT	40ull
#define			GEM_TXFLAG_TCPHLEN	0x0000ff0000000000ull
#define				GEM_TXFLAG_TCPHLEN_SHIFT	40ull
#define			GEM_TXFLAG_MSS		0xffff000000000000ull
#define				GEM_TXFLAG_MSS_SHIFT	48ull

		void (*gc_tx_start) (struct gem_dev *dp, int slot, int frags);
		void	(*gc_rx_desc_write)(struct gem_dev *dp, int slot,
			    ddi_dma_cookie_t *dmacookie, int frags);
		void	(*gc_rx_start)(struct gem_dev *dp, int slot, int frags);

		uint_t	(*gc_tx_desc_stat)
			(struct gem_dev *dp, int slot, int descs);
#define			GEM_TX_DONE	0x00010000
#define			GEM_TX_ERR	0x00020000


		uint64_t (*gc_rx_desc_stat)
				(struct gem_dev *dp, int slot, int frags);

#define			GEM_RX_CKSUM		0xffff000000000000ull
#define			GEM_RX_CKSUM_SHIFT	48
#define			GEM_RX_PRI		0x0000e00000000000ull
#define			GEM_RX_PRI_SHIFT	45
#define			GEM_RX_CFI		0x0000100000000000ull
#define			GEM_RX_VID		0x00000fff00000000ull
#define			GEM_RX_VID_SHIFT	32
#define			GEM_RX_VTAG		0x0000ffff00000000ull
#define			GEM_RX_VTAG_SHIFT	32

#define			GEM_RX_CKSUM_IPv6	0x00080000ul
#define			GEM_RX_CKSUM_IPv6_SHIFT	19
#define			GEM_RX_CKSUM_IPv4	0x00040000ul
#define			GEM_RX_CKSUM_IPv4_SHIFT	18
#define			GEM_RX_CKSUM_UDP	0x00020000ul
#define			GEM_RX_CKSUM_UDP_SHIFT	17
#define			GEM_RX_CKSUM_TCP	0x00010000ul
#define			GEM_RX_CKSUM_TCP_SHIFT	16
#define			GEM_RX_ERR		0x00008000ul
#define			GEM_RX_DONE		0x00004000ul
#define			GEM_RX_LEN		0x00003ffful	/* 16KB - 1 */

		void	(*gc_tx_desc_init)(struct gem_dev *dp, int slot);
		void	(*gc_rx_desc_init)(struct gem_dev *dp, int slot);
		void	(*gc_tx_desc_clean)(struct gem_dev *dp, int slot);
		void	(*gc_rx_desc_clean)(struct gem_dev *dp, int slot);

		/* mii operations */
		int	(*gc_mii_probe)(struct gem_dev *dp);
		int	(*gc_mii_init)(struct gem_dev *dp);
		int	(*gc_mii_config)(struct gem_dev *dp);
		void	(*gc_mii_sync)(struct gem_dev *dp);
		uint16_t (*gc_mii_read)(struct gem_dev *dp, uint_t reg);
		void (*gc_mii_write)(struct gem_dev *dp,
			uint_t reg, uint16_t val);
		void (*gc_mii_tune_phy)(struct gem_dev *dp);

		/* packet in/out operation for copy-style  */
		void (*gc_put_packet)(struct gem_dev *dp,
			mblk_t *, void *, size_t);
		mblk_t	*(*gc_get_packet)(struct gem_dev *dp,
			struct rxbuf *, size_t);
		int	gc_nports;

		/* hw checksum */
		uint32_t	gc_hck_rx_start;
	} gc;

	uint32_t	misc_flag;
#define		GEM_LSO			0x00000400
#define		GEM_CTRL_PKT		0x00000200
#define		GEM_SOFTINTR		0x00000100
#define		GEM_POLL_RXONLY		0x00000080
#define		GEM_VLAN_HARD		0x00000040
#define		GEM_VLAN_SOFT		0x00000020
#define		GEM_VLAN		(GEM_VLAN_HARD | GEM_VLAN_SOFT)
#define		GEM_CKSUM_HEADER_IPv4	0x00000010
#define		GEM_CKSUM_PARTIAL	0x00000008
#define		GEM_CKSUM_FULL_IPv6	0x00000004
#define		GEM_CKSUM_FULL_IPv4	0x00000002
#define		GEM_NOINTR		0x00000001

	volatile timeout_id_t	intr_watcher_id;

	uint_t	mtu;

	/* performance tuning parameters */
	uint_t	txthr;		/* tx fifo threshoold */
	uint_t	txmaxdma;	/* tx max dma burst size */
	uint_t	rxthr;		/* rx fifo threshoold */
	uint_t	rxmaxdma;	/* tx max dma burst size */

	/* kstat stuff */
	kstat_t	*ksp;

	/* multiple port device support */
	struct	gem_dev	*next;	/* pointer to next port on the same device */
	int		port;

	/* ndd stuff */
	caddr_t	nd_data_p;
	caddr_t	nd_arg_p;

#ifdef GEM_DEBUG_LEVEL
	int	tx_cnt;
#endif
};

/*
 * Exported functions
 */
boolean_t gem_get_mac_addr_conf(struct gem_dev *);
int gem_mii_probe_default(struct gem_dev *);
int gem_mii_config_default(struct gem_dev *);
boolean_t gem_mii_link_check(struct gem_dev *dp);
uint16_t gem_mii_read(struct gem_dev *, uint_t);
void gem_mii_write(struct gem_dev *, uint_t, uint16_t);
int gem_reclaim_txbuf(struct gem_dev *dp);
int gem_restart_nic(struct gem_dev *dp, uint_t flags);
#define	GEM_RESTART_NOWAIT	0x00000002
#define	GEM_RESTART_KEEP_BUF	0x00000001
boolean_t gem_tx_done(struct gem_dev *);
int gem_receive(struct gem_dev *);
int gem_receive_copy(struct gem_dev *);
struct gem_dev *gem_do_attach(dev_info_t *, int,
		struct gem_conf *, void *, ddi_acc_handle_t *, void *, int);

mblk_t *gem_send_common(struct gem_dev *, mblk_t *, uint32_t);
#define	GEM_SEND_COPY	0x00008000
#define	GEM_SEND_CTRL	0x000000ff	/* private flags for control packets */
#define	GEM_SEND_VTAG	0xffff0000
#define	GEM_SEND_VTAG_SHIFT	16

mblk_t *gem_get_packet_default(struct gem_dev *, struct rxbuf *, size_t);

uint32_t gem_ether_crc_le(const uint8_t *addr, int len);
uint32_t gem_ether_crc_be(const uint8_t *addr, int len);
int gem_do_detach(dev_info_t *);

int gem_getlongprop_buf(dev_t dev, dev_info_t *dip,
	int flags, char *name, void *buf, int *lenp);
int gem_getprop(dev_t dev, dev_info_t *dip,
	int flags, char *name, int defvalue);

struct rxbuf *gem_get_rxbuf(struct gem_dev *, int);

void gem_rx_desc_dma_sync(struct gem_dev *, int, int, int);
void gem_tx_desc_dma_sync(struct gem_dev *, int, int, int);

int gem_resume(dev_info_t *);
int gem_suspend(dev_info_t *);
uint8_t gem_search_pci_cap(dev_info_t *dip, ddi_acc_handle_t, uint8_t);
int gem_pci_set_power_state(dev_info_t *, ddi_acc_handle_t, uint_t);
int gem_pci_regs_map_setup(dev_info_t *, uint32_t, uint32_t,
	struct ddi_device_acc_attr *, caddr_t *, ddi_acc_handle_t *);
void gem_mod_init(struct dev_ops *, char *);
void gem_mod_fini(struct dev_ops *);

#define	GEM_GET_DEV(dip) \
	((struct gem_dev *)(ddi_get_driver_private(dip)))
#endif /* _SFE_UTIL_H_ */
