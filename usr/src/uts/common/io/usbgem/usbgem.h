/*
 * usbgem.h: General USB to Ethernet MAC driver framework
 * @(#)usbgem.h	1.4 12/02/09
 * (C) Copyright 2003-2009 Masayuki Murayama KHF04453@nifty.ne.jp
 */

#ifndef __USBGEM_H__
#define	__USBGEM_H__

#pragma	ident	"@(#)usbgem.h	1.4 12/02/09"

#ifdef USBGEM_CONFIG_GLDv3
#include <sys/mac.h>
#ifndef MAC_VERSION
#include <sys/mac_provider.h>
#endif
#include <sys/mac_ether.h>
#else
#include <sys/gld.h>
#endif /* GLDv3 */

/*
 * Useful macros and typedefs
 */
#define	USBGEM_NAME_LEN	32

#define	USBGEM_TX_TIMEOUT		(drv_usectohz(3*1000000))
#define	USBGEM_TX_TIMEOUT_INTERVAL	(drv_usectohz(1*1000000))
#define	USBGEM_LINK_WATCH_INTERVAL	(drv_usectohz(1*1000000))

/* general return code */
#define	USBGEM_SUCCESS	0
#define	USBGEM_FAILURE	1

/* return code of usbgem_tx_done */
#define	INTR_RESTART_TX	0x80000000U

struct usbgem_stats {
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

struct mcast_addr {
	struct ether_addr	addr;
	uint32_t		hash;
};

#define	USBGEM_MAXMC	64
#define	USBGEM_MCALLOC	(sizeof (struct mcast_addr) * USBGEM_MAXMC)

#define	SLOT(dp, n)	((n) % (dp)->ugc.usbgc_tx_list_max)

/*
 * mac soft state
 */
struct usbgem_dev {
	dev_info_t	*dip;
#ifdef USBGEM_CONFIG_GLDv3
	mac_handle_t	mh;
#else
	void		*macinfo;	/* opaque handle for upper layer */
#endif
	char		name[USBGEM_NAME_LEN];

	/* pointer to usb private data */
	usb_client_dev_data_t	*reg_data;

	/* usb handles */
	usb_pipe_handle_t	default_pipe;
	usb_pipe_handle_t	bulkin_pipe;
	usb_pipe_handle_t	bulkout_pipe;
	usb_pipe_handle_t	intr_pipe;

	/* usb endpoints */
	usb_ep_descr_t		*ep_default;
	usb_ep_descr_t		*ep_bulkin;
	usb_ep_descr_t		*ep_bulkout;
	usb_ep_descr_t		*ep_intr;

	/* usb policies */
	usb_pipe_policy_t	policy_default;
	usb_pipe_policy_t	policy_bulkin;
	usb_pipe_policy_t	policy_bulkout;
	usb_pipe_policy_t	policy_interrupt;

	/* MAC address information */
	struct ether_addr	cur_addr;
	struct ether_addr	dev_addr;

	/* RX state and resource management */
	kmutex_t		rxlock;
	int			rx_busy_cnt;
	boolean_t		rx_active;
	kcondvar_t		rx_drain_cv;

	/* RX buffer management */
	int			rx_buf_len;

	/* TX state and resource management */
	kmutex_t		txlock;
	int			tx_busy_cnt;
	usb_bulk_req_t		*tx_free_list;
	kcondvar_t		tx_drain_cv;
	clock_t			tx_start_time;
	int			bulkout_timeout;	/* in second */
	int			tx_max_packets;
	int			tx_seq_num;
	int			tx_intr_pended;

	/* NIC state from OS view */
	int			nic_state;
#define	NIC_STATE_UNKNOWN	0
#define	NIC_STATE_STOPPED	1
#define	NIC_STATE_INITIALIZED	2
#define	NIC_STATE_ONLINE	3

	/* MAC state from hardware view */
	int			mac_state;
#define	MAC_STATE_DISCONNECTED	0	/* it includes suspended state too */
#define	MAC_STATE_STOPPED	1	/* powered up / buf not initialized */
#define	MAC_STATE_INITIALIZED	2	/* initialized */
#define	MAC_STATE_ONLINE	3	/* working correctly  */
#define	MAC_STATE_ERROR		4	/* need to restart nic */

	clock_t			fatal_error;

	/* robustness: timer and watchdog */
	uint_t			tx_watcher_stop;
	kt_did_t		tx_watcher_did;
	kcondvar_t		tx_watcher_cv;
	kmutex_t		tx_watcher_lock;
	clock_t			tx_watcher_timeout;
	clock_t			tx_watcher_interval;

	/* MII mamagement */
	boolean_t		anadv_autoneg:1;
	boolean_t		anadv_1000fdx:1;
	boolean_t		anadv_1000hdx:1;
	boolean_t		anadv_100t4:1;
	boolean_t		anadv_100fdx:1;
	boolean_t		anadv_100hdx:1;
	boolean_t		anadv_10fdx:1;
	boolean_t		anadv_10hdx:1;
	boolean_t		anadv_1000t_ms:2;
	boolean_t		anadv_pause:1;
	boolean_t		anadv_asmpause:1;
	boolean_t		mii_advert_ro:1;

	boolean_t		full_duplex:1;
	int			speed:3;
#define		USBGEM_SPD_10	0
#define		USBGEM_SPD_100	1
#define		USBGEM_SPD_1000	2
#define		USBGEM_SPD_NUM	3
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

	uint16_t		mii_status_ro;
	uint16_t		mii_xstatus_ro;

	int			mii_state;
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

	uint_t			link_watcher_stop;
	kt_did_t		link_watcher_did;
	kcondvar_t		link_watcher_wait_cv;
	kmutex_t		link_watcher_lock;

	krwlock_t		dev_state_lock;	/* mac_state and nic_state */
	ksema_t			hal_op_lock;	/* serialize hw operations */
	ksema_t			drv_op_lock;	/* hotplug op lock */

	/* multcast list */
	ksema_t			rxfilter_lock;
	int			mc_count;
	int			mc_count_req;
	struct mcast_addr	*mc_list;
	int			rxmode;
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
	struct usbgem_stats		stats;

	/* pointer to local structure */
	void			*private;
	int			priv_size;

	/* configuration */
	struct usbgem_conf {
		/* name */
		char		usbgc_name[USBGEM_NAME_LEN];
		int		usbgc_ppa;

		/* specification on usb */
		int	usbgc_ifnum;	/* interface number */
		int	usbgc_alt;	/* alternate */

		/* specification on tx engine */
		int		usbgc_tx_list_max;

		/* specification on rx engine */
		int		usbgc_rx_header_len;
		int		usbgc_rx_list_max;

		/* time out parameters */
		clock_t		usbgc_tx_timeout;
		clock_t		usbgc_tx_timeout_interval;

		/* flow control */
		int		usbgc_flow_control;

		/* MII timeout parameters */
		clock_t	usbgc_mii_linkdown_timeout;
		clock_t	usbgc_mii_link_watch_interval;
		clock_t	usbgc_mii_reset_timeout;

		clock_t	usbgc_mii_an_watch_interval;
		clock_t	usbgc_mii_an_timeout;
		clock_t	usbgc_mii_an_wait;
		clock_t	usbgc_mii_an_delay;

		/* MII configuration */
		int	usbgc_mii_addr_min;
		int	usbgc_mii_linkdown_action;
		int	usbgc_mii_linkdown_timeout_action;
#define		MII_ACTION_NONE		0
#define		MII_ACTION_RESET	1
#define		MII_ACTION_RSA		2
		boolean_t	usbgc_mii_dont_reset:1;
		boolean_t	usbgc_mii_an_oneshot:1;
		boolean_t	usbgc_mii_hw_link_detection:1;
		boolean_t	usbgc_mii_stop_mac_on_linkdown:1;
		uint16_t	usbgc_mii_an_cmd;

		/* I/O methods */

		/* mac operation */
		int	(*usbgc_attach_chip)(struct usbgem_dev *dp);
		int	(*usbgc_reset_chip)(struct usbgem_dev *dp);
		int	(*usbgc_init_chip)(struct usbgem_dev *dp);
		int	(*usbgc_start_chip)(struct usbgem_dev *dp);
		int	(*usbgc_stop_chip)(struct usbgem_dev *dp);
		uint32_t (*usbgc_multicast_hash)(struct usbgem_dev *dp,
		    const uint8_t *);
		int	(*usbgc_set_rx_filter)(struct usbgem_dev *dp);
		int	(*usbgc_set_media)(struct usbgem_dev *dp);
		int	(*usbgc_get_stats)(struct usbgem_dev *dp);
		void	(*usbgc_interrupt)(struct usbgem_dev *dp, mblk_t *mp);

		/* packet manipulation */
		mblk_t	*(*usbgc_tx_make_packet)(struct usbgem_dev *dp,
		    mblk_t *mp);
		mblk_t	*(*usbgc_rx_make_packet)(struct usbgem_dev *dp,
		    mblk_t *mp);
		/* mii operations */
		int	(*usbgc_mii_probe)(struct usbgem_dev *dp);
		int	(*usbgc_mii_init)(struct usbgem_dev *dp);
		int	(*usbgc_mii_config)(struct usbgem_dev *dp, int *errp);
		uint16_t (*usbgc_mii_read)(struct usbgem_dev *dp, uint_t reg,
		    int *errp);
		void	(*usbgc_mii_write)(struct usbgem_dev *dp, uint_t reg,
		    uint16_t val, int *errp);

		/* jumbo frame */
		int	usbgc_max_mtu;
		int	usbgc_default_mtu;
		int	usbgc_min_mtu;
	} ugc;

	int	misc_flag;
#define	USBGEM_VLAN	0x0001
	timeout_id_t	intr_watcher_id;

	/* buffer size */
	uint_t	mtu;

	/* performance tuning parameters */
	uint_t	txthr;		/* tx fifo threshoold */
	uint_t	txmaxdma;	/* tx max dma burst size */
	uint_t	rxthr;		/* rx fifo threshoold */
	uint_t	rxmaxdma;	/* tx max dma burst size */

	/* kstat stuff */
	kstat_t	*ksp;

	/* ndd stuff */
	caddr_t	nd_data_p;
	caddr_t	nd_arg_p;

#ifdef USBGEM_DEBUG_LEVEL
	int	tx_cnt;
#endif
};

/*
 * Exported functions
 */
int usbgem_ctrl_out(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    void *bp, int size);

int usbgem_ctrl_in(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    void *bp, int size);

int usbgem_ctrl_out_val(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    uint32_t v);

int usbgem_ctrl_in_val(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    void *valp);

void usbgem_generate_macaddr(struct usbgem_dev *, uint8_t *);
boolean_t usbgem_get_mac_addr_conf(struct usbgem_dev *);
int usbgem_mii_probe_default(struct usbgem_dev *);
int usbgem_mii_init_default(struct usbgem_dev *);
int usbgem_mii_config_default(struct usbgem_dev *, int *errp);
void usbgem_mii_update_link(struct usbgem_dev *);
void usbgem_restart_tx(struct usbgem_dev *);
boolean_t usbgem_tx_done(struct usbgem_dev *, int);
void usbgem_receive(struct usbgem_dev *);
struct usbgem_dev *usbgem_do_attach(dev_info_t *,
    struct usbgem_conf *, void *, int);
int usbgem_do_detach(dev_info_t *);

uint32_t usbgem_ether_crc_le(const uint8_t *addr);
uint32_t usbgem_ether_crc_be(const uint8_t *addr);

int usbgem_resume(dev_info_t *);
int usbgem_suspend(dev_info_t *);
int usbgem_quiesce(dev_info_t *);

#ifdef USBGEM_CONFIG_GLDv3
#if DEVO_REV < 4
#define	USBGEM_STREAM_OPS(dev_ops, attach, detach) \
    DDI_DEFINE_STREAM_OPS(dev_ops, nulldev, nulldev, attach, detach, \
    nodev, NULL, D_MP, NULL)
#else
#define	USBGEM_STREAM_OPS(dev_ops, attach, detach) \
    DDI_DEFINE_STREAM_OPS(dev_ops, nulldev, nulldev, attach, detach, \
    nodev, NULL, D_MP, NULL, usbgem_quiesce)
#endif
#else
#define	usbgem_getinfo	gld_getinfo
#define	usbgem_open	gld_open
#define	usbgem_close	gld_close
#define	usbgem_wput	gld_wput
#define	usbgem_wsrv	gld_wsrv
#define	usbgem_rsrv	gld_rsrv
#define	usbgem_power	NULL
#endif
int usbgem_mod_init(struct dev_ops *, char *);
void usbgem_mod_fini(struct dev_ops *);

#define	USBGEM_GET_DEV(dip) \
	((struct usbgem_dev *)(ddi_get_driver_private(dip)))

#endif /* __USBGEM_H__ */
