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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Driver specific data structures and function prototypes
 */

#ifndef	_OCE_IMPL_H_
#define	_OCE_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/kstat.h>
#include <sys/ddi_intr.h>
#include <sys/cmn_err.h>
#include <sys/byteorder.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/bitmap.h>
#include <sys/ddidmareq.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/note.h>
#include <oce_hw.h>
#include <oce_hw_eth.h>
#include <oce_io.h>
#include <oce_buf.h>
#include <oce_utils.h>
#include <oce_version.h>

#define	OCE_MIN_MTU	1500
#define	OCE_MAX_MTU	9000
#define	OCE_MAX_MCA	32
#define	OCE_RQ_MAX_FRAME_SZ 9018

#define	OCE_MAX_EQ	8
#define	OCE_MAX_CQ	1024
#define	OCE_MAX_WQ	8
#define	OCE_WQ_NUM_BUFFERS	2048
#define	OCE_WQ_BUF_SIZE	2048
#define	OCE_LSO_MAX_SIZE (32 * 1024)
#define	OCE_DEFAULT_BCOPY_LIMIT	1024
#define	OCE_DEFAULT_WQ_EQD	16

#define	OCE_MAX_RQ		8
#define	OCE_MAX_RQ_POSTS	255
#define	OCE_RQ_NUM_BUFFERS	2048
#define	OCE_RQ_BUF_SIZE		2048
#define	OCE_DEFAULT_RECHARGE_THRESHOLD	OCE_MAX_RQ_POSTS
#define	OCE_NUM_USED_VECTORS    2
#define	OCE_DMA_ALIGNMENT   0x1000ull

#define	OCE_DEFAULT_TX_RING_SIZE    256
#define	OCE_DEFAULT_RX_RING_SIZE    1024

#define	OCE_INVAL_IF_ID			-1

#define	OCE_DEFAULT_IF_CAP	(MBX_RX_IFACE_FLAGS_PROMISCUOUS	| \
			MBX_RX_IFACE_FLAGS_BROADCAST		| \
			MBX_RX_IFACE_FLAGS_UNTAGGED		| \
			MBX_RX_IFACE_FLAGS_MCAST_PROMISCUOUS	| \
			MBX_RX_IFACE_FLAGS_PASS_L3L4)

#define	OCE_DEFAULT_IF_CAP_EN	(MBX_RX_IFACE_FLAGS_BROADCAST	| \
				MBX_RX_IFACE_FLAGS_UNTAGGED	| \
				MBX_RX_IFACE_FLAGS_MCAST_PROMISCUOUS	| \
				MBX_RX_IFACE_FLAGS_PASS_L3L4)

#define	OCE_RX_FILTER_GLOBAL_FLAGS	(NTWK_RX_FILTER_IP_CKSUM | \
					NTWK_RX_FILTER_TCP_CKSUM | \
					NTWK_RX_FILTER_UDP_CKSUM | \
					NTWK_RX_FILTER_STRIP_CRC)


#define	OCE_FM_CAPABILITY		DDI_FM_EREPORT_CAPABLE	|	\
					DDI_FM_ACCCHK_CAPABLE	|	\
					DDI_FM_DMACHK_CAPABLE

/* flow control definitions */
#define	OCE_FC_NONE	0x00000000
#define	OCE_FC_TX	0x00000001
#define	OCE_FC_RX	0x00000002
#define	OCE_DEFAULT_FLOW_CONTROL	(OCE_FC_TX | OCE_FC_RX)

/* PCI Information */
#define	OCE_DEV_CFG_BAR	0x01
#define	OCE_PCI_CSR_BAR	0x02
#define	OCE_PCI_DB_BAR	0x03

/* macros for device IO */
#define	OCE_READ_REG32(handle, addr) ddi_get32(handle, addr)
#define	OCE_WRITE_REG32(handle, addr, value) ddi_put32(handle, addr, value)

#define	OCE_CSR_READ32(dev, offset) \
	OCE_READ_REG32((dev)->csr_handle, \
	    (uint32_t *)(void *)((dev)->csr_addr + offset))

#define	OCE_CSR_WRITE32(dev, offset, value) \
	OCE_WRITE_REG32((dev)->csr_handle, \
	    (uint32_t *)(void *)((dev)->csr_addr + offset), value)

#define	OCE_DB_READ32(dev, offset) \
	OCE_READ_REG32((dev)->db_handle, \
	    (uint32_t *)(void *)((dev)->db_addr + offset))

#define	OCE_DB_WRITE32(dev, offset, value) \
	OCE_WRITE_REG32((dev)->db_handle, \
		(uint32_t *)(void *)((dev)->db_addr + offset), value)

#define	OCE_CFG_READ32(dev, offset) \
	OCE_READ_REG32((dev)->dev_cfg_handle, \
	    (uint32_t *)(void *)((dev)->dev_cfg_addr + offset))

#define	OCE_CFG_WRITE32(dev, offset, value) \
	OCE_WRITE_REG32((dev)->dev_cfg_handle, \
	    (uint32_t *)(void *)((dev)->dev_cfg_addr + offset), value)

#define	OCE_PCI_FUNC(dev) \
	((OCE_CFG_READ32(dev, PCICFG_INTR_CTRL) \
	    >> HOSTINTR_PFUNC_SHIFT) & HOSTINTR_PFUNC_MASK)

#define	DEV_LOCK(dev)	{ oce_chip_di(dev); mutex_enter(&dev->dev_lock); }

#define	DEV_UNLOCK(dev)	{ mutex_exit(&dev->dev_lock); oce_chip_ei(dev); }

enum oce_ring_size {
	RING_SIZE_256  = 256,
	RING_SIZE_512  = 512,
	RING_SIZE_1024 = 1024,
	RING_SIZE_2048 = 2048
};

enum oce_driver_state {
	STATE_INIT		= 0x2,
	STATE_MAC_STARTED	= 0x4,
	STATE_QUIESCE		= 0x8,
	STATE_MAC_STOPPING	= 0x10
};

struct oce_dev {
	uint32_t dev_id;		/* device ID or instance number */
	int32_t if_id; 			/* IF ID */
	uint8_t fn; 			/* function number */
	uint8_t fw_version[32]; 	/* fw version string */
	enum oce_driver_state state; 	/* state */
	struct oce_mq *mq;		/* MQ ring */
	oce_dma_buf_t *bmbx;		/* Bootstrap MailBox	*/
	kmutex_t bmbx_lock;		/* Bootstrap Lock	*/
	uint16_t mod_mask;		/* Log Mask 	*/
	int16_t severity;		/* Log level	*/
	struct oce_wq *wq[OCE_MAX_WQ];	/* TXQ Array */
	struct oce_rq *rq[OCE_MAX_RQ];	/* RXQ Array */
	struct oce_cq *cq[OCE_MAX_CQ];	/* Completion Queues */
	struct oce_eq *eq[OCE_MAX_EQ];	/* Event Queues	*/
	uint32_t bcopy_limit;		/* BCOPY Limit */

	uint32_t cookie;

	clock_t stat_ticks;
	uint32_t in_stats;

	/* Add implementation specific stuff here */
	int num_bars;
	ddi_acc_handle_t cfg_handle;	/* PCI Config Space Regs */
	caddr_t csr_addr;
	ddi_acc_handle_t csr_handle;	/* MMIO Control Status Regs */
	caddr_t db_addr;
	ddi_acc_handle_t db_handle;	/* MMIO DoorBell Area */
	caddr_t dev_cfg_addr;
	ddi_acc_handle_t dev_cfg_handle;	/* MMIO CONFIG SPACE */
	mac_handle_t mac_handle;	/* MAC HANDLE	*/

	/* device info structure for device tree node */
	dev_info_t *dip;
	kstat_t *oce_kstats;		/* NIC STATS */
	oce_dma_buf_t *stats_dbuf;	/* STATS BUFFER */
	struct mbx_get_nic_stats *hw_stats;
	/* dev stats */
	uint32_t tx_errors;
	uint32_t tx_noxmtbuf;

	/* link status */
	struct link_status link;

	/* flow control settings */
	uint32_t flow_control;

	/* the type of interrupts supported */
	int intr_types;
	/* number of vectors used */
	int num_vectors;
	/* interrupt priority */
	uint_t intr_pri;
	int intr_cap;
	/* intr handler table */
	ddi_intr_handle_t *htable;

	/* lock for device */
	kmutex_t dev_lock;

	/* hardware mac address */
	uint8_t mac_addr[ETHERADDRL];

	/* Current Multicast address table that we have set to h/w */
	uint16_t num_mca;
	struct ether_addr multi_cast[OCE_MAX_MCA];

	/* device configuration */
	uint32_t pmac_id; /* used to add or remove mac */
	uint8_t unicast_addr[ETHERADDRL];
	uint32_t mtu;
	enum oce_ring_size tx_ring_size;
	enum oce_ring_size rx_ring_size;
	boolean_t lso_capable;
	boolean_t promisc;
	uint32_t if_cap_flags;
	int32_t  fm_caps;
	uint32_t  attach_state;
	boolean_t suspended;
	uint32_t  neqs;	/* No of event queues */
	uint32_t  nwqs;	/* No of Work Queues */
	uint32_t  nrqs;	/* No of Receive Queues */

	/* fw config: only relevant fields */
	uint32_t    config_number;
	uint32_t    asic_revision;
	uint32_t    port_id;
	uint32_t    function_mode;
};

/* GLD handler functions */
int oce_m_start(void *arg);
void oce_m_stop(void *arg);
mblk_t *oce_m_send(void *arg, mblk_t *pkt);
int oce_m_promiscuous(void *arg, boolean_t enable);
int oce_m_multicast(void *arg, boolean_t add, const uint8_t *mca);
int oce_m_unicast(void *arg, const uint8_t *uca);
boolean_t oce_m_getcap(void *arg, mac_capab_t cap, void *data);
void oce_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
int oce_m_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, const void *val);
int oce_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t flags, uint_t size, void *val, uint_t *perm);
int oce_m_stat(void *arg, uint_t stat, uint64_t *val);

/* Hardware start/stop functions */
int oce_start(struct oce_dev *dev);
void oce_stop(struct oce_dev *dev);

/* FMA support Functions */
void oce_fm_init(struct oce_dev *dev);
void oce_fm_fini(struct oce_dev *dev);
void oce_set_dma_fma_flags(int fm_caps);
void oce_set_reg_fma_flags(int fm_caps);
void oce_set_tx_map_dma_fma_flags(int fm_caps);
void oce_fm_ereport(struct oce_dev *dev, char *detail);
int  oce_fm_check_acc_handle(struct oce_dev *dev,
    ddi_acc_handle_t acc_handle);
int  oce_fm_check_dma_handle(struct oce_dev *dev,
    ddi_dma_handle_t dma_handle);

/* Interrupt handling */
int oce_setup_intr(struct oce_dev *dev);
int oce_teardown_intr(struct oce_dev *dev);
int oce_setup_handlers(struct oce_dev *dev);
void oce_remove_handler(struct oce_dev *dev);
void oce_ei(struct oce_dev *dev);
void oce_di(struct oce_dev *dev);
void oce_chip_ei(struct oce_dev *dev);
void oce_chip_di(struct oce_dev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _OCE_IMPL_H_ */
