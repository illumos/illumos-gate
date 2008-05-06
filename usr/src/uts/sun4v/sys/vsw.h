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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This header file contains the data structures which the
 * virtual switch (vsw) uses to communicate with its clients and
 * the outside world.
 */

#ifndef	_VSW_H
#define	_VSW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/vio_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/ethernet.h>
#include <sys/vio_util.h>
#include <sys/vgen_stats.h>
#include <sys/vsw_ldc.h>
#include <sys/vsw_hio.h>

#define	DRV_NAME	"vsw"

/*
 * Only support ETHER mtu at moment.
 */
#define	VSW_MTU		ETHERMAX

/* ID of the source of a frame being switched */
#define	VSW_PHYSDEV		1	/* physical device associated */
#define	VSW_VNETPORT		2	/* port connected to vnet (over ldc) */
#define	VSW_LOCALDEV		4	/* vsw configured as an eth interface */

/*
 * Vsw queue -- largely modeled after squeue
 *
 * VSW_QUEUE_RUNNING, vqueue thread for queue is running.
 * VSW_QUEUE_DRAINED, vqueue thread has drained current work and is exiting.
 * VSW_QUEUE_STOP, request for the vqueue thread to stop.
 * VSW_QUEUE_STOPPED, vqueue thread is not running.
 */
#define	VSW_QUEUE_RUNNING	0x01
#define	VSW_QUEUE_DRAINED	0x02
#define	VSW_QUEUE_STOP		0x04
#define	VSW_QUEUE_STOPPED	0x08

typedef struct vsw_queue_s {
	kmutex_t	vq_lock;	/* Lock, before using any member. */
	kcondvar_t	vq_cv;		/* Async threads block on. */
	uint32_t	vq_state;	/* State flags. */

	mblk_t		*vq_first;	/* First mblk chain or NULL. */
	mblk_t		*vq_last;	/* Last mblk chain. */

	processorid_t	vq_bind;	/* Process to bind to */
	kthread_t	*vq_worker;	/* Queue's thread */
} vsw_queue_t;

/*
 * VSW MAC Ring Resources.
 *	MAC Ring resource is composed of this state structure and
 *	a kernel thread to perform the processing of the ring.
 */
typedef struct vsw_mac_ring_s {
	uint32_t	ring_state;

	mac_blank_t	ring_blank;
	void		*ring_arg;

	vsw_queue_t	*ring_vqp;
	struct vsw	*ring_vswp;
} vsw_mac_ring_t;

/*
 * Maximum Ring Resources.
 */
#define	VSW_MAC_RX_RINGS	0x40

/*
 * States for entry in ring table.
 */
#define	VSW_MAC_RING_FREE	1
#define	VSW_MAC_RING_INUSE	2

/*
 * Number of hash chains in the multicast forwarding database.
 */
#define		VSW_NCHAINS	8

/* Number of transmit descriptors -  must be power of 2 */
#define		VSW_RING_NUM_EL	512

/*
 * State of interface if switch plumbed as network device.
 */
#define		VSW_IF_REG	0x1	/* interface was registered */
#define		VSW_IF_UP	0x2	/* Interface UP */
#define		VSW_IF_PROMISC	0x4	/* Interface in promiscious mode */

#define		VSW_U_P(state)	\
			(state == (VSW_IF_UP | VSW_IF_PROMISC))

/*
 * Switching modes.
 */
#define		VSW_LAYER2		0x1	/* Layer 2 - MAC switching */
#define		VSW_LAYER2_PROMISC	0x2	/* Layer 2 + promisc mode */
#define		VSW_LAYER3		0x4	/* Layer 3 - IP switching */

#define		NUM_SMODES	3	/* number of switching modes */

#define	VSW_PRI_ETH_DEFINED(vswp)	((vswp)->pri_num_types != 0)

/*
 * vsw instance state information.
 */
typedef struct	vsw {
	int			instance;	/* instance # */
	dev_info_t		*dip;		/* associated dev_info */
	uint64_t		regprop;	/* "reg" property */
	struct vsw		*next;		/* next in list */
	char			physname[LIFNAMSIZ];	/* phys-dev */
	uint8_t			smode[NUM_SMODES];	/* switching mode */
	int			smode_idx;	/* curr pos in smode array */
	int			smode_num;	/* # of modes specified */
	kmutex_t		swtmout_lock;	/* setup switching tmout lock */
	boolean_t		swtmout_enabled; /* setup switching tmout on */
	timeout_id_t		swtmout_id;	/* setup switching tmout id */
	uint32_t		switching_setup_done; /* setup switching done */
	int			mac_open_retries; /* mac_open() retry count */
	vsw_port_list_t		plist;		/* associated ports */
	ddi_taskq_t		*taskq_p;	/* VIO ctrl msg taskq */
	mod_hash_t		*fdb_hashp;	/* forwarding database */
	uint32_t		fdb_nchains;	/* # of hash chains in fdb */
	mod_hash_t		*vlan_hashp;	/* vlan hash table */
	uint32_t		vlan_nchains;	/* # of vlan hash chains */
	uint32_t		max_frame_size;	/* max frame size supported */

	mod_hash_t		*mfdb;		/* multicast FDB */
	krwlock_t		mfdbrw;		/* rwlock for mFDB */

	vio_mblk_pool_t		*rxh;		/* Receive pool handle */
	void			(*vsw_switch_frame)
					(struct vsw *, mblk_t *, int,
					vsw_port_t *, mac_resource_handle_t);

	/* mac layer */
	krwlock_t		mac_rwlock;	/* protect fields below */
	mac_handle_t		mh;
	mac_rx_handle_t		mrh;
	multiaddress_capab_t	maddr;		/* Multiple uni addr capable */
	const mac_txinfo_t	*txinfo;	/* MAC tx routine */
	boolean_t		mstarted;	/* Mac Started? */
	boolean_t		mresources;	/* Mac Resources cb? */

	/*
	 * MAC Ring Resources.
	 */
	kmutex_t		mac_ring_lock;	/* Lock for the table. */
	uint32_t		mac_ring_tbl_sz;
	vsw_mac_ring_t		*mac_ring_tbl;	/* Mac ring table. */

	kmutex_t		hw_lock;	/* sync access to HW */
	boolean_t		recfg_reqd;	/* Reconfig of addrs needed */
	int			promisc_cnt;

	/* Machine Description updates  */
	mdeg_node_spec_t	*inst_spec;
	mdeg_handle_t		mdeg_hdl;
	mdeg_handle_t		mdeg_port_hdl;

	/* if configured as an ethernet interface */
	mac_handle_t		if_mh;		/* MAC handle */
	struct ether_addr	if_addr;	/* interface address */
	krwlock_t		if_lockrw;
	uint8_t			if_state;	/* interface state */

	mac_addr_slot_t		addr_slot;	/* Unicast address slot */
	int			addr_set;	/* Addr set where */

	/* multicast addresses when configured as eth interface */
	kmutex_t		mca_lock;	/* multicast lock */
	mcst_addr_t		*mcap;		/* list of multicast addrs */

	uint32_t		pri_num_types;	/* # of priority eth types */
	uint16_t		*pri_types;	/* priority eth types */
	vio_mblk_pool_t		*pri_tx_vmp;	/* tx priority mblk pool */
	uint16_t		default_vlan_id; /* default vlan id */
	uint16_t		pvid;	/* port vlan id (untagged) */
	uint16_t		*vids;	/* vlan ids (tagged) */
	uint16_t		nvids;	/* # of vids */
	uint32_t		vids_size; /* size alloc'd for vids list */

	/* HybridIO related fields */
	boolean_t		hio_capable;	/* Phys dev HIO capable */
	vsw_hio_t		vhio;		/* HybridIO info */
} vsw_t;

/*
 * The flags that are used by vsw_mac_rx().
 */
typedef enum {
	VSW_MACRX_PROMISC = 0x01,
	VSW_MACRX_COPYMSG = 0x02,
	VSW_MACRX_FREEMSG = 0x04
} vsw_macrx_flags_t;


#ifdef DEBUG

extern int vswdbg;
extern void vswdebug(vsw_t *vswp, const char *fmt, ...);

#define	D1(...)		\
if (vswdbg & 0x01)	\
	vswdebug(__VA_ARGS__)

#define	D2(...)		\
if (vswdbg & 0x02)	\
	vswdebug(__VA_ARGS__)

#define	D3(...)		\
if (vswdbg & 0x04)	\
	vswdebug(__VA_ARGS__)

#define	DWARN(...)	\
if (vswdbg & 0x08)	\
	vswdebug(__VA_ARGS__)

#define	DERR(...)	\
if (vswdbg & 0x10)	\
	vswdebug(__VA_ARGS__)

#else

#define	DERR(...)	if (0)	do { } while (0)
#define	DWARN(...)	if (0)	do { } while (0)
#define	D1(...)		if (0)	do { } while (0)
#define	D2(...)		if (0)	do { } while (0)
#define	D3(...)		if (0)	do { } while (0)

#endif	/* DEBUG */


#ifdef	__cplusplus
}
#endif

#endif	/* _VSW_H */
