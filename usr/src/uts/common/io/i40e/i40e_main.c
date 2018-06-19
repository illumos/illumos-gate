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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2017 Tegile Systems, Inc.  All rights reserved.
 */

/*
 * i40e - Intel 10/40 Gb Ethernet driver
 *
 * The i40e driver is the main software device driver for the Intel 40 Gb family
 * of devices. Note that these devices come in many flavors with both 40 GbE
 * ports and 10 GbE ports. This device is the successor to the 82599 family of
 * devices (ixgbe).
 *
 * Unlike previous generations of Intel 1 GbE and 10 GbE devices, the 40 GbE
 * devices defined in the XL710 controller (previously known as Fortville) are a
 * rather different beast and have a small switch embedded inside of them. In
 * addition, the way that most of the programming is done has been overhauled.
 * As opposed to just using PCIe memory mapped registers, it also has an
 * administrative queue which is used to communicate with firmware running on
 * the chip.
 *
 * Each physical function in the hardware shows up as a device that this driver
 * will bind to. The hardware splits many resources evenly across all of the
 * physical functions present on the device, while other resources are instead
 * shared across the entire card and its up to the device driver to
 * intelligently partition them.
 *
 * ------------
 * Organization
 * ------------
 *
 * This driver is made up of several files which have their own theory
 * statements spread across them. We'll touch on the high level purpose of each
 * file here, and then we'll get into more discussion on how the device is
 * generally modelled with respect to the interfaces in illumos.
 *
 * i40e_gld.c: This file contains all of the bindings to MAC and the networking
 *             stack.
 *
 * i40e_intr.c: This file contains all of the interrupt service routines and
 *              contains logic to enable and disable interrupts on the hardware.
 *              It also contains the logic to map hardware resources such as the
 *              rings to and from interrupts and controls their ability to fire.
 *
 *              There is a big theory statement on interrupts present there.
 *
 * i40e_main.c: The file that you're currently in. It interfaces with the
 *              traditional OS DDI interfaces and is in charge of configuring
 *              the device.
 *
 * i40e_osdep.[ch]: These files contain interfaces and definitions needed to
 *                  work with Intel's common code for the device.
 *
 * i40e_stats.c: This file contains the general work and logic around our
 *               kstats. A theory statement on their organization and use of the
 *               hardware exists there.
 *
 * i40e_sw.h: This header file contains all of the primary structure definitions
 *            and constants that are used across the entire driver.
 *
 * i40e_transceiver.c: This file contains all of the logic for sending and
 *                     receiving data. It contains all of the ring and DMA
 *                     allocation logic, as well as, the actual interfaces to
 *                     send and receive data.
 *
 *                     A big theory statement on ring management, descriptors,
 *                     and how it ties into the OS is present there.
 *
 * --------------
 * General Design
 * --------------
 *
 * Before we go too far into the general way we've laid out data structures and
 * the like, it's worth taking some time to explain how the hardware is
 * organized. This organization informs a lot of how we do things at this time
 * in the driver.
 *
 * Each physical device consists of a number of one or more ports, which are
 * considered physical functions in the PCI sense and thus each get enumerated
 * by the system, resulting in an instance being created and attached to. While
 * there are many resources that are unique to each physical function eg.
 * instance of the device, there are many that are shared across all of them.
 * Several resources have an amount reserved for each Virtual Station Interface
 * (VSI) and then a static pool of resources, available for all functions on the
 * card.
 *
 * The most important resource in hardware are its transmit and receive queue
 * pairs (i40e_trqpair_t). These should be thought of as rings in GLDv3
 * parlance. There are a set number of these on each device; however, they are
 * statically partitioned among all of the different physical functions.
 *
 * 'Fortville' (the code name for this device family) is basically a switch. To
 * map MAC addresses and other things to queues, we end up having to create
 * Virtual Station Interfaces (VSIs) and establish forwarding rules that direct
 * traffic to a queue. A VSI owns a collection of queues and has a series of
 * forwarding rules that point to it. One way to think of this is to treat it
 * like MAC does a VNIC. When MAC refers to a group, a collection of rings and
 * classification resources, that is a VSI in i40e.
 *
 * The sets of VSIs is shared across the entire device, though there may be some
 * amount that are reserved to each PF. Because the GLDv3 does not let us change
 * the number of groups dynamically, we instead statically divide this amount
 * evenly between all the functions that exist. In addition, we have the same
 * problem with the mac address forwarding rules. There are a static number that
 * exist shared across all the functions.
 *
 * To handle both of these resources, what we end up doing is going through and
 * determining which functions belong to the same device. Nominally one might do
 * this by having a nexus driver; however, a prime requirement for a nexus
 * driver is identifying the various children and activating them. While it is
 * possible to get this information from NVRAM, we would end up duplicating a
 * lot of the PCI enumeration logic. Really, at the end of the day, the device
 * doesn't give us the traditional identification properties we want from a
 * nexus driver.
 *
 * Instead, we rely on some properties that are guaranteed to be unique. While
 * it might be tempting to leverage the PBA or serial number of the device from
 * NVRAM, there is nothing that says that two devices can't be mis-programmed to
 * have the same values in NVRAM. Instead, we uniquely identify a group of
 * functions based on their parent in the /devices tree, their PCI bus and PCI
 * function identifiers. Using either on their own may not be sufficient.
 *
 * For each unique PCI device that we encounter, we'll create a i40e_device_t.
 * From there, because we don't have a good way to tell the GLDv3 about sharing
 * resources between everything, we'll end up just dividing the resources
 * evenly between all of the functions. Longer term, if we don't have to declare
 * to the GLDv3 that these resources are shared, then we'll maintain a pool and
 * have each PF allocate from the pool in the device, thus if only two of four
 * ports are being used, for example, then all of the resources can still be
 * used.
 *
 * -------------------------------------------
 * Transmit and Receive Queue Pair Allocations
 * -------------------------------------------
 *
 * NVRAM ends up assigning each PF its own share of the transmit and receive LAN
 * queue pairs, we have no way of modifying it, only observing it. From there,
 * it's up to us to map these queues to VSIs and VFs. Since we don't support any
 * VFs at this time, we only focus on assignments to VSIs.
 *
 * At the moment, we used a static mapping of transmit/receive queue pairs to a
 * given VSI (eg. rings to a group). Though in the fullness of time, we want to
 * make this something which is fully dynamic and take advantage of documented,
 * but not yet available functionality for adding filters based on VXLAN and
 * other encapsulation technologies.
 *
 * -------------------------------------
 * Broadcast, Multicast, and Promiscuous
 * -------------------------------------
 *
 * As part of the GLDv3, we need to make sure that we can handle receiving
 * broadcast and multicast traffic. As well as enabling promiscuous mode when
 * requested. GLDv3 requires that all broadcast and multicast traffic be
 * retrieved by the default group, eg. the first one. This is the same thing as
 * the default VSI.
 *
 * To receieve broadcast traffic, we enable it through the admin queue, rather
 * than use one of our filters for it. For multicast traffic, we reserve a
 * certain number of the hash filters and assign them to a given PF. When we
 * exceed those, we then switch to using promiscuous mode for multicast traffic.
 *
 * More specifically, once we exceed the number of filters (indicated because
 * the i40e_t`i40e_resources.ifr_nmcastfilt ==
 * i40e_t`i40e_resources.ifr_nmcastfilt_used), we then instead need to toggle
 * promiscuous mode. If promiscuous mode is toggled then we keep track of the
 * number of MACs added to it by incrementing i40e_t`i40e_mcast_promisc_count.
 * That will stay enabled until that count reaches zero indicating that we have
 * only added multicast addresses that we have a corresponding entry for.
 *
 * Because MAC itself wants to toggle promiscuous mode, which includes both
 * unicast and multicast traffic, we go through and keep track of that
 * ourselves. That is maintained through the use of the i40e_t`i40e_promisc_on
 * member.
 *
 * --------------
 * VSI Management
 * --------------
 *
 * At this time, we currently only support a single MAC group, and thus a single
 * VSI. This VSI is considered the default VSI and should be the only one that
 * exists after a reset. Currently it is stored as the member
 * i40e_t`i40e_vsi_id. While this works for the moment and for an initial
 * driver, it's not sufficient for the longer-term path of the driver. Instead,
 * we'll want to actually have a unique i40e_vsi_t structure which is used
 * everywhere. Note that this means that every place that uses the
 * i40e_t`i40e_vsi_id will need to be refactored.
 *
 * ----------------
 * Structure Layout
 * ----------------
 *
 * The following images relates the core data structures together. The primary
 * structure in the system is the i40e_t. It itself contains multiple rings,
 * i40e_trqpair_t's which contain the various transmit and receive data. The
 * receive data is stored outside of the i40e_trqpair_t and instead in the
 * i40e_rx_data_t. The i40e_t has a corresponding i40e_device_t which keeps
 * track of per-physical device state. Finally, for every active descriptor,
 * there is a corresponding control block, which is where the
 * i40e_rx_control_block_t and the i40e_tx_control_block_t come from.
 *
 *   +-----------------------+       +-----------------------+
 *   | Global i40e_t list    |       | Global Device list    |
 *   |                       |    +--|                       |
 *   | i40e_glist            |    |  | i40e_dlist            |
 *   +-----------------------+    |  +-----------------------+
 *       |                        v
 *       |      +------------------------+      +-----------------------+
 *       |      | Device-wide Structure  |----->| Device-wide Structure |--> ...
 *       |      | i40e_device_t          |      | i40e_device_t         |
 *       |      |                        |      +-----------------------+
 *       |      | dev_info_t *     ------+--> Parent in devices tree.
 *       |      | uint_t           ------+--> PCI bus number
 *       |      | uint_t           ------+--> PCI device number
 *       |      | uint_t           ------+--> Number of functions
 *       |      | i40e_switch_rsrcs_t ---+--> Captured total switch resources
 *       |      | list_t           ------+-------------+
 *       |      +------------------------+             |
 *       |                           ^                 |
 *       |                           +--------+        |
 *       |                                    |        v
 *       |  +---------------------------+     |   +-------------------+
 *       +->| GLDv3 Device, per PF      |-----|-->| GLDv3 Device (PF) |--> ...
 *          | i40e_t                    |     |   | i40e_t            |
 *          | **Primary Structure**     |     |   +-------------------+
 *          |                           |     |
 *          | i40e_device_t *         --+-----+
 *          | i40e_state_t            --+---> Device State
 *          | i40e_hw_t               --+---> Intel common code structure
 *          | mac_handle_t            --+---> GLDv3 handle to MAC
 *          | ddi_periodic_t          --+---> Link activity timer
 *          | int (vsi_id)            --+---> VSI ID, main identifier
 *          | i40e_func_rsrc_t        --+---> Available hardware resources
 *          | i40e_switch_rsrc_t *    --+---> Switch resource snapshot
 *          | i40e_sdu                --+---> Current MTU
 *          | i40e_frame_max          --+---> Current HW frame size
 *          | i40e_uaddr_t *          --+---> Array of assigned unicast MACs
 *          | i40e_maddr_t *          --+---> Array of assigned multicast MACs
 *          | i40e_mcast_promisccount --+---> Active multicast state
 *          | i40e_promisc_on         --+---> Current promiscuous mode state
 *          | int                     --+---> Number of transmit/receive pairs
 *          | kstat_t *               --+---> PF kstats
 *          | kstat_t *               --+---> VSI kstats
 *          | i40e_pf_stats_t         --+---> PF kstat backing data
 *          | i40e_vsi_stats_t        --+---> VSI kstat backing data
 *          | i40e_trqpair_t *        --+---------+
 *          +---------------------------+         |
 *                                                |
 *                                                v
 *  +-------------------------------+       +-----------------------------+
 *  | Transmit/Receive Queue Pair   |-------| Transmit/Receive Queue Pair |->...
 *  | i40e_trqpair_t                |       | i40e_trqpair_t              |
 *  + Ring Data Structure           |       +-----------------------------+
 *  |                               |
 *  | mac_ring_handle_t             +--> MAC RX ring handle
 *  | mac_ring_handle_t             +--> MAC TX ring handle
 *  | i40e_rxq_stat_t             --+--> RX Queue stats
 *  | i40e_txq_stat_t             --+--> TX Queue stats
 *  | uint32_t (tx ring size)       +--> TX Ring Size
 *  | uint32_t (tx free list size)  +--> TX Free List Size
 *  | i40e_dma_buffer_t     --------+--> TX Descriptor ring DMA
 *  | i40e_tx_desc_t *      --------+--> TX descriptor ring
 *  | volatile unt32_t *            +--> TX Write back head
 *  | uint32_t               -------+--> TX ring head
 *  | uint32_t               -------+--> TX ring tail
 *  | uint32_t               -------+--> Num TX desc free
 *  | i40e_tx_control_block_t *   --+--> TX control block array  ---+
 *  | i40e_tx_control_block_t **  --+--> TCB work list          ----+
 *  | i40e_tx_control_block_t **  --+--> TCB free list           ---+
 *  | uint32_t               -------+--> Free TCB count             |
 *  | i40e_rx_data_t *       -------+--+                            v
 *  +-------------------------------+  |          +---------------------------+
 *                                     |          | Per-TX Frame Metadata     |
 *                                     |          | i40e_tx_control_block_t   |
 *                +--------------------+          |                           |
 *                |           mblk to transmit <--+---      mblk_t *          |
 *                |           type of transmit <--+---      i40e_tx_type_t    |
 *                |              TX DMA handle <--+---      ddi_dma_handle_t  |
 *                v              TX DMA buffer <--+---      i40e_dma_buffer_t |
 *    +------------------------------+            +---------------------------+
 *    | Core Receive Data            |
 *    | i40e_rx_data_t               |
 *    |                              |
 *    | i40e_dma_buffer_t          --+--> RX descriptor DMA Data
 *    | i40e_rx_desc_t             --+--> RX descriptor ring
 *    | uint32_t                   --+--> Next free desc.
 *    | i40e_rx_control_block_t *  --+--> RX Control Block Array  ---+
 *    | i40e_rx_control_block_t ** --+--> RCB work list           ---+
 *    | i40e_rx_control_block_t ** --+--> RCB free list           ---+
 *    +------------------------------+                               |
 *                ^                                                  |
 *                |     +---------------------------+                |
 *                |     | Per-RX Frame Metadata     |<---------------+
 *                |     | i40e_rx_control_block_t   |
 *                |     |                           |
 *                |     | mblk_t *              ----+--> Received mblk_t data
 *                |     | uint32_t              ----+--> Reference count
 *                |     | i40e_dma_buffer_t     ----+--> Receive data DMA info
 *                |     | frtn_t                ----+--> mblk free function info
 *                +-----+-- i40e_rx_data_t *        |
 *                      +---------------------------+
 *
 * -------------
 * Lock Ordering
 * -------------
 *
 * In order to ensure that we don't deadlock, the following represents the
 * lock order being used. When grabbing locks, follow the following order. Lower
 * numbers are more important. Thus, the i40e_glock which is number 0, must be
 * taken before any other locks in the driver. On the other hand, the
 * i40e_t`i40e_stat_lock, has the highest number because it's the least
 * important lock. Note, that just because one lock is higher than another does
 * not mean that all intermediary locks are required.
 *
 * 0) i40e_glock
 * 1) i40e_t`i40e_general_lock
 *
 * 2) i40e_trqpair_t`itrq_rx_lock
 * 3) i40e_trqpair_t`itrq_tx_lock
 * 4) i40e_t`i40e_rx_pending_lock
 * 5) i40e_trqpair_t`itrq_tcb_lock
 *
 * 6) i40e_t`i40e_stat_lock
 *
 * Rules and expectations:
 *
 * 1) A thread holding locks belong to one PF should not hold locks belonging to
 * a second. If for some reason this becomes necessary, locks should be grabbed
 * based on the list order in the i40e_device_t, which implies that the
 * i40e_glock is held.
 *
 * 2) When grabbing locks between multiple transmit and receive queues, the
 * locks for the lowest number transmit/receive queue should be grabbed first.
 *
 * 3) When grabbing both the transmit and receive lock for a given queue, always
 * grab i40e_trqpair_t`itrq_rx_lock before the i40e_trqpair_t`itrq_tx_lock.
 *
 * 4) The following pairs of locks are not expected to be held at the same time:
 *
 * o i40e_t`i40e_rx_pending_lock and i40e_trqpair_t`itrq_tcb_lock
 *
 * -----------
 * Future Work
 * -----------
 *
 * At the moment the i40e_t driver is rather bare bones, allowing us to start
 * getting data flowing and folks using it while we develop additional features.
 * While bugs have been filed to cover this future work, the following gives an
 * overview of expected work:
 *
 *  o TSO support
 *  o Multiple group support
 *  o DMA binding and breaking up the locking in ring recycling.
 *  o Enhanced detection of device errors
 *  o Participation in IRM
 *  o FMA device reset
 *  o Stall detection, temperature error detection, etc.
 *  o More dynamic resource pools
 */

#include "i40e_sw.h"

static char i40e_ident[] = "Intel 10/40Gb Ethernet v1.0.1";

/*
 * The i40e_glock primarily protects the lists below and the i40e_device_t
 * structures.
 */
static kmutex_t i40e_glock;
static list_t i40e_glist;
static list_t i40e_dlist;

/*
 * Access attributes for register mapping.
 */
static ddi_device_acc_attr_t i40e_regs_acc_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

/*
 * Logging function for this driver.
 */
static void
i40e_dev_err(i40e_t *i40e, int level, boolean_t console, const char *fmt,
    va_list ap)
{
	char buf[1024];

	(void) vsnprintf(buf, sizeof (buf), fmt, ap);

	if (i40e == NULL) {
		cmn_err(level, (console) ? "%s: %s" : "!%s: %s",
		    I40E_MODULE_NAME, buf);
	} else {
		dev_err(i40e->i40e_dip, level, (console) ? "%s" : "!%s",
		    buf);
	}
}

/*
 * Because there's the stupid trailing-comma problem with the C preprocessor
 * and variable arguments, I need to instantiate these.	 Pardon the redundant
 * code.
 */
/*PRINTFLIKE2*/
void
i40e_error(i40e_t *i40e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i40e_dev_err(i40e, CE_WARN, B_FALSE, fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE2*/
void
i40e_log(i40e_t *i40e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i40e_dev_err(i40e, CE_NOTE, B_FALSE, fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE2*/
void
i40e_notice(i40e_t *i40e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i40e_dev_err(i40e, CE_NOTE, B_TRUE, fmt, ap);
	va_end(ap);
}

/*
 * Various parts of the driver need to know if the controller is from the X722
 * family, which has a few additional capabilities and different programming
 * means. We don't consider virtual functions as part of this as they are quite
 * different and will require substantially more work.
 */
static boolean_t
i40e_is_x722(i40e_t *i40e)
{
	return (i40e->i40e_hw_space.mac.type == I40E_MAC_X722);
}

static void
i40e_device_rele(i40e_t *i40e)
{
	i40e_device_t *idp = i40e->i40e_device;

	if (idp == NULL)
		return;

	mutex_enter(&i40e_glock);
	VERIFY(idp->id_nreg > 0);
	list_remove(&idp->id_i40e_list, i40e);
	idp->id_nreg--;
	if (idp->id_nreg == 0) {
		list_remove(&i40e_dlist, idp);
		list_destroy(&idp->id_i40e_list);
		kmem_free(idp->id_rsrcs, sizeof (i40e_switch_rsrc_t) *
		    idp->id_rsrcs_alloc);
		kmem_free(idp, sizeof (i40e_device_t));
	}
	i40e->i40e_device = NULL;
	mutex_exit(&i40e_glock);
}

static i40e_device_t *
i40e_device_find(i40e_t *i40e, dev_info_t *parent, uint_t bus, uint_t device)
{
	i40e_device_t *idp;
	mutex_enter(&i40e_glock);
	for (idp = list_head(&i40e_dlist); idp != NULL;
	    idp = list_next(&i40e_dlist, idp)) {
		if (idp->id_parent == parent && idp->id_pci_bus == bus &&
		    idp->id_pci_device == device) {
			break;
		}
	}

	if (idp != NULL) {
		VERIFY(idp->id_nreg < idp->id_nfuncs);
		idp->id_nreg++;
	} else {
		i40e_hw_t *hw = &i40e->i40e_hw_space;
		ASSERT(hw->num_ports > 0);
		ASSERT(hw->num_partitions > 0);

		/*
		 * The Intel common code doesn't exactly keep the number of PCI
		 * functions. But it calculates it during discovery of
		 * partitions and ports. So what we do is undo the calculation
		 * that it does originally, as functions are evenly spread
		 * across ports in the rare case of partitions.
		 */
		idp = kmem_alloc(sizeof (i40e_device_t), KM_SLEEP);
		idp->id_parent = parent;
		idp->id_pci_bus = bus;
		idp->id_pci_device = device;
		idp->id_nfuncs = hw->num_ports * hw->num_partitions;
		idp->id_nreg = 1;
		idp->id_rsrcs_alloc = i40e->i40e_switch_rsrc_alloc;
		idp->id_rsrcs_act = i40e->i40e_switch_rsrc_actual;
		idp->id_rsrcs = kmem_alloc(sizeof (i40e_switch_rsrc_t) *
		    idp->id_rsrcs_alloc, KM_SLEEP);
		bcopy(i40e->i40e_switch_rsrcs, idp->id_rsrcs,
		    sizeof (i40e_switch_rsrc_t) * idp->id_rsrcs_alloc);
		list_create(&idp->id_i40e_list, sizeof (i40e_t),
		    offsetof(i40e_t, i40e_dlink));

		list_insert_tail(&i40e_dlist, idp);
	}

	list_insert_tail(&idp->id_i40e_list, i40e);
	mutex_exit(&i40e_glock);

	return (idp);
}

static void
i40e_link_state_set(i40e_t *i40e, link_state_t state)
{
	if (i40e->i40e_link_state == state)
		return;

	i40e->i40e_link_state = state;
	mac_link_update(i40e->i40e_mac_hdl, i40e->i40e_link_state);
}

/*
 * This is a basic link check routine. Mostly we're using this just to see
 * if we can get any accurate information about the state of the link being
 * up or down, as well as updating the link state, speed, etc. information.
 */
void
i40e_link_check(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	boolean_t ls;
	int ret;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	hw->phy.get_link_info = B_TRUE;
	if ((ret = i40e_get_link_status(hw, &ls)) != I40E_SUCCESS) {
		i40e->i40e_s_link_status_errs++;
		i40e->i40e_s_link_status_lasterr = ret;
		return;
	}

	/*
	 * Firmware abstracts all of the mac and phy information for us, so we
	 * can use i40e_get_link_status to determine the current state.
	 */
	if (ls == B_TRUE) {
		enum i40e_aq_link_speed speed;

		speed = i40e_get_link_speed(hw);

		/*
		 * Translate from an i40e value to a value in Mbits/s.
		 */
		switch (speed) {
		case I40E_LINK_SPEED_100MB:
			i40e->i40e_link_speed = 100;
			break;
		case I40E_LINK_SPEED_1GB:
			i40e->i40e_link_speed = 1000;
			break;
		case I40E_LINK_SPEED_10GB:
			i40e->i40e_link_speed = 10000;
			break;
		case I40E_LINK_SPEED_20GB:
			i40e->i40e_link_speed = 20000;
			break;
		case I40E_LINK_SPEED_40GB:
			i40e->i40e_link_speed = 40000;
			break;
		case I40E_LINK_SPEED_25GB:
			i40e->i40e_link_speed = 25000;
			break;
		default:
			i40e->i40e_link_speed = 0;
			break;
		}

		/*
		 * At this time, hardware does not support half-duplex
		 * operation, hence why we don't ask the hardware about our
		 * current speed.
		 */
		i40e->i40e_link_duplex = LINK_DUPLEX_FULL;
		i40e_link_state_set(i40e, LINK_STATE_UP);
	} else {
		i40e->i40e_link_speed = 0;
		i40e->i40e_link_duplex = 0;
		i40e_link_state_set(i40e, LINK_STATE_DOWN);
	}
}

static void
i40e_rem_intrs(i40e_t *i40e)
{
	int i, rc;

	for (i = 0; i < i40e->i40e_intr_count; i++) {
		rc = ddi_intr_free(i40e->i40e_intr_handles[i]);
		if (rc != DDI_SUCCESS) {
			i40e_log(i40e, "failed to free interrupt %d: %d",
			    i, rc);
		}
	}

	kmem_free(i40e->i40e_intr_handles, i40e->i40e_intr_size);
	i40e->i40e_intr_handles = NULL;
}

static void
i40e_rem_intr_handlers(i40e_t *i40e)
{
	int i, rc;

	for (i = 0; i < i40e->i40e_intr_count; i++) {
		rc = ddi_intr_remove_handler(i40e->i40e_intr_handles[i]);
		if (rc != DDI_SUCCESS) {
			i40e_log(i40e, "failed to remove interrupt %d: %d",
			    i, rc);
		}
	}
}

/*
 * illumos Fault Management Architecture (FMA) support.
 */

int
i40e_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

int
i40e_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * Fault service error handling callback function.
 */
/* ARGSUSED */
static int
i40e_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
i40e_fm_init(i40e_t *i40e)
{
	ddi_iblock_cookie_t iblk;

	i40e->i40e_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    i40e->i40e_dip, DDI_PROP_DONTPASS, "fm_capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	if (i40e->i40e_fm_capabilities < 0) {
		i40e->i40e_fm_capabilities = 0;
	} else if (i40e->i40e_fm_capabilities > 0xf) {
		i40e->i40e_fm_capabilities = DDI_FM_EREPORT_CAPABLE |
		    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
		    DDI_FM_ERRCB_CAPABLE;
	}

	/*
	 * Only register with IO Fault Services if we have some capability
	 */
	if (i40e->i40e_fm_capabilities & DDI_FM_ACCCHK_CAPABLE) {
		i40e_regs_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		i40e_regs_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if (i40e->i40e_fm_capabilities) {
		ddi_fm_init(i40e->i40e_dip, &i40e->i40e_fm_capabilities, &iblk);

		if (DDI_FM_EREPORT_CAP(i40e->i40e_fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(i40e->i40e_fm_capabilities)) {
			pci_ereport_setup(i40e->i40e_dip);
		}

		if (DDI_FM_ERRCB_CAP(i40e->i40e_fm_capabilities)) {
			ddi_fm_handler_register(i40e->i40e_dip,
			    i40e_fm_error_cb, (void*)i40e);
		}
	}

	if (i40e->i40e_fm_capabilities & DDI_FM_DMACHK_CAPABLE) {
		i40e_init_dma_attrs(i40e, B_TRUE);
	} else {
		i40e_init_dma_attrs(i40e, B_FALSE);
	}
}

static void
i40e_fm_fini(i40e_t *i40e)
{
	if (i40e->i40e_fm_capabilities) {

		if (DDI_FM_EREPORT_CAP(i40e->i40e_fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(i40e->i40e_fm_capabilities))
			pci_ereport_teardown(i40e->i40e_dip);

		if (DDI_FM_ERRCB_CAP(i40e->i40e_fm_capabilities))
			ddi_fm_handler_unregister(i40e->i40e_dip);

		ddi_fm_fini(i40e->i40e_dip);
	}
}

void
i40e_fm_ereport(i40e_t *i40e, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(i40e->i40e_fm_capabilities)) {
		ddi_fm_ereport_post(i40e->i40e_dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}

/*
 * Here we're trying to get the ID of the default VSI. In general, when we come
 * through and look at this shortly after attach, we expect there to only be a
 * single element present, which is the default VSI. Importantly, each PF seems
 * to not see any other devices, in part because of the simple switch mode that
 * we're using. If for some reason, we see more artifact, we'll need to revisit
 * what we're doing here.
 */
static int
i40e_get_vsi_id(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	struct i40e_aqc_get_switch_config_resp *sw_config;
	uint8_t aq_buf[I40E_AQ_LARGE_BUF];
	uint16_t next = 0;
	int rc;

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	sw_config = (struct i40e_aqc_get_switch_config_resp *)aq_buf;
	rc = i40e_aq_get_switch_config(hw, sw_config, sizeof (aq_buf), &next,
	    NULL);
	if (rc != I40E_SUCCESS) {
		i40e_error(i40e, "i40e_aq_get_switch_config() failed %d: %d",
		    rc, hw->aq.asq_last_status);
		return (-1);
	}

	if (LE_16(sw_config->header.num_reported) != 1) {
		i40e_error(i40e, "encountered multiple (%d) switching units "
		    "during attach, not proceeding",
		    LE_16(sw_config->header.num_reported));
		return (-1);
	}

	return (sw_config->element[0].seid);
}

/*
 * We need to fill the i40e_hw_t structure with the capabilities of this PF. We
 * must also provide the memory for it; however, we don't need to keep it around
 * to the call to the common code. It takes it and parses it into an internal
 * structure.
 */
static boolean_t
i40e_get_hw_capabilities(i40e_t *i40e, i40e_hw_t *hw)
{
	struct i40e_aqc_list_capabilities_element_resp *buf;
	int rc;
	size_t len;
	uint16_t needed;
	int nelems = I40E_HW_CAP_DEFAULT;

	len = nelems * sizeof (*buf);

	for (;;) {
		ASSERT(len > 0);
		buf = kmem_alloc(len, KM_SLEEP);
		rc = i40e_aq_discover_capabilities(hw, buf, len,
		    &needed, i40e_aqc_opc_list_func_capabilities, NULL);
		kmem_free(buf, len);

		if (hw->aq.asq_last_status == I40E_AQ_RC_ENOMEM &&
		    nelems == I40E_HW_CAP_DEFAULT) {
			if (nelems == needed) {
				i40e_error(i40e, "Capability discovery failed "
				    "due to byzantine common code");
				return (B_FALSE);
			}
			len = needed;
			continue;
		} else if (rc != I40E_SUCCESS ||
		    hw->aq.asq_last_status != I40E_AQ_RC_OK) {
			i40e_error(i40e, "Capability discovery failed: %d", rc);
			return (B_FALSE);
		}

		break;
	}

	return (B_TRUE);
}

/*
 * Obtain the switch's capabilities as seen by this PF and keep it around for
 * our later use.
 */
static boolean_t
i40e_get_switch_resources(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint8_t cnt = 2;
	uint8_t act;
	size_t size;
	i40e_switch_rsrc_t *buf;

	for (;;) {
		enum i40e_status_code ret;
		size = cnt * sizeof (i40e_switch_rsrc_t);
		ASSERT(size > 0);
		if (size > UINT16_MAX)
			return (B_FALSE);
		buf = kmem_alloc(size, KM_SLEEP);

		ret = i40e_aq_get_switch_resource_alloc(hw, &act, buf,
		    cnt, NULL);
		if (ret == I40E_ERR_ADMIN_QUEUE_ERROR &&
		    hw->aq.asq_last_status == I40E_AQ_RC_EINVAL) {
			kmem_free(buf, size);
			cnt += I40E_SWITCH_CAP_DEFAULT;
			continue;
		} else if (ret != I40E_SUCCESS) {
			kmem_free(buf, size);
			i40e_error(i40e,
			    "failed to retrieve switch statistics: %d", ret);
			return (B_FALSE);
		}

		break;
	}

	i40e->i40e_switch_rsrc_alloc = cnt;
	i40e->i40e_switch_rsrc_actual = act;
	i40e->i40e_switch_rsrcs = buf;

	return (B_TRUE);
}

static void
i40e_cleanup_resources(i40e_t *i40e)
{
	if (i40e->i40e_uaddrs != NULL) {
		kmem_free(i40e->i40e_uaddrs, sizeof (i40e_uaddr_t) *
		    i40e->i40e_resources.ifr_nmacfilt);
		i40e->i40e_uaddrs = NULL;
	}

	if (i40e->i40e_maddrs != NULL) {
		kmem_free(i40e->i40e_maddrs, sizeof (i40e_maddr_t) *
		    i40e->i40e_resources.ifr_nmcastfilt);
		i40e->i40e_maddrs = NULL;
	}

	if (i40e->i40e_switch_rsrcs != NULL) {
		size_t sz = sizeof (i40e_switch_rsrc_t) *
		    i40e->i40e_switch_rsrc_alloc;
		ASSERT(sz > 0);
		kmem_free(i40e->i40e_switch_rsrcs, sz);
		i40e->i40e_switch_rsrcs = NULL;
	}

	if (i40e->i40e_device != NULL)
		i40e_device_rele(i40e);
}

static boolean_t
i40e_get_available_resources(i40e_t *i40e)
{
	dev_info_t *parent;
	uint16_t bus, device, func;
	uint_t nregs;
	int *regs, i;
	i40e_device_t *idp;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	parent = ddi_get_parent(i40e->i40e_dip);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, i40e->i40e_dip, 0, "reg",
	    &regs, &nregs) != DDI_PROP_SUCCESS) {
		return (B_FALSE);
	}

	if (nregs < 1) {
		ddi_prop_free(regs);
		return (B_FALSE);
	}

	bus = PCI_REG_BUS_G(regs[0]);
	device = PCI_REG_DEV_G(regs[0]);
	func = PCI_REG_FUNC_G(regs[0]);
	ddi_prop_free(regs);

	i40e->i40e_hw_space.bus.func = func;
	i40e->i40e_hw_space.bus.device = device;

	if (i40e_get_switch_resources(i40e) == B_FALSE) {
		return (B_FALSE);
	}

	/*
	 * To calculate the total amount of a resource we have available, we
	 * need to add how many our i40e_t thinks it has guaranteed, if any, and
	 * then we need to go through and divide the number of available on the
	 * device, which was snapshotted before anyone should have allocated
	 * anything, and use that to derive how many are available from the
	 * pool. Longer term, we may want to turn this into something that's
	 * more of a pool-like resource that everything can share (though that
	 * may require some more assistance from MAC).
	 *
	 * Though for transmit and receive queue pairs, we just have to ask
	 * firmware instead.
	 */
	idp = i40e_device_find(i40e, parent, bus, device);
	i40e->i40e_device = idp;
	i40e->i40e_resources.ifr_nvsis = 0;
	i40e->i40e_resources.ifr_nvsis_used = 0;
	i40e->i40e_resources.ifr_nmacfilt = 0;
	i40e->i40e_resources.ifr_nmacfilt_used = 0;
	i40e->i40e_resources.ifr_nmcastfilt = 0;
	i40e->i40e_resources.ifr_nmcastfilt_used = 0;

	for (i = 0; i < i40e->i40e_switch_rsrc_actual; i++) {
		i40e_switch_rsrc_t *srp = &i40e->i40e_switch_rsrcs[i];

		switch (srp->resource_type) {
		case I40E_AQ_RESOURCE_TYPE_VSI:
			i40e->i40e_resources.ifr_nvsis +=
			    LE_16(srp->guaranteed);
			i40e->i40e_resources.ifr_nvsis_used = LE_16(srp->used);
			break;
		case I40E_AQ_RESOURCE_TYPE_MACADDR:
			i40e->i40e_resources.ifr_nmacfilt +=
			    LE_16(srp->guaranteed);
			i40e->i40e_resources.ifr_nmacfilt_used =
			    LE_16(srp->used);
			break;
		case I40E_AQ_RESOURCE_TYPE_MULTICAST_HASH:
			i40e->i40e_resources.ifr_nmcastfilt +=
			    LE_16(srp->guaranteed);
			i40e->i40e_resources.ifr_nmcastfilt_used =
			    LE_16(srp->used);
			break;
		default:
			break;
		}
	}

	for (i = 0; i < idp->id_rsrcs_act; i++) {
		i40e_switch_rsrc_t *srp = &i40e->i40e_switch_rsrcs[i];
		switch (srp->resource_type) {
		case I40E_AQ_RESOURCE_TYPE_VSI:
			i40e->i40e_resources.ifr_nvsis +=
			    LE_16(srp->total_unalloced) / idp->id_nfuncs;
			break;
		case I40E_AQ_RESOURCE_TYPE_MACADDR:
			i40e->i40e_resources.ifr_nmacfilt +=
			    LE_16(srp->total_unalloced) / idp->id_nfuncs;
			break;
		case I40E_AQ_RESOURCE_TYPE_MULTICAST_HASH:
			i40e->i40e_resources.ifr_nmcastfilt +=
			    LE_16(srp->total_unalloced) / idp->id_nfuncs;
		default:
			break;
		}
	}

	i40e->i40e_resources.ifr_nrx_queue = hw->func_caps.num_rx_qp;
	i40e->i40e_resources.ifr_ntx_queue = hw->func_caps.num_tx_qp;

	i40e->i40e_uaddrs = kmem_zalloc(sizeof (i40e_uaddr_t) *
	    i40e->i40e_resources.ifr_nmacfilt, KM_SLEEP);
	i40e->i40e_maddrs = kmem_zalloc(sizeof (i40e_maddr_t) *
	    i40e->i40e_resources.ifr_nmcastfilt, KM_SLEEP);

	/*
	 * Initialize these as multicast addresses to indicate it's invalid for
	 * sanity purposes. Think of it like 0xdeadbeef.
	 */
	for (i = 0; i < i40e->i40e_resources.ifr_nmacfilt; i++)
		i40e->i40e_uaddrs[i].iua_mac[0] = 0x01;

	return (B_TRUE);
}

static boolean_t
i40e_enable_interrupts(i40e_t *i40e)
{
	int i, rc;

	if (i40e->i40e_intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_enable(i40e->i40e_intr_handles,
		    i40e->i40e_intr_count);
		if (rc != DDI_SUCCESS) {
			i40e_error(i40e, "Interrupt block-enable failed: %d",
			    rc);
			return (B_FALSE);
		}
	} else {
		for (i = 0; i < i40e->i40e_intr_count; i++) {
			rc = ddi_intr_enable(i40e->i40e_intr_handles[i]);
			if (rc != DDI_SUCCESS) {
				i40e_error(i40e,
				    "Failed to enable interrupt %d: %d", i, rc);
				while (--i >= 0) {
					(void) ddi_intr_disable(
					    i40e->i40e_intr_handles[i]);
				}
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

static boolean_t
i40e_disable_interrupts(i40e_t *i40e)
{
	int i, rc;

	if (i40e->i40e_intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_disable(i40e->i40e_intr_handles,
		    i40e->i40e_intr_count);
		if (rc != DDI_SUCCESS) {
			i40e_error(i40e,
			    "Interrupt block-disabled failed: %d", rc);
			return (B_FALSE);
		}
	} else {
		for (i = 0; i < i40e->i40e_intr_count; i++) {
			rc = ddi_intr_disable(i40e->i40e_intr_handles[i]);
			if (rc != DDI_SUCCESS) {
				i40e_error(i40e,
				    "Failed to disable interrupt %d: %d",
				    i, rc);
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

/*
 * Free receive & transmit rings.
 */
static void
i40e_free_trqpairs(i40e_t *i40e)
{
	int i;
	i40e_trqpair_t *itrq;

	if (i40e->i40e_trqpairs != NULL) {
		for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
			itrq = &i40e->i40e_trqpairs[i];
			mutex_destroy(&itrq->itrq_rx_lock);
			mutex_destroy(&itrq->itrq_tx_lock);
			mutex_destroy(&itrq->itrq_tcb_lock);

			/*
			 * Should have already been cleaned up by start/stop,
			 * etc.
			 */
			ASSERT(itrq->itrq_txkstat == NULL);
			ASSERT(itrq->itrq_rxkstat == NULL);
		}

		kmem_free(i40e->i40e_trqpairs,
		    sizeof (i40e_trqpair_t) * i40e->i40e_num_trqpairs);
		i40e->i40e_trqpairs = NULL;
	}

	cv_destroy(&i40e->i40e_rx_pending_cv);
	mutex_destroy(&i40e->i40e_rx_pending_lock);
	mutex_destroy(&i40e->i40e_general_lock);
}

/*
 * Allocate transmit and receive rings, as well as other data structures that we
 * need.
 */
static boolean_t
i40e_alloc_trqpairs(i40e_t *i40e)
{
	int i;
	void *mutexpri = DDI_INTR_PRI(i40e->i40e_intr_pri);

	/*
	 * Now that we have the priority for the interrupts, initialize
	 * all relevant locks.
	 */
	mutex_init(&i40e->i40e_general_lock, NULL, MUTEX_DRIVER, mutexpri);
	mutex_init(&i40e->i40e_rx_pending_lock, NULL, MUTEX_DRIVER, mutexpri);
	cv_init(&i40e->i40e_rx_pending_cv, NULL, CV_DRIVER, NULL);

	i40e->i40e_trqpairs = kmem_zalloc(sizeof (i40e_trqpair_t) *
	    i40e->i40e_num_trqpairs, KM_SLEEP);
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[i];

		itrq->itrq_i40e = i40e;
		mutex_init(&itrq->itrq_rx_lock, NULL, MUTEX_DRIVER, mutexpri);
		mutex_init(&itrq->itrq_tx_lock, NULL, MUTEX_DRIVER, mutexpri);
		mutex_init(&itrq->itrq_tcb_lock, NULL, MUTEX_DRIVER, mutexpri);
		itrq->itrq_index = i;
	}

	return (B_TRUE);
}



/*
 * Unless a .conf file already overrode i40e_t structure values, they will
 * be 0, and need to be set in conjunction with the now-available HW report.
 *
 * However, at the moment, we cap all of these resources as we only support a
 * single receive ring and a single group.
 */
/* ARGSUSED */
static void
i40e_hw_to_instance(i40e_t *i40e, i40e_hw_t *hw)
{
	if (i40e->i40e_num_trqpairs == 0) {
		i40e->i40e_num_trqpairs = I40E_TRQPAIR_MAX;
	}

	if (i40e->i40e_num_rx_groups == 0) {
		i40e->i40e_num_rx_groups = I40E_GROUP_MAX;
	}
}

/*
 * Free any resources required by, or setup by, the Intel common code.
 */
static void
i40e_common_code_fini(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	int rc;

	rc = i40e_shutdown_lan_hmc(hw);
	if (rc != I40E_SUCCESS)
		i40e_error(i40e, "failed to shutdown LAN hmc: %d", rc);

	rc = i40e_shutdown_adminq(hw);
	if (rc != I40E_SUCCESS)
		i40e_error(i40e, "failed to shutdown admin queue: %d", rc);
}

/*
 * Initialize and call Intel common-code routines, includes some setup
 * the common code expects from the driver.  Also prints on failure, so
 * the caller doesn't have to.
 */
static boolean_t
i40e_common_code_init(i40e_t *i40e, i40e_hw_t *hw)
{
	int rc;

	i40e_clear_hw(hw);
	rc = i40e_pf_reset(hw);
	if (rc != 0) {
		i40e_error(i40e, "failed to reset hardware: %d", rc);
		i40e_fm_ereport(i40e, DDI_FM_DEVICE_NO_RESPONSE);
		return (B_FALSE);
	}

	rc = i40e_init_shared_code(hw);
	if (rc != 0) {
		i40e_error(i40e, "failed to initialize i40e core: %d", rc);
		return (B_FALSE);
	}

	hw->aq.num_arq_entries = I40E_DEF_ADMINQ_SIZE;
	hw->aq.num_asq_entries =  I40E_DEF_ADMINQ_SIZE;
	hw->aq.arq_buf_size = I40E_ADMINQ_BUFSZ;
	hw->aq.asq_buf_size = I40E_ADMINQ_BUFSZ;

	rc = i40e_init_adminq(hw);
	if (rc != 0) {
		i40e_error(i40e, "failed to initialize firmware admin queue: "
		    "%d, potential firmware version mismatch", rc);
		i40e_fm_ereport(i40e, DDI_FM_DEVICE_INVAL_STATE);
		return (B_FALSE);
	}

	if (hw->aq.api_maj_ver == I40E_FW_API_VERSION_MAJOR &&
	    hw->aq.api_min_ver > I40E_FW_API_VERSION_MINOR) {
		i40e_log(i40e, "The driver for the device detected a newer "
		    "version of the NVM image (%d.%d) than expected (%d.%d).\n"
		    "Please install the most recent version of the network "
		    "driver.\n", hw->aq.api_maj_ver, hw->aq.api_min_ver,
		    I40E_FW_API_VERSION_MAJOR, I40E_FW_API_VERSION_MINOR);
	} else if (hw->aq.api_maj_ver < I40E_FW_API_VERSION_MAJOR ||
	    hw->aq.api_min_ver < (I40E_FW_API_VERSION_MINOR - 1)) {
		i40e_log(i40e, "The driver for the device detected an older"
		    " version of the NVM image (%d.%d) than expected (%d.%d)."
		    "\nPlease update the NVM image.\n",
		    hw->aq.api_maj_ver, hw->aq.api_min_ver,
		    I40E_FW_API_VERSION_MAJOR, I40E_FW_API_VERSION_MINOR - 1);
	}

	i40e_clear_pxe_mode(hw);

	/*
	 * We need to call this so that the common code can discover
	 * capabilities of the hardware, which it uses throughout the rest.
	 */
	if (!i40e_get_hw_capabilities(i40e, hw)) {
		i40e_error(i40e, "failed to obtain hardware capabilities");
		return (B_FALSE);
	}

	if (i40e_get_available_resources(i40e) == B_FALSE) {
		i40e_error(i40e, "failed to obtain hardware resources");
		return (B_FALSE);
	}

	i40e_hw_to_instance(i40e, hw);

	rc = i40e_init_lan_hmc(hw, hw->func_caps.num_tx_qp,
	    hw->func_caps.num_rx_qp, 0, 0);
	if (rc != 0) {
		i40e_error(i40e, "failed to initialize hardware memory cache: "
		    "%d", rc);
		return (B_FALSE);
	}

	rc = i40e_configure_lan_hmc(hw, I40E_HMC_MODEL_DIRECT_ONLY);
	if (rc != 0) {
		i40e_error(i40e, "failed to configure hardware memory cache: "
		    "%d", rc);
		return (B_FALSE);
	}

	(void) i40e_aq_stop_lldp(hw, TRUE, NULL);

	rc = i40e_get_mac_addr(hw, hw->mac.addr);
	if (rc != I40E_SUCCESS) {
		i40e_error(i40e, "failed to retrieve hardware mac address: %d",
		    rc);
		return (B_FALSE);
	}

	rc = i40e_validate_mac_addr(hw->mac.addr);
	if (rc != 0) {
		i40e_error(i40e, "failed to validate internal mac address: "
		    "%d", rc);
		return (B_FALSE);
	}
	bcopy(hw->mac.addr, hw->mac.perm_addr, ETHERADDRL);
	if ((rc = i40e_get_port_mac_addr(hw, hw->mac.port_addr)) !=
	    I40E_SUCCESS) {
		i40e_error(i40e, "failed to retrieve port mac address: %d",
		    rc);
		return (B_FALSE);
	}

	/*
	 * We need to obtain the Virtual Station ID (VSI) before we can
	 * perform other operations on the device.
	 */
	i40e->i40e_vsi_id = i40e_get_vsi_id(i40e);
	if (i40e->i40e_vsi_id == -1) {
		i40e_error(i40e, "failed to obtain VSI ID");
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
i40e_unconfigure(dev_info_t *devinfo, i40e_t *i40e)
{
	int rc;

	if (i40e->i40e_attach_progress & I40E_ATTACH_ENABLE_INTR)
		(void) i40e_disable_interrupts(i40e);

	if ((i40e->i40e_attach_progress & I40E_ATTACH_LINK_TIMER) &&
	    i40e->i40e_periodic_id != 0) {
		ddi_periodic_delete(i40e->i40e_periodic_id);
		i40e->i40e_periodic_id = 0;
	}

	if (i40e->i40e_attach_progress & I40E_ATTACH_MAC) {
		rc = mac_unregister(i40e->i40e_mac_hdl);
		if (rc != 0) {
			i40e_error(i40e, "failed to unregister from mac: %d",
			    rc);
		}
	}

	if (i40e->i40e_attach_progress & I40E_ATTACH_STATS) {
		i40e_stats_fini(i40e);
	}

	if (i40e->i40e_attach_progress & I40E_ATTACH_ADD_INTR)
		i40e_rem_intr_handlers(i40e);

	if (i40e->i40e_attach_progress & I40E_ATTACH_ALLOC_RINGSLOCKS)
		i40e_free_trqpairs(i40e);

	if (i40e->i40e_attach_progress & I40E_ATTACH_ALLOC_INTR)
		i40e_rem_intrs(i40e);

	if (i40e->i40e_attach_progress & I40E_ATTACH_COMMON_CODE)
		i40e_common_code_fini(i40e);

	i40e_cleanup_resources(i40e);

	if (i40e->i40e_attach_progress & I40E_ATTACH_PROPS)
		(void) ddi_prop_remove_all(devinfo);

	if (i40e->i40e_attach_progress & I40E_ATTACH_REGS_MAP &&
	    i40e->i40e_osdep_space.ios_reg_handle != NULL) {
		ddi_regs_map_free(&i40e->i40e_osdep_space.ios_reg_handle);
		i40e->i40e_osdep_space.ios_reg_handle = NULL;
	}

	if ((i40e->i40e_attach_progress & I40E_ATTACH_PCI_CONFIG) &&
	    i40e->i40e_osdep_space.ios_cfg_handle != NULL) {
		pci_config_teardown(&i40e->i40e_osdep_space.ios_cfg_handle);
		i40e->i40e_osdep_space.ios_cfg_handle = NULL;
	}

	if (i40e->i40e_attach_progress & I40E_ATTACH_FM_INIT)
		i40e_fm_fini(i40e);

	kmem_free(i40e->i40e_aqbuf, I40E_ADMINQ_BUFSZ);
	kmem_free(i40e, sizeof (i40e_t));

	ddi_set_driver_private(devinfo, NULL);
}

static boolean_t
i40e_final_init(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	struct i40e_osdep *osdep = OS_DEP(hw);
	uint8_t pbanum[I40E_PBANUM_STRLEN];
	enum i40e_status_code irc;
	char buf[I40E_DDI_PROP_LEN];

	pbanum[0] = '\0';
	irc = i40e_read_pba_string(hw, pbanum, sizeof (pbanum));
	if (irc != I40E_SUCCESS) {
		i40e_log(i40e, "failed to read PBA string: %d", irc);
	} else {
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, i40e->i40e_dip,
		    "printed-board-assembly", (char *)pbanum);
	}

#ifdef	DEBUG
	ASSERT(snprintf(NULL, 0, "%d.%d", hw->aq.fw_maj_ver,
	    hw->aq.fw_min_ver) < sizeof (buf));
	ASSERT(snprintf(NULL, 0, "%x", hw->aq.fw_build) < sizeof (buf));
	ASSERT(snprintf(NULL, 0, "%d.%d", hw->aq.api_maj_ver,
	    hw->aq.api_min_ver) < sizeof (buf));
#endif

	(void) snprintf(buf, sizeof (buf), "%d.%d", hw->aq.fw_maj_ver,
	    hw->aq.fw_min_ver);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, i40e->i40e_dip,
	    "firmware-version", buf);
	(void) snprintf(buf, sizeof (buf), "%x", hw->aq.fw_build);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, i40e->i40e_dip,
	    "firmware-build", buf);
	(void) snprintf(buf, sizeof (buf), "%d.%d", hw->aq.api_maj_ver,
	    hw->aq.api_min_ver);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, i40e->i40e_dip,
	    "api-version", buf);

	if (!i40e_set_hw_bus_info(hw))
		return (B_FALSE);

	if (i40e_check_acc_handle(osdep->ios_reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
i40e_identify_hardware(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	struct i40e_osdep *osdep = &i40e->i40e_osdep_space;

	hw->vendor_id = pci_config_get16(osdep->ios_cfg_handle, PCI_CONF_VENID);
	hw->device_id = pci_config_get16(osdep->ios_cfg_handle, PCI_CONF_DEVID);
	hw->revision_id = pci_config_get8(osdep->ios_cfg_handle,
	    PCI_CONF_REVID);
	hw->subsystem_device_id =
	    pci_config_get16(osdep->ios_cfg_handle, PCI_CONF_SUBSYSID);
	hw->subsystem_vendor_id =
	    pci_config_get16(osdep->ios_cfg_handle, PCI_CONF_SUBVENID);

	/*
	 * Note that we set the hardware's bus information later on, in
	 * i40e_get_available_resources(). The common code doesn't seem to
	 * require that it be set in any ways, it seems to be mostly for
	 * book-keeping.
	 */
}

static boolean_t
i40e_regs_map(i40e_t *i40e)
{
	dev_info_t *devinfo = i40e->i40e_dip;
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	struct i40e_osdep *osdep = &i40e->i40e_osdep_space;
	off_t memsize;
	int ret;

	if (ddi_dev_regsize(devinfo, I40E_ADAPTER_REGSET, &memsize) !=
	    DDI_SUCCESS) {
		i40e_error(i40e, "Used invalid register set to map PCIe regs");
		return (B_FALSE);
	}

	if ((ret = ddi_regs_map_setup(devinfo, I40E_ADAPTER_REGSET,
	    (caddr_t *)&hw->hw_addr, 0, memsize, &i40e_regs_acc_attr,
	    &osdep->ios_reg_handle)) != DDI_SUCCESS) {
		i40e_error(i40e, "failed to map device registers: %d", ret);
		return (B_FALSE);
	}

	osdep->ios_reg_size = memsize;
	return (B_TRUE);
}

/*
 * Update parameters required when a new MTU has been configured.  Calculate the
 * maximum frame size, as well as, size our DMA buffers which we size in
 * increments of 1K.
 */
void
i40e_update_mtu(i40e_t *i40e)
{
	uint32_t rx, tx;

	i40e->i40e_frame_max = i40e->i40e_sdu +
	    sizeof (struct ether_vlan_header) + ETHERFCSL;

	rx = i40e->i40e_frame_max + I40E_BUF_IPHDR_ALIGNMENT;
	i40e->i40e_rx_buf_size = ((rx >> 10) +
	    ((rx & (((uint32_t)1 << 10) -1)) > 0 ? 1 : 0)) << 10;

	tx = i40e->i40e_frame_max;
	i40e->i40e_tx_buf_size = ((tx >> 10) +
	    ((tx & (((uint32_t)1 << 10) -1)) > 0 ? 1 : 0)) << 10;
}

static int
i40e_get_prop(i40e_t *i40e, char *prop, int min, int max, int def)
{
	int val;

	val = ddi_prop_get_int(DDI_DEV_T_ANY, i40e->i40e_dip, DDI_PROP_DONTPASS,
	    prop, def);
	if (val > max)
		val = max;
	if (val < min)
		val = min;
	return (val);
}

static void
i40e_init_properties(i40e_t *i40e)
{
	i40e->i40e_sdu = i40e_get_prop(i40e, "default_mtu",
	    I40E_MIN_MTU, I40E_MAX_MTU, I40E_DEF_MTU);

	i40e->i40e_intr_force = i40e_get_prop(i40e, "intr_force",
	    I40E_INTR_NONE, I40E_INTR_LEGACY, I40E_INTR_NONE);

	i40e->i40e_mr_enable = i40e_get_prop(i40e, "mr_enable",
	    B_FALSE, B_TRUE, B_TRUE);

	i40e->i40e_tx_ring_size = i40e_get_prop(i40e, "tx_ring_size",
	    I40E_MIN_TX_RING_SIZE, I40E_MAX_TX_RING_SIZE,
	    I40E_DEF_TX_RING_SIZE);
	if ((i40e->i40e_tx_ring_size % I40E_DESC_ALIGN) != 0) {
		i40e->i40e_tx_ring_size = P2ROUNDUP(i40e->i40e_tx_ring_size,
		    I40E_DESC_ALIGN);
	}

	i40e->i40e_tx_block_thresh = i40e_get_prop(i40e, "tx_resched_threshold",
	    I40E_MIN_TX_BLOCK_THRESH,
	    i40e->i40e_tx_ring_size - I40E_TX_MAX_COOKIE,
	    I40E_DEF_TX_BLOCK_THRESH);

	i40e->i40e_rx_ring_size = i40e_get_prop(i40e, "rx_ring_size",
	    I40E_MIN_RX_RING_SIZE, I40E_MAX_RX_RING_SIZE,
	    I40E_DEF_RX_RING_SIZE);
	if ((i40e->i40e_rx_ring_size % I40E_DESC_ALIGN) != 0) {
		i40e->i40e_rx_ring_size = P2ROUNDUP(i40e->i40e_rx_ring_size,
		    I40E_DESC_ALIGN);
	}

	i40e->i40e_rx_limit_per_intr = i40e_get_prop(i40e, "rx_limit_per_intr",
	    I40E_MIN_RX_LIMIT_PER_INTR,	I40E_MAX_RX_LIMIT_PER_INTR,
	    I40E_DEF_RX_LIMIT_PER_INTR);

	i40e->i40e_tx_hcksum_enable = i40e_get_prop(i40e, "tx_hcksum_enable",
	    B_FALSE, B_TRUE, B_TRUE);

	i40e->i40e_rx_hcksum_enable = i40e_get_prop(i40e, "rx_hcksum_enable",
	    B_FALSE, B_TRUE, B_TRUE);

	i40e->i40e_rx_dma_min = i40e_get_prop(i40e, "rx_dma_threshold",
	    I40E_MIN_RX_DMA_THRESH, I40E_MAX_RX_DMA_THRESH,
	    I40E_DEF_RX_DMA_THRESH);

	i40e->i40e_tx_dma_min = i40e_get_prop(i40e, "tx_dma_threshold",
	    I40E_MIN_TX_DMA_THRESH, I40E_MAX_TX_DMA_THRESH,
	    I40E_DEF_TX_DMA_THRESH);

	i40e->i40e_tx_itr = i40e_get_prop(i40e, "tx_intr_throttle",
	    I40E_MIN_ITR, I40E_MAX_ITR, I40E_DEF_TX_ITR);

	i40e->i40e_rx_itr = i40e_get_prop(i40e, "rx_intr_throttle",
	    I40E_MIN_ITR, I40E_MAX_ITR, I40E_DEF_RX_ITR);

	i40e->i40e_other_itr = i40e_get_prop(i40e, "other_intr_throttle",
	    I40E_MIN_ITR, I40E_MAX_ITR, I40E_DEF_OTHER_ITR);

	if (!i40e->i40e_mr_enable) {
		i40e->i40e_num_trqpairs = I40E_TRQPAIR_NOMSIX;
		i40e->i40e_num_rx_groups = I40E_GROUP_NOMSIX;
	}

	i40e_update_mtu(i40e);
}

/*
 * There are a few constraints on interrupts that we're currently imposing, some
 * of which are restrictions from hardware. For a fuller treatment, see
 * i40e_intr.c.
 *
 * Currently, to use MSI-X we require two interrupts be available though in
 * theory we should participate in IRM and happily use more interrupts.
 *
 * Hardware only supports a single MSI being programmed and therefore if we
 * don't have MSI-X interrupts available at this time, then we ratchet down the
 * number of rings and groups available. Obviously, we only bother with a single
 * fixed interrupt.
 */
static boolean_t
i40e_alloc_intr_handles(i40e_t *i40e, dev_info_t *devinfo, int intr_type)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	ddi_acc_handle_t rh = i40e->i40e_osdep_space.ios_reg_handle;
	int request, count, actual, rc, min;
	uint32_t reg;

	switch (intr_type) {
	case DDI_INTR_TYPE_FIXED:
	case DDI_INTR_TYPE_MSI:
		request = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSIX:
		min = 2;
		if (!i40e->i40e_mr_enable) {
			request = 2;
			break;
		}
		reg = I40E_READ_REG(hw, I40E_GLPCI_CNF2);
		/*
		 * Should this read fail, we will drop back to using
		 * MSI or fixed interrupts.
		 */
		if (i40e_check_acc_handle(rh) != DDI_FM_OK) {
			ddi_fm_service_impact(i40e->i40e_dip,
			    DDI_SERVICE_DEGRADED);
			return (B_FALSE);
		}
		request = (reg & I40E_GLPCI_CNF2_MSI_X_PF_N_MASK) >>
		    I40E_GLPCI_CNF2_MSI_X_PF_N_SHIFT;
		request++;	/* the register value is n - 1 */
		break;
	default:
		panic("bad interrupt type passed to i40e_alloc_intr_handles: "
		    "%d", intr_type);
		return (B_FALSE);
	}

	rc = ddi_intr_get_nintrs(devinfo, intr_type, &count);
	if (rc != DDI_SUCCESS || count < min) {
		i40e_log(i40e, "Get interrupt number failed, "
		    "returned %d, count %d", rc, count);
		return (B_FALSE);
	}

	rc = ddi_intr_get_navail(devinfo, intr_type, &count);
	if (rc != DDI_SUCCESS || count < min) {
		i40e_log(i40e, "Get AVAILABLE interrupt number failed, "
		    "returned %d, count %d", rc, count);
		return (B_FALSE);
	}

	actual = 0;
	i40e->i40e_intr_count = 0;
	i40e->i40e_intr_count_max = 0;
	i40e->i40e_intr_count_min = 0;

	i40e->i40e_intr_size = request * sizeof (ddi_intr_handle_t);
	ASSERT(i40e->i40e_intr_size != 0);
	i40e->i40e_intr_handles = kmem_alloc(i40e->i40e_intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, i40e->i40e_intr_handles, intr_type, 0,
	    min(request, count), &actual, DDI_INTR_ALLOC_NORMAL);
	if (rc != DDI_SUCCESS) {
		i40e_log(i40e, "Interrupt allocation failed with %d.", rc);
		goto alloc_handle_fail;
	}

	i40e->i40e_intr_count = actual;
	i40e->i40e_intr_count_max = request;
	i40e->i40e_intr_count_min = min;

	if (actual < min) {
		i40e_log(i40e, "actual (%d) is less than minimum (%d).",
		    actual, min);
		goto alloc_handle_fail;
	}

	/*
	 * Record the priority and capabilities for our first vector.  Once
	 * we have it, that's our priority until detach time.  Even if we
	 * eventually participate in IRM, our priority shouldn't change.
	 */
	rc = ddi_intr_get_pri(i40e->i40e_intr_handles[0], &i40e->i40e_intr_pri);
	if (rc != DDI_SUCCESS) {
		i40e_log(i40e,
		    "Getting interrupt priority failed with %d.", rc);
		goto alloc_handle_fail;
	}

	rc = ddi_intr_get_cap(i40e->i40e_intr_handles[0], &i40e->i40e_intr_cap);
	if (rc != DDI_SUCCESS) {
		i40e_log(i40e,
		    "Getting interrupt capabilities failed with %d.", rc);
		goto alloc_handle_fail;
	}

	i40e->i40e_intr_type = intr_type;
	return (B_TRUE);

alloc_handle_fail:

	i40e_rem_intrs(i40e);
	return (B_FALSE);
}

static boolean_t
i40e_alloc_intrs(i40e_t *i40e, dev_info_t *devinfo)
{
	int intr_types, rc;
	uint_t max_trqpairs;

	if (i40e_is_x722(i40e)) {
		max_trqpairs = I40E_722_MAX_TC_QUEUES;
	} else {
		max_trqpairs = I40E_710_MAX_TC_QUEUES;
	}

	rc = ddi_intr_get_supported_types(devinfo, &intr_types);
	if (rc != DDI_SUCCESS) {
		i40e_error(i40e, "failed to get supported interrupt types: %d",
		    rc);
		return (B_FALSE);
	}

	i40e->i40e_intr_type = 0;

	if ((intr_types & DDI_INTR_TYPE_MSIX) &&
	    i40e->i40e_intr_force <= I40E_INTR_MSIX) {
		if (i40e_alloc_intr_handles(i40e, devinfo,
		    DDI_INTR_TYPE_MSIX)) {
			i40e->i40e_num_trqpairs =
			    MIN(i40e->i40e_intr_count - 1, max_trqpairs);
			return (B_TRUE);
		}
	}

	/*
	 * We only use multiple transmit/receive pairs when MSI-X interrupts are
	 * available due to the fact that the device basically only supports a
	 * single MSI interrupt.
	 */
	i40e->i40e_num_trqpairs = I40E_TRQPAIR_NOMSIX;
	i40e->i40e_num_rx_groups = I40E_GROUP_NOMSIX;

	if ((intr_types & DDI_INTR_TYPE_MSI) &&
	    (i40e->i40e_intr_force <= I40E_INTR_MSI)) {
		if (i40e_alloc_intr_handles(i40e, devinfo, DDI_INTR_TYPE_MSI))
			return (B_TRUE);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (i40e_alloc_intr_handles(i40e, devinfo, DDI_INTR_TYPE_FIXED))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Map different interrupts to MSI-X vectors.
 */
static boolean_t
i40e_map_intrs_to_vectors(i40e_t *i40e)
{
	int i;

	if (i40e->i40e_intr_type != DDI_INTR_TYPE_MSIX) {
		return (B_TRUE);
	}

	/*
	 * Each queue pair is mapped to a single interrupt, so transmit
	 * and receive interrupts for a given queue share the same vector.
	 * The number of queue pairs is one less than the number of interrupt
	 * vectors and is assigned the vector one higher than its index.
	 * Vector zero is reserved for the admin queue.
	 */
	ASSERT(i40e->i40e_intr_count == i40e->i40e_num_trqpairs + 1);

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e->i40e_trqpairs[i].itrq_rx_intrvec = i + 1;
		i40e->i40e_trqpairs[i].itrq_tx_intrvec = i + 1;
	}

	return (B_TRUE);
}

static boolean_t
i40e_add_intr_handlers(i40e_t *i40e)
{
	int rc, vector;

	switch (i40e->i40e_intr_type) {
	case DDI_INTR_TYPE_MSIX:
		for (vector = 0; vector < i40e->i40e_intr_count; vector++) {
			rc = ddi_intr_add_handler(
			    i40e->i40e_intr_handles[vector],
			    (ddi_intr_handler_t *)i40e_intr_msix, i40e,
			    (void *)(uintptr_t)vector);
			if (rc != DDI_SUCCESS) {
				i40e_log(i40e, "Add interrupt handler (MSI-X) "
				    "failed: return %d, vector %d", rc, vector);
				for (vector--; vector >= 0; vector--) {
					(void) ddi_intr_remove_handler(
					    i40e->i40e_intr_handles[vector]);
				}
				return (B_FALSE);
			}
		}
		break;
	case DDI_INTR_TYPE_MSI:
		rc = ddi_intr_add_handler(i40e->i40e_intr_handles[0],
		    (ddi_intr_handler_t *)i40e_intr_msi, i40e, NULL);
		if (rc != DDI_SUCCESS) {
			i40e_log(i40e, "Add interrupt handler (MSI) failed: "
			    "return %d", rc);
			return (B_FALSE);
		}
		break;
	case DDI_INTR_TYPE_FIXED:
		rc = ddi_intr_add_handler(i40e->i40e_intr_handles[0],
		    (ddi_intr_handler_t *)i40e_intr_legacy, i40e, NULL);
		if (rc != DDI_SUCCESS) {
			i40e_log(i40e, "Add interrupt handler (legacy) failed:"
			    " return %d", rc);
			return (B_FALSE);
		}
		break;
	default:
		/* Cast to pacify lint */
		panic("i40e_intr_type %p contains an unknown type: %d",
		    (void *)i40e, i40e->i40e_intr_type);
	}

	return (B_TRUE);
}

/*
 * Perform periodic checks. Longer term, we should be thinking about additional
 * things here:
 *
 * o Stall Detection
 * o Temperature sensor detection
 * o Device resetting
 * o Statistics updating to avoid wraparound
 */
static void
i40e_timer(void *arg)
{
	i40e_t *i40e = arg;

	mutex_enter(&i40e->i40e_general_lock);
	i40e_link_check(i40e);
	mutex_exit(&i40e->i40e_general_lock);
}

/*
 * Get the hardware state, and scribble away anything that needs scribbling.
 */
static void
i40e_get_hw_state(i40e_t *i40e, i40e_hw_t *hw)
{
	int rc;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	(void) i40e_aq_get_link_info(hw, TRUE, NULL, NULL);
	i40e_link_check(i40e);

	/*
	 * Try and determine our PHY. Note that we may have to retry to and
	 * delay to detect fiber correctly.
	 */
	rc = i40e_aq_get_phy_capabilities(hw, B_FALSE, B_TRUE, &i40e->i40e_phy,
	    NULL);
	if (rc == I40E_ERR_UNKNOWN_PHY) {
		i40e_msec_delay(200);
		rc = i40e_aq_get_phy_capabilities(hw, B_FALSE, B_TRUE,
		    &i40e->i40e_phy, NULL);
	}

	if (rc != I40E_SUCCESS) {
		if (rc == I40E_ERR_UNKNOWN_PHY) {
			i40e_error(i40e, "encountered unknown PHY type, "
			    "not attaching.");
		} else {
			i40e_error(i40e, "error getting physical capabilities: "
			    "%d, %d", rc, hw->aq.asq_last_status);
		}
	}

	rc = i40e_update_link_info(hw);
	if (rc != I40E_SUCCESS) {
		i40e_error(i40e, "failed to update link information: %d", rc);
	}

	/*
	 * In general, we don't want to mask off (as in stop from being a cause)
	 * any of the interrupts that the phy might be able to generate.
	 */
	rc = i40e_aq_set_phy_int_mask(hw, 0, NULL);
	if (rc != I40E_SUCCESS) {
		i40e_error(i40e, "failed to update phy link mask: %d", rc);
	}
}

/*
 * Go through and re-initialize any existing filters that we may have set up for
 * this device. Note that we would only expect them to exist if hardware had
 * already been initialized and we had just reset it. While we're not
 * implementing this yet, we're keeping this around for when we add reset
 * capabilities, so this isn't forgotten.
 */
/* ARGSUSED */
static void
i40e_init_macaddrs(i40e_t *i40e, i40e_hw_t *hw)
{
}

/*
 * Configure the hardware for the Virtual Station Interface (VSI).  Currently
 * we only support one, but in the future we could instantiate more than one
 * per attach-point.
 */
static boolean_t
i40e_config_vsi(i40e_t *i40e, i40e_hw_t *hw)
{
	struct i40e_vsi_context	context;
	int err, tc_queues;

	bzero(&context, sizeof (struct i40e_vsi_context));
	context.seid = i40e->i40e_vsi_id;
	context.pf_num = hw->pf_id;
	err = i40e_aq_get_vsi_params(hw, &context, NULL);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "get VSI params failed with %d", err);
		return (B_FALSE);
	}

	i40e->i40e_vsi_num = context.vsi_number;

	/*
	 * Set the queue and traffic class bits.  Keep it simple for now.
	 */
	context.info.valid_sections = I40E_AQ_VSI_PROP_QUEUE_MAP_VALID;
	context.info.mapping_flags = I40E_AQ_VSI_QUE_MAP_CONTIG;
	context.info.queue_mapping[0] = I40E_ASSIGN_ALL_QUEUES;

	/*
	 * tc_queues determines the size of the traffic class, where the size is
	 * 2^^tc_queues to a maximum of 64 for the X710 and 128 for the X722.
	 *
	 * Some examples:
	 * 	i40e_num_trqpairs == 1 =>  tc_queues = 0, 2^^0 = 1.
	 * 	i40e_num_trqpairs == 7 =>  tc_queues = 3, 2^^3 = 8.
	 * 	i40e_num_trqpairs == 8 =>  tc_queues = 3, 2^^3 = 8.
	 * 	i40e_num_trqpairs == 9 =>  tc_queues = 4, 2^^4 = 16.
	 * 	i40e_num_trqpairs == 17 => tc_queues = 5, 2^^5 = 32.
	 * 	i40e_num_trqpairs == 64 => tc_queues = 6, 2^^6 = 64.
	 */
	tc_queues = ddi_fls(i40e->i40e_num_trqpairs - 1);

	context.info.tc_mapping[0] = ((0 << I40E_AQ_VSI_TC_QUE_OFFSET_SHIFT) &
	    I40E_AQ_VSI_TC_QUE_OFFSET_MASK) |
	    ((tc_queues << I40E_AQ_VSI_TC_QUE_NUMBER_SHIFT) &
	    I40E_AQ_VSI_TC_QUE_NUMBER_MASK);

	context.info.valid_sections |= I40E_AQ_VSI_PROP_VLAN_VALID;
	context.info.port_vlan_flags = I40E_AQ_VSI_PVLAN_MODE_ALL |
	    I40E_AQ_VSI_PVLAN_EMOD_NOTHING;

	context.flags = LE16_TO_CPU(I40E_AQ_VSI_TYPE_PF);

	i40e->i40e_vsi_stat_id = LE16_TO_CPU(context.info.stat_counter_idx);
	if (i40e_stat_vsi_init(i40e) == B_FALSE)
		return (B_FALSE);

	err = i40e_aq_update_vsi_params(hw, &context, NULL);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "Update VSI params failed with %d", err);
		return (B_FALSE);
	}


	return (B_TRUE);
}

/*
 * Configure the RSS key. For the X710 controller family, this is set on a
 * per-PF basis via registers. For the X722, this is done on a per-VSI basis
 * through the admin queue.
 */
static boolean_t
i40e_config_rss_key(i40e_t *i40e, i40e_hw_t *hw)
{
	uint32_t seed[I40E_PFQF_HKEY_MAX_INDEX + 1];

	(void) random_get_pseudo_bytes((uint8_t *)seed, sizeof (seed));

	if (i40e_is_x722(i40e)) {
		struct i40e_aqc_get_set_rss_key_data key;
		const char *u8seed = (char *)seed;
		enum i40e_status_code status;

		CTASSERT(sizeof (key) >= (sizeof (key.standard_rss_key) +
		    sizeof (key.extended_hash_key)));

		bcopy(u8seed, key.standard_rss_key,
		    sizeof (key.standard_rss_key));
		bcopy(&u8seed[sizeof (key.standard_rss_key)],
		    key.extended_hash_key, sizeof (key.extended_hash_key));

		status = i40e_aq_set_rss_key(hw, i40e->i40e_vsi_num, &key);
		if (status != I40E_SUCCESS) {
			i40e_error(i40e, "failed to set rss key: %d", status);
			return (B_FALSE);
		}
	} else {
		uint_t i;
		for (i = 0; i <= I40E_PFQF_HKEY_MAX_INDEX; i++)
			i40e_write_rx_ctl(hw, I40E_PFQF_HKEY(i), seed[i]);
	}

	return (B_TRUE);
}

/*
 * Populate the LUT. The size of each entry in the LUT depends on the controller
 * family, with the X722 using a known 7-bit width. On the X710 controller, this
 * is programmed through its control registers where as on the X722 this is
 * configured through the admin queue. Also of note, the X722 allows the LUT to
 * be set on a per-PF or VSI basis. At this time, as we only have a single VSI,
 * we use the PF setting as it is the primary VSI.
 *
 * We populate the LUT in a round robin fashion with the rx queue indices from 0
 * to i40e_num_trqpairs - 1.
 */
static boolean_t
i40e_config_rss_hlut(i40e_t *i40e, i40e_hw_t *hw)
{
	uint32_t *hlut;
	uint8_t lut_mask;
	uint_t i;
	boolean_t ret = B_FALSE;

	/*
	 * We always configure the PF with a table size of 512 bytes in
	 * i40e_chip_start().
	 */
	hlut = kmem_alloc(I40E_HLUT_TABLE_SIZE, KM_NOSLEEP);
	if (hlut == NULL) {
		i40e_error(i40e, "i40e_config_rss() buffer allocation failed");
		return (B_FALSE);
	}

	/*
	 * The width of the X722 is apparently defined to be 7 bits, regardless
	 * of the capability.
	 */
	if (i40e_is_x722(i40e)) {
		lut_mask = (1 << 7) - 1;
	} else {
		lut_mask = (1 << hw->func_caps.rss_table_entry_width) - 1;
	}

	for (i = 0; i < I40E_HLUT_TABLE_SIZE; i++)
		((uint8_t *)hlut)[i] = (i % i40e->i40e_num_trqpairs) & lut_mask;

	if (i40e_is_x722(i40e)) {
		enum i40e_status_code status;
		status = i40e_aq_set_rss_lut(hw, i40e->i40e_vsi_num, B_TRUE,
		    (uint8_t *)hlut, I40E_HLUT_TABLE_SIZE);
		if (status != I40E_SUCCESS) {
			i40e_error(i40e, "failed to set RSS LUT: %d", status);
			goto out;
		}
	} else {
		for (i = 0; i < I40E_HLUT_TABLE_SIZE >> 2; i++) {
			I40E_WRITE_REG(hw, I40E_PFQF_HLUT(i), hlut[i]);
		}
	}
	ret = B_TRUE;
out:
	kmem_free(hlut, I40E_HLUT_TABLE_SIZE);
	return (ret);
}

/*
 * Set up RSS.
 * 	1. Seed the hash key.
 *	2. Enable PCTYPEs for the hash filter.
 *	3. Populate the LUT.
 */
static boolean_t
i40e_config_rss(i40e_t *i40e, i40e_hw_t *hw)
{
	uint64_t hena;

	/*
	 * 1. Seed the hash key
	 */
	if (!i40e_config_rss_key(i40e, hw))
		return (B_FALSE);

	/*
	 * 2. Configure PCTYPES
	 */
	hena = (1ULL << I40E_FILTER_PCTYPE_NONF_IPV4_OTHER) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV4_TCP) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV4_SCTP) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV4_UDP) |
	    (1ULL << I40E_FILTER_PCTYPE_FRAG_IPV4) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV6_OTHER) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV6_TCP) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV6_SCTP) |
	    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV6_UDP) |
	    (1ULL << I40E_FILTER_PCTYPE_FRAG_IPV6) |
	    (1ULL << I40E_FILTER_PCTYPE_L2_PAYLOAD);

	/*
	 * Add additional types supported by the X722 controller.
	 */
	if (i40e_is_x722(i40e)) {
		hena |= (1ULL << I40E_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP) |
		    (1ULL << I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP) |
		    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK) |
		    (1ULL << I40E_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP) |
		    (1ULL << I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP) |
		    (1ULL << I40E_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK);
	}

	i40e_write_rx_ctl(hw, I40E_PFQF_HENA(0), (uint32_t)hena);
	i40e_write_rx_ctl(hw, I40E_PFQF_HENA(1), (uint32_t)(hena >> 32));

	/*
	 * 3. Populate LUT
	 */
	return (i40e_config_rss_hlut(i40e, hw));
}

/*
 * Wrapper to kick the chipset on.
 */
static boolean_t
i40e_chip_start(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	struct i40e_filter_control_settings filter;
	int rc;

	if (((hw->aq.fw_maj_ver == 4) && (hw->aq.fw_min_ver < 33)) ||
	    (hw->aq.fw_maj_ver < 4)) {
		i40e_msec_delay(75);
		if (i40e_aq_set_link_restart_an(hw, TRUE, NULL) !=
		    I40E_SUCCESS) {
			i40e_error(i40e, "failed to restart link: admin queue "
			    "error: %d", hw->aq.asq_last_status);
			return (B_FALSE);
		}
	}

	/* Determine hardware state */
	i40e_get_hw_state(i40e, hw);

	/* Initialize mac addresses. */
	i40e_init_macaddrs(i40e, hw);

	/*
	 * Set up the filter control. If the hash lut size is changed from
	 * I40E_HASH_LUT_SIZE_512 then I40E_HLUT_TABLE_SIZE and
	 * i40e_config_rss_hlut() will need to be updated.
	 */
	bzero(&filter, sizeof (filter));
	filter.enable_ethtype = TRUE;
	filter.enable_macvlan = TRUE;
	filter.hash_lut_size = I40E_HASH_LUT_SIZE_512;

	rc = i40e_set_filter_control(hw, &filter);
	if (rc != I40E_SUCCESS) {
		i40e_error(i40e, "i40e_set_filter_control() returned %d", rc);
		return (B_FALSE);
	}

	i40e_intr_chip_init(i40e);

	if (!i40e_config_vsi(i40e, hw))
		return (B_FALSE);

	if (!i40e_config_rss(i40e, hw))
		return (B_FALSE);

	i40e_flush(hw);

	return (B_TRUE);
}

/*
 * Take care of tearing down the rx ring. See 8.3.3.1.2 for more information.
 */
static void
i40e_shutdown_rx_rings(i40e_t *i40e)
{
	int i;
	uint32_t reg;

	i40e_hw_t *hw = &i40e->i40e_hw_space;

	/*
	 * Step 1. The interrupt linked list (see i40e_intr.c for more
	 * information) should have already been cleared before calling this
	 * function.
	 */
#ifdef	DEBUG
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		for (i = 1; i < i40e->i40e_intr_count; i++) {
			reg = I40E_READ_REG(hw, I40E_PFINT_LNKLSTN(i - 1));
			VERIFY3U(reg, ==, I40E_QUEUE_TYPE_EOL);
		}
	} else {
		reg = I40E_READ_REG(hw, I40E_PFINT_LNKLST0);
		VERIFY3U(reg, ==, I40E_QUEUE_TYPE_EOL);
	}

#endif	/* DEBUG */

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		/*
		 * Step 1. Request the queue by clearing QENA_REQ. It may not be
		 * set due to unwinding from failures and a partially enabled
		 * ring set.
		 */
		reg = I40E_READ_REG(hw, I40E_QRX_ENA(i));
		if (!(reg & I40E_QRX_ENA_QENA_REQ_MASK))
			continue;
		VERIFY((reg & I40E_QRX_ENA_QENA_REQ_MASK) ==
		    I40E_QRX_ENA_QENA_REQ_MASK);
		reg &= ~I40E_QRX_ENA_QENA_REQ_MASK;
		I40E_WRITE_REG(hw, I40E_QRX_ENA(i), reg);
	}

	/*
	 * Step 2. Wait for the disable to take, by having QENA_STAT in the FPM
	 * be cleared. Note that we could still receive data in the queue during
	 * this time. We don't actually wait for this now and instead defer this
	 * to i40e_shutdown_rings_wait(), after we've interleaved disabling the
	 * TX queues as well.
	 */
}

static void
i40e_shutdown_tx_rings(i40e_t *i40e)
{
	int i;
	uint32_t reg;

	i40e_hw_t *hw = &i40e->i40e_hw_space;

	/*
	 * Step 1. The interrupt linked list should already have been cleared.
	 */
#ifdef DEBUG
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		for (i = 1; i < i40e->i40e_intr_count; i++) {
			reg = I40E_READ_REG(hw, I40E_PFINT_LNKLSTN(i - 1));
			VERIFY3U(reg, ==, I40E_QUEUE_TYPE_EOL);
		}
	} else {
		reg = I40E_READ_REG(hw, I40E_PFINT_LNKLST0);
		VERIFY3U(reg, ==, I40E_QUEUE_TYPE_EOL);

	}
#endif	/* DEBUG */

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		/*
		 * Step 2. Set the SET_QDIS flag for every queue.
		 */
		i40e_pre_tx_queue_cfg(hw, i, B_FALSE);
	}

	/*
	 * Step 3. Wait at least 400 usec (can be done once for all queues).
	 */
	drv_usecwait(500);

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		/*
		 * Step 4. Clear the QENA_REQ flag which tells hardware to
		 * quiesce. If QENA_REQ is not already set then that means that
		 * we likely already tried to disable this queue.
		 */
		reg = I40E_READ_REG(hw, I40E_QTX_ENA(i));
		if (!(reg & I40E_QTX_ENA_QENA_REQ_MASK))
			continue;
		reg &= ~I40E_QTX_ENA_QENA_REQ_MASK;
		I40E_WRITE_REG(hw, I40E_QTX_ENA(i), reg);
	}

	/*
	 * Step 5. Wait for all drains to finish. This will be done by the
	 * hardware removing the QENA_STAT flag from the queue. Rather than
	 * waiting here, we interleave it with all the others in
	 * i40e_shutdown_rings_wait().
	 */
}

/*
 * Wait for all the rings to be shut down. e.g. Steps 2 and 5 from the above
 * functions.
 */
static boolean_t
i40e_shutdown_rings_wait(i40e_t *i40e)
{
	int i, try;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		uint32_t reg;

		for (try = 0; try < I40E_RING_WAIT_NTRIES; try++) {
			reg = I40E_READ_REG(hw, I40E_QRX_ENA(i));
			if ((reg & I40E_QRX_ENA_QENA_STAT_MASK) == 0)
				break;
			i40e_msec_delay(I40E_RING_WAIT_PAUSE);
		}

		if ((reg & I40E_QRX_ENA_QENA_STAT_MASK) != 0) {
			i40e_error(i40e, "timed out disabling rx queue %d",
			    i);
			return (B_FALSE);
		}

		for (try = 0; try < I40E_RING_WAIT_NTRIES; try++) {
			reg = I40E_READ_REG(hw, I40E_QTX_ENA(i));
			if ((reg & I40E_QTX_ENA_QENA_STAT_MASK) == 0)
				break;
			i40e_msec_delay(I40E_RING_WAIT_PAUSE);
		}

		if ((reg & I40E_QTX_ENA_QENA_STAT_MASK) != 0) {
			i40e_error(i40e, "timed out disabling tx queue %d",
			    i);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
i40e_shutdown_rings(i40e_t *i40e)
{
	i40e_shutdown_rx_rings(i40e);
	i40e_shutdown_tx_rings(i40e);
	return (i40e_shutdown_rings_wait(i40e));
}

static void
i40e_setup_rx_descs(i40e_trqpair_t *itrq)
{
	int i;
	i40e_rx_data_t *rxd = itrq->itrq_rxdata;

	for (i = 0; i < rxd->rxd_ring_size; i++) {
		i40e_rx_control_block_t *rcb;
		i40e_rx_desc_t *rdesc;

		rcb = rxd->rxd_work_list[i];
		rdesc = &rxd->rxd_desc_ring[i];

		rdesc->read.pkt_addr =
		    CPU_TO_LE64((uintptr_t)rcb->rcb_dma.dmab_dma_address);
		rdesc->read.hdr_addr = 0;
	}
}

static boolean_t
i40e_setup_rx_hmc(i40e_trqpair_t *itrq)
{
	i40e_rx_data_t *rxd = itrq->itrq_rxdata;
	i40e_t *i40e = itrq->itrq_i40e;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	struct i40e_hmc_obj_rxq rctx;
	int err;

	bzero(&rctx, sizeof (struct i40e_hmc_obj_rxq));
	rctx.base = rxd->rxd_desc_area.dmab_dma_address /
	    I40E_HMC_RX_CTX_UNIT;
	rctx.qlen = rxd->rxd_ring_size;
	VERIFY(i40e->i40e_rx_buf_size >= I40E_HMC_RX_DBUFF_MIN);
	VERIFY(i40e->i40e_rx_buf_size <= I40E_HMC_RX_DBUFF_MAX);
	rctx.dbuff = i40e->i40e_rx_buf_size >> I40E_RXQ_CTX_DBUFF_SHIFT;
	rctx.hbuff = 0 >> I40E_RXQ_CTX_HBUFF_SHIFT;
	rctx.dtype = I40E_HMC_RX_DTYPE_NOSPLIT;
	rctx.dsize = I40E_HMC_RX_DSIZE_32BYTE;
	rctx.crcstrip = I40E_HMC_RX_CRCSTRIP_ENABLE;
	rctx.fc_ena = I40E_HMC_RX_FC_DISABLE;
	rctx.l2tsel = I40E_HMC_RX_L2TAGORDER;
	rctx.hsplit_0 = I40E_HMC_RX_HDRSPLIT_DISABLE;
	rctx.hsplit_1 = I40E_HMC_RX_HDRSPLIT_DISABLE;
	rctx.showiv = I40E_HMC_RX_INVLAN_DONTSTRIP;
	rctx.rxmax = i40e->i40e_frame_max;
	rctx.tphrdesc_ena = I40E_HMC_RX_TPH_DISABLE;
	rctx.tphwdesc_ena = I40E_HMC_RX_TPH_DISABLE;
	rctx.tphdata_ena = I40E_HMC_RX_TPH_DISABLE;
	rctx.tphhead_ena = I40E_HMC_RX_TPH_DISABLE;
	rctx.lrxqthresh = I40E_HMC_RX_LOWRXQ_NOINTR;

	/*
	 * This must be set to 0x1, see Table 8-12 in section 8.3.3.2.2.
	 */
	rctx.prefena = I40E_HMC_RX_PREFENA;

	err = i40e_clear_lan_rx_queue_context(hw, itrq->itrq_index);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to clear rx queue %d context: %d",
		    itrq->itrq_index, err);
		return (B_FALSE);
	}

	err = i40e_set_lan_rx_queue_context(hw, itrq->itrq_index, &rctx);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to set rx queue %d context: %d",
		    itrq->itrq_index, err);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Take care of setting up the descriptor rings and actually programming the
 * device. See 8.3.3.1.1 for the full list of steps we need to do to enable the
 * rx rings.
 */
static boolean_t
i40e_setup_rx_rings(i40e_t *i40e)
{
	int i;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[i];
		i40e_rx_data_t *rxd = itrq->itrq_rxdata;
		uint32_t reg;

		/*
		 * Step 1. Program all receive ring descriptors.
		 */
		i40e_setup_rx_descs(itrq);

		/*
		 * Step 2. Program the queue's FPM/HMC context.
		 */
		if (i40e_setup_rx_hmc(itrq) == B_FALSE)
			return (B_FALSE);

		/*
		 * Step 3. Clear the queue's tail pointer and set it to the end
		 * of the space.
		 */
		I40E_WRITE_REG(hw, I40E_QRX_TAIL(i), 0);
		I40E_WRITE_REG(hw, I40E_QRX_TAIL(i), rxd->rxd_ring_size - 1);

		/*
		 * Step 4. Enable the queue via the QENA_REQ.
		 */
		reg = I40E_READ_REG(hw, I40E_QRX_ENA(i));
		VERIFY0(reg & (I40E_QRX_ENA_QENA_REQ_MASK |
		    I40E_QRX_ENA_QENA_STAT_MASK));
		reg |= I40E_QRX_ENA_QENA_REQ_MASK;
		I40E_WRITE_REG(hw, I40E_QRX_ENA(i), reg);
	}

	/*
	 * Note, we wait for every queue to be enabled before we start checking.
	 * This will hopefully cause most queues to be enabled at this point.
	 */
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		uint32_t j, reg;

		/*
		 * Step 5. Verify that QENA_STAT has been set. It's promised
		 * that this should occur within about 10 us, but like other
		 * systems, we give the card a bit more time.
		 */
		for (j = 0; j < I40E_RING_WAIT_NTRIES; j++) {
			reg = I40E_READ_REG(hw, I40E_QRX_ENA(i));

			if (reg & I40E_QRX_ENA_QENA_STAT_MASK)
				break;
			i40e_msec_delay(I40E_RING_WAIT_PAUSE);
		}

		if ((reg & I40E_QRX_ENA_QENA_STAT_MASK) == 0) {
			i40e_error(i40e, "failed to enable rx queue %d, timed "
			    "out.", i);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
i40e_setup_tx_hmc(i40e_trqpair_t *itrq)
{
	i40e_t *i40e = itrq->itrq_i40e;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	struct i40e_hmc_obj_txq tctx;
	struct i40e_vsi_context	context;
	int err;

	bzero(&tctx, sizeof (struct i40e_hmc_obj_txq));
	tctx.new_context = I40E_HMC_TX_NEW_CONTEXT;
	tctx.base = itrq->itrq_desc_area.dmab_dma_address /
	    I40E_HMC_TX_CTX_UNIT;
	tctx.fc_ena = I40E_HMC_TX_FC_DISABLE;
	tctx.timesync_ena = I40E_HMC_TX_TS_DISABLE;
	tctx.fd_ena = I40E_HMC_TX_FD_DISABLE;
	tctx.alt_vlan_ena = I40E_HMC_TX_ALT_VLAN_DISABLE;
	tctx.head_wb_ena = I40E_HMC_TX_WB_ENABLE;
	tctx.qlen = itrq->itrq_tx_ring_size;
	tctx.tphrdesc_ena = I40E_HMC_TX_TPH_DISABLE;
	tctx.tphrpacket_ena = I40E_HMC_TX_TPH_DISABLE;
	tctx.tphwdesc_ena = I40E_HMC_TX_TPH_DISABLE;
	tctx.head_wb_addr = itrq->itrq_desc_area.dmab_dma_address +
	    sizeof (i40e_tx_desc_t) * itrq->itrq_tx_ring_size;

	/*
	 * This field isn't actually documented, like crc, but it suggests that
	 * it should be zeroed. We leave both of these here because of that for
	 * now. We should check with Intel on why these are here even.
	 */
	tctx.crc = 0;
	tctx.rdylist_act = 0;

	/*
	 * We're supposed to assign the rdylist field with the value of the
	 * traffic class index for the first device. We query the VSI parameters
	 * again to get what the handle is. Note that every queue is always
	 * assigned to traffic class zero, because we don't actually use them.
	 */
	bzero(&context, sizeof (struct i40e_vsi_context));
	context.seid = i40e->i40e_vsi_id;
	context.pf_num = hw->pf_id;
	err = i40e_aq_get_vsi_params(hw, &context, NULL);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "get VSI params failed with %d", err);
		return (B_FALSE);
	}
	tctx.rdylist = LE_16(context.info.qs_handle[0]);

	err = i40e_clear_lan_tx_queue_context(hw, itrq->itrq_index);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to clear tx queue %d context: %d",
		    itrq->itrq_index, err);
		return (B_FALSE);
	}

	err = i40e_set_lan_tx_queue_context(hw, itrq->itrq_index, &tctx);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to set tx queue %d context: %d",
		    itrq->itrq_index, err);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Take care of setting up the descriptor rings and actually programming the
 * device. See 8.4.3.1.1 for what we need to do here.
 */
static boolean_t
i40e_setup_tx_rings(i40e_t *i40e)
{
	int i;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[i];
		uint32_t reg;

		/*
		 * Step 1. Clear the queue disable flag and verify that the
		 * index is set correctly.
		 */
		i40e_pre_tx_queue_cfg(hw, i, B_TRUE);

		/*
		 * Step 2. Prepare the queue's FPM/HMC context.
		 */
		if (i40e_setup_tx_hmc(itrq) == B_FALSE)
			return (B_FALSE);

		/*
		 * Step 3. Verify that it's clear that this PF owns this queue.
		 */
		reg = I40E_QTX_CTL_PF_QUEUE;
		reg |= (hw->pf_id << I40E_QTX_CTL_PF_INDX_SHIFT) &
		    I40E_QTX_CTL_PF_INDX_MASK;
		I40E_WRITE_REG(hw, I40E_QTX_CTL(itrq->itrq_index), reg);
		i40e_flush(hw);

		/*
		 * Step 4. Set the QENA_REQ flag.
		 */
		reg = I40E_READ_REG(hw, I40E_QTX_ENA(i));
		VERIFY0(reg & (I40E_QTX_ENA_QENA_REQ_MASK |
		    I40E_QTX_ENA_QENA_STAT_MASK));
		reg |= I40E_QTX_ENA_QENA_REQ_MASK;
		I40E_WRITE_REG(hw, I40E_QTX_ENA(i), reg);
	}

	/*
	 * Note, we wait for every queue to be enabled before we start checking.
	 * This will hopefully cause most queues to be enabled at this point.
	 */
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		uint32_t j, reg;

		/*
		 * Step 5. Verify that QENA_STAT has been set. It's promised
		 * that this should occur within about 10 us, but like BSD,
		 * we'll try for up to 100 ms for this queue.
		 */
		for (j = 0; j < I40E_RING_WAIT_NTRIES; j++) {
			reg = I40E_READ_REG(hw, I40E_QTX_ENA(i));

			if (reg & I40E_QTX_ENA_QENA_STAT_MASK)
				break;
			i40e_msec_delay(I40E_RING_WAIT_PAUSE);
		}

		if ((reg & I40E_QTX_ENA_QENA_STAT_MASK) == 0) {
			i40e_error(i40e, "failed to enable tx queue %d, timed "
			    "out", i);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

void
i40e_stop(i40e_t *i40e, boolean_t free_allocations)
{
	int i;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	/*
	 * Shutdown and drain the tx and rx pipeline. We do this using the
	 * following steps.
	 *
	 * 1) Shutdown interrupts to all the queues (trying to keep the admin
	 *    queue alive).
	 *
	 * 2) Remove all of the interrupt tx and rx causes by setting the
	 *    interrupt linked lists to zero.
	 *
	 * 2) Shutdown the tx and rx rings. Because i40e_shutdown_rings() should
	 *    wait for all the queues to be disabled, once we reach that point
	 *    it should be safe to free associated data.
	 *
	 * 4) Wait 50ms after all that is done. This ensures that the rings are
	 *    ready for programming again and we don't have to think about this
	 *    in other parts of the driver.
	 *
	 * 5) Disable remaining chip interrupts, (admin queue, etc.)
	 *
	 * 6) Verify that FM is happy with all the register accesses we
	 *    performed.
	 */
	i40e_intr_io_disable_all(i40e);
	i40e_intr_io_clear_cause(i40e);

	if (i40e_shutdown_rings(i40e) == B_FALSE) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_LOST);
	}

	delay(50 * drv_usectohz(1000));

	i40e_intr_chip_fini(i40e);

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		mutex_enter(&i40e->i40e_trqpairs[i].itrq_rx_lock);
		mutex_enter(&i40e->i40e_trqpairs[i].itrq_tx_lock);
	}

	/*
	 * We should consider refactoring this to be part of the ring start /
	 * stop routines at some point.
	 */
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_stats_trqpair_fini(&i40e->i40e_trqpairs[i]);
	}

	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_cfg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_LOST);
	}

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_tx_cleanup_ring(&i40e->i40e_trqpairs[i]);
	}

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		mutex_exit(&i40e->i40e_trqpairs[i].itrq_rx_lock);
		mutex_exit(&i40e->i40e_trqpairs[i].itrq_tx_lock);
	}

	i40e_stat_vsi_fini(i40e);

	i40e->i40e_link_speed = 0;
	i40e->i40e_link_duplex = 0;
	i40e_link_state_set(i40e, LINK_STATE_UNKNOWN);

	if (free_allocations) {
		i40e_free_ring_mem(i40e, B_FALSE);
	}
}

boolean_t
i40e_start(i40e_t *i40e, boolean_t alloc)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	boolean_t rc = B_TRUE;
	int i, err;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	if (alloc) {
		if (i40e_alloc_ring_mem(i40e) == B_FALSE) {
			i40e_error(i40e,
			    "Failed to allocate ring memory");
			return (B_FALSE);
		}
	}

	/*
	 * This should get refactored to be part of ring start and stop at
	 * some point, along with most of the logic here.
	 */
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		if (i40e_stats_trqpair_init(&i40e->i40e_trqpairs[i]) ==
		    B_FALSE) {
			int j;

			for (j = 0; j < i; j++) {
				i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[j];
				i40e_stats_trqpair_fini(itrq);
			}
			return (B_FALSE);
		}
	}

	if (!i40e_chip_start(i40e)) {
		i40e_fm_ereport(i40e, DDI_FM_DEVICE_INVAL_STATE);
		rc = B_FALSE;
		goto done;
	}

	if (i40e_setup_rx_rings(i40e) == B_FALSE) {
		rc = B_FALSE;
		goto done;
	}

	if (i40e_setup_tx_rings(i40e) == B_FALSE) {
		rc = B_FALSE;
		goto done;
	}

	/*
	 * Enable broadcast traffic; however, do not enable multicast traffic.
	 * That's handle exclusively through MAC's mc_multicst routines.
	 */
	err = i40e_aq_set_vsi_broadcast(hw, i40e->i40e_vsi_id, B_TRUE, NULL);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to set default VSI: %d", err);
		rc = B_FALSE;
		goto done;
	}

	err = i40e_aq_set_mac_config(hw, i40e->i40e_frame_max, B_TRUE, 0, NULL);
	if (err != I40E_SUCCESS) {
		i40e_error(i40e, "failed to set MAC config: %d", err);
		rc = B_FALSE;
		goto done;
	}

	/*
	 * Finally, make sure that we're happy from an FM perspective.
	 */
	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		rc = B_FALSE;
		goto done;
	}

	/* Clear state bits prior to final interrupt enabling. */
	atomic_and_32(&i40e->i40e_state,
	    ~(I40E_ERROR | I40E_STALL | I40E_OVERTEMP));

	i40e_intr_io_enable_all(i40e);

done:
	if (rc == B_FALSE) {
		i40e_stop(i40e, B_FALSE);
		if (alloc == B_TRUE) {
			i40e_free_ring_mem(i40e, B_TRUE);
		}
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_LOST);
	}

	return (rc);
}

/*
 * We may have loaned up descriptors to the stack. As such, if we still have
 * them outstanding, then we will not continue with detach.
 */
static boolean_t
i40e_drain_rx(i40e_t *i40e)
{
	mutex_enter(&i40e->i40e_rx_pending_lock);
	while (i40e->i40e_rx_pending > 0) {
		if (cv_reltimedwait(&i40e->i40e_rx_pending_cv,
		    &i40e->i40e_rx_pending_lock,
		    drv_usectohz(I40E_DRAIN_RX_WAIT), TR_CLOCK_TICK) == -1) {
			mutex_exit(&i40e->i40e_rx_pending_lock);
			return (B_FALSE);
		}
	}
	mutex_exit(&i40e->i40e_rx_pending_lock);

	return (B_TRUE);
}

static int
i40e_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	i40e_t *i40e;
	struct i40e_osdep *osdep;
	i40e_hw_t *hw;
	int instance;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(devinfo);
	i40e = kmem_zalloc(sizeof (i40e_t), KM_SLEEP);

	i40e->i40e_aqbuf = kmem_zalloc(I40E_ADMINQ_BUFSZ, KM_SLEEP);
	i40e->i40e_instance = instance;
	i40e->i40e_dip = devinfo;

	hw = &i40e->i40e_hw_space;
	osdep = &i40e->i40e_osdep_space;
	hw->back = osdep;
	osdep->ios_i40e = i40e;

	ddi_set_driver_private(devinfo, i40e);

	i40e_fm_init(i40e);
	i40e->i40e_attach_progress |= I40E_ATTACH_FM_INIT;

	if (pci_config_setup(devinfo, &osdep->ios_cfg_handle) != DDI_SUCCESS) {
		i40e_error(i40e, "Failed to map PCI configurations.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_PCI_CONFIG;

	i40e_identify_hardware(i40e);

	if (!i40e_regs_map(i40e)) {
		i40e_error(i40e, "Failed to map device registers.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_REGS_MAP;

	i40e_init_properties(i40e);
	i40e->i40e_attach_progress |= I40E_ATTACH_PROPS;

	if (!i40e_common_code_init(i40e, hw))
		goto attach_fail;
	i40e->i40e_attach_progress |= I40E_ATTACH_COMMON_CODE;

	/*
	 * When we participate in IRM, we should make sure that we register
	 * ourselves with it before callbacks.
	 */
	if (!i40e_alloc_intrs(i40e, devinfo)) {
		i40e_error(i40e, "Failed to allocate interrupts.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_ALLOC_INTR;

	if (!i40e_alloc_trqpairs(i40e)) {
		i40e_error(i40e,
		    "Failed to allocate receive & transmit rings.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_ALLOC_RINGSLOCKS;

	if (!i40e_map_intrs_to_vectors(i40e)) {
		i40e_error(i40e, "Failed to map interrupts to vectors.");
		goto attach_fail;
	}

	if (!i40e_add_intr_handlers(i40e)) {
		i40e_error(i40e, "Failed to add the interrupt handlers.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_ADD_INTR;

	if (!i40e_final_init(i40e)) {
		i40e_error(i40e, "Final initialization failed.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_INIT;

	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_cfg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_LOST);
		goto attach_fail;
	}

	if (!i40e_stats_init(i40e)) {
		i40e_error(i40e, "Stats initialization failed.");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_STATS;

	if (!i40e_register_mac(i40e)) {
		i40e_error(i40e, "Failed to register to MAC/GLDv3");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_MAC;

	i40e->i40e_periodic_id = ddi_periodic_add(i40e_timer, i40e,
	    I40E_CYCLIC_PERIOD, DDI_IPL_0);
	if (i40e->i40e_periodic_id == 0) {
		i40e_error(i40e, "Failed to add the link-check timer");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_LINK_TIMER;

	if (!i40e_enable_interrupts(i40e)) {
		i40e_error(i40e, "Failed to enable DDI interrupts");
		goto attach_fail;
	}
	i40e->i40e_attach_progress |= I40E_ATTACH_ENABLE_INTR;

	atomic_or_32(&i40e->i40e_state, I40E_INITIALIZED);

	mutex_enter(&i40e_glock);
	list_insert_tail(&i40e_glist, i40e);
	mutex_exit(&i40e_glock);

	return (DDI_SUCCESS);

attach_fail:
	i40e_unconfigure(devinfo, i40e);
	return (DDI_FAILURE);
}

static int
i40e_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	i40e_t *i40e;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	i40e = (i40e_t *)ddi_get_driver_private(devinfo);
	if (i40e == NULL) {
		i40e_log(NULL, "i40e_detach() called with no i40e pointer!");
		return (DDI_FAILURE);
	}

	if (i40e_drain_rx(i40e) == B_FALSE) {
		i40e_log(i40e, "timed out draining DMA resources, %d buffers "
		    "remain", i40e->i40e_rx_pending);
		return (DDI_FAILURE);
	}

	mutex_enter(&i40e_glock);
	list_remove(&i40e_glist, i40e);
	mutex_exit(&i40e_glock);

	i40e_unconfigure(devinfo, i40e);

	return (DDI_SUCCESS);
}

static struct cb_ops i40e_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops i40e_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	i40e_attach,		/* devo_attach */
	i40e_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&i40e_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power,		/* devo_power */
	ddi_quiesce_not_supported /* devo_quiesce */
};

static struct modldrv i40e_modldrv = {
	&mod_driverops,
	i40e_ident,
	&i40e_dev_ops
};

static struct modlinkage i40e_modlinkage = {
	MODREV_1,
	&i40e_modldrv,
	NULL
};

/*
 * Module Initialization Functions.
 */
int
_init(void)
{
	int status;

	list_create(&i40e_glist, sizeof (i40e_t), offsetof(i40e_t, i40e_glink));
	list_create(&i40e_dlist, sizeof (i40e_device_t),
	    offsetof(i40e_device_t, id_link));
	mutex_init(&i40e_glock, NULL, MUTEX_DRIVER, NULL);
	mac_init_ops(&i40e_dev_ops, I40E_MODULE_NAME);

	status = mod_install(&i40e_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&i40e_dev_ops);
		mutex_destroy(&i40e_glock);
		list_destroy(&i40e_dlist);
		list_destroy(&i40e_glist);
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i40e_modlinkage, modinfop));
}

int
_fini(void)
{
	int status;

	status = mod_remove(&i40e_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&i40e_dev_ops);
		mutex_destroy(&i40e_glock);
		list_destroy(&i40e_dlist);
		list_destroy(&i40e_glist);
	}

	return (status);
}
