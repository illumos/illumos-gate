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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Intel I225/226 Ethernet Driver
 * ------------------------------
 *
 * This driver implements support for the Intel I225 and I226 Ethernet
 * controllers which support up to 2.5 GbE and generally only supports BASE-T
 * copper phys. This device is yet another variant on the venerable Intel 1 GbE
 * devices that are found in e1000g(4D) and igb(4D). This is its own driver in
 * part because that's how Intel did things and refactored their common code
 * which we import and is found in the 'core' directory.
 *
 * There is not a good datasheet for the MAC that we've been able to find for
 * this part. It's not clear that Intel even has a doc for this in their
 * Resource and Design Center. The primary datasheet documents the NVM and other
 * parts of it, but not the software interface. Based on observations from the
 * common code we describe this as somewhat of an evolution of the I217 and
 * I210, with less features than the I210, which comes from the server world
 * (which ws itself a more stripped down I350).
 *
 * The result of all this is us trying to focus on what we know about this part
 * and making some assumptions along the way. This includes things like:
 *
 * 1) We believe that the device only supports up to 4 RX and TX queues.
 * 2) There is only one TX context for each TX queue and it is mapped to the
 * queue.
 * 3) There is no support for the head writeback modes that we've found.
 * 4) This does otherwise support both the MSI-X and MSI/INTx interrupt
 * management which are shaped very differently in the device.
 * 5) The 2500BASE-T PHY support is unique, but the other PHY settings are
 * roughly the same as far as we can tell.
 *
 * There are certainly more differences than the points up above, but the above
 * are ones that generally influence our design.
 *
 * ------------
 * Organization
 * ------------
 *
 * This driver is first broken into two different pieces. There is the 'core'
 * code which we import from Intel via FreeBSD. All of these sources are in the
 * 'uts/common/io/igc/core' directory and we try our hardest to avoid modifying
 * them (hence the smatch gags). The core code can be thought of as abstracting
 * the MAC, NVM, and PHY across different chipsets (right now it's all the I225)
 * and providing us with a series of library calls that we can do to manage the
 * chip.
 *
 * The remaining files that sit alongside this one implement different portions
 * of functionality related to the device. In particular:
 *
 *  igc.[ch]:		This is the main entry point for the driver and the
 *			source of this block comment. It implements all of the
 *			basic DDI entry points: attach and detach, interrupts,
 *			PCI config space and register set up and tear down.
 *
 *			The header file contains all of the structure
 *			definitions that we use throughout this and the basic
 *			constants we use for sizing.
 *
 *  igc_gld.c		This file implements all of the major GLDv3 required
 *			entry points that are found in mac(9E). The guts of the
 *			actual I/O are in igc_ring.c, but getting and setting
 *			all of the various MAC properties and other bits is
 *			here.
 *
 *  igc_osdep.[ch]	The osdep (OS dependent) files, are used to define and
 *			implement the functionality required by the common code.
 *			igc_osdep.h is included in the build of each file.
 *
 *			We have a second use for igc_osdep.h which is where we
 *			put missing hardware definitions that apply. This is for
 *			cases where the core code doesn't have it and it should
 *			really live in igc_defines.h or igc_regs.h, but we keep
 *			it here to avoid modifying those.
 *
 *  igc_ring.c		This implements the core I/O routines of the device
 *			driver, starting with the descriptor ring setup and tear
 *			down as well as DMA, descriptor ring, and per-frame
 *			memory. It also implements all of the primary logic for
 *			transmitting and receiving frames.
 *
 *  igc_stat.c		This file deals with kstat creation and destruction as
 *			well as reading and fetching all of the registers that
 *			exist in hardware.
 *
 * There are a few primary data structures to be aware of. Their relationships
 * are shown in the following image and then described. Note, each structure has
 * many more fields than those pictured:
 *
 * +---------------+
 * | dev_info_t *  |
 * |              -|-+
 * | private data  | |
 * +---------------+ v
 *   +------------------------------+        +---------------------+
 *   | igc_t                        |        | igc_addr_t          |
 *   | per-instance primary         |  +---->|                     |
 *   | structure                    |  |+--->| Notes a MAC address | ...
 *   |                              |  ||    | stored in hardware  |
 *   | igc_addr_t    *igc_ucast    -|--+|    +---------------------+
 *   | igc_addr_t    *igc_mcast    -|---+      +---------------------------+
 *   | struct igc_hw *igc_hw       -|--------->| struct igc_hw (core code) |
 *   | igc_tx_ring_t *igc_tx_rings -|--+       |                           |
 *   | igc_rx_ring_t *igc_rx_rings -|--|---+   | igc_mac_info mac          |
 *   +------------------------------+  |   |   | igc_fc_info  fc           |
 *                                     |   |   | igc_phy_info phy          |
 *  +----------------------------------+   |   | igc_nvm_info nvm          |
 *  |                                      v   +---------------------------+
 *  |  +--------------------------------------+
 *  |  | igc_rx_ring_t                        |
 *  |  |                                      |
 *  |  | igc_adv_rx_desc *irr_ring         ---|--> rx hw descriptor ring
 *  |  | uint32_t        irr_next          ---|--> next entry to look for data
 *  |  | igc_rx_buffer_t **irr_work_list   ---|--> corresponds to ring entries
 *  |  | uint32_t        irr_nfree         ---|--> number of free list entries
 *  |  | igc_rx_buffer_t **irr_free_list   ---|--> set of buffers free for bind
 *  |  | igc_rx_buffer_t *irr_arena        ---|-+> array of all rx buffers
 *  |  +--------------------------------------+ |
 *  |                                           |
 *  |          +----------------------------+   |
 *  |          | igc_rx_buffer_t            |<--+
 *  |          |                            |
 *  |          | mblk_t            *igb_mp -|---> mblk_t for rx buffer
 *  |          | igc_dma_buffer_t  irb_dma -|---> DMA memory for rx buffer
 *  |          +----------------------------+
 *  |
 *  |   +------------------------------------+
 *  +-->| igc_tx_ring_t                      |
 *      |                                    |
 *      | icc_adv_tx_desc   *itr_ring      --|--> tx hw descriptor ring
 *      | uin32_t           itr_ring_head  --|--> next descriptor to recycle
 *      | uin32_t           itr_ring_fail  --|--> next descriptor to place
 *      | uin32_t           itr_ring_free  --|--> free descriptors in ring
 *      | igc_tx_buffer_t   **itr_work_list  |--> corresponds to ring entries
 *      | list_t            itr_free_list  --|--> available tx buffers
 *      | igc_tx_buffer_t   *itr_arena     --|-+> array of all tx buffers
 *      +------------------------------------+ |
 *                                             |
 *        +---------------------------------+  |
 *        | igc_tx_buffer_t                 |<-+
 *        |                                 |
 *        | mblk_t           *itb_mp      --|--> mblk to tx (only in first)
 *        | igc_dma_buffer_t itb_dma      --|--> tx DMA buffer for copy
 *        | ddi_dma_handle_t itb_bind_hdl --|--> DMA handle for bind
 *        +---------------------------------+
 *
 * igc_t		This is the primary data structure that exists for each
 *			instance of the driver. There is generally a 1:1
 *			relationship between a physical port, an instance of the
 *			driver, and a PCI function. This structure provides
 *			access to the device's registers and it embeds the
 *			common code's struct igc_hw.
 *
 * struct igc_hw	This structure is used by the core code and it contains
 *			information related to the MAC, PHY, NVM, and related
 *			information that the device uses. In general, this
 *			structure is used when performing API calls to the
 *			common code. The common code calls back into us in the
 *			igc_osdep.c interfaces.
 *
 * igc_tx_ring_t	This structure represents a single transmit ring in
 *			hardware, its associated software state, and
 *			miscellaneous data like statistics, MAC handles, etc.
 *			See the 'TX Data Path Design' section for more
 *			information.
 *
 * igc_rx_ring_t	This is the receive variant of a ring. It represents and
 *			tracks the hardware state along with all our metadata.
 *			One of these exists for each receive ring that we've
 *			enabled (currently one). See the 'RX Data Path Design'
 *			section for more information.
 *
 * igc_tx_buffer_t	This represents a single tx buffer in the driver. A tx
 *			buffer contains DMA based storage that it can use to
 *			transmit a packet and contains a second DMA handle that
 *			can be used to bind a specific mblk_t to it. tx buffers
 *			are capped at the current page size and can be smaller
 *			if the maximum packet size is smaller. A 1500 byte MTU
 *			will end up with a 2 KiB buffer due to the device's
 *			internal alignment requirements.
 *
 * igc_rx_buffer_t	This represents a single rx buffer in the driver. These
 *			buffers may be loaned up to MAC and then returned to us
 *			later. They contain a single DMA buffer which right now
 *			is a single contiguous buffer that fits the maximum
 *			packet size. Each buffer has a corresponding mblk_t that
 *			it is mapped to.
 *
 * igc_dma_buffer_t	This represent a DMA buffer in the system. DMA buffers
 *			are used for transmit buffers, receive buffers, or
 *			various ring descriptor entries. The DMA buffer
 *			structure is not inherently limited to a specific number
 *			of cookies. It is always mapped in our virtual address
 *			space and encapsulates the various DDI functions. In
 *			general, one expects to interface with the idb_va member
 *			when needing to access the memory, the idb_size member
 *			when wanting to understand how much memory is in the
 *			buffer, and the idb_hdl member when needing to access
 *			the DMA cookies.
 *
 * igc_addr_t		This represents a 48-bit Ethernet MAC address slot in
 *			the hardware that may or may not be used at any given
 *			point in time.
 *
 * --------------------
 * Rings and Interrupts
 * --------------------
 *
 * The I225/226 controller like the I210 supports up to 4 rx and tx rings. Due
 * to the long history of this controller and its tradition from the e1000g/igb
 * days and much older parts like the 8254x series, it has two entirely
 * different sets of interrupt modes. One where MSI-X is used and a mode where
 * a single MSI or INTx interrupt is used. Currently the driver only supports
 * the MSI-X mode as that gives us more flexibility and due to the fact that the
 * interrupt modes and register handling are different, reduces the complexity
 * in the driver.
 *
 * The hardware uses its IVAR registers to map specific queues to interrupts.
 * Each rx queue and tx queue is mapped to a specific bit position in the IVAR
 * and there is an additional IVAR register for miscellaneous causes like link
 * state changes. While the IVAR register allows for several bits for MSI-X
 * entries, for the most part, it appears that there is only support for values
 * in the range [0, 4] based on the I210 which we believe extends to the I225/6.
 *
 * MSI-X mode causes the device's various interrupt registers to be split into
 * two groups the 'legacy' and 'extended' (sometimes called advanced) ones. The
 * extended ones all start with 'E'. When in MSI-X mode, the EICR (cause), EICS
 * (cause set), EIAC (auto-clear), EIMS (mask set) registers all operate with
 * indexes that refer to the MSI-X. The primary way to temporarily disable
 * interrupts for polling is to remove the given MSI-X from the auto-clear set
 * and to clear it from the enabled mask set.
 *
 * The implication of all of this is that we can only really disable interrupts
 * for polling on a per-MSI-X basis. This generally means that the design for
 * interrupts and rings is that all the tx rings and the link state change
 * events share interrupt 0, while rx rings use interrupts 1-4. Because the x86
 * 'apix' modules end up defaulting to two interrupts to a driver, we end up
 * only supporting a single rx and tx ring for the time being, though the driver
 * is phrased in terms of a variable number of such rings.
 *
 * -------------------
 * RX Data Path Design
 * -------------------
 *
 * The rx data path is based around allocating a fixed number of receive buffers
 * for each ring. We have two goals in the allocation buffer and ring design:
 *
 * 1) We want to make sure that the ring is always full of valid descriptors for
 *    rx to prevent stalls. One implication of this is that we will always
 *    refill a received buffer with a new one and notify the hardware that the
 *    buffer is usable again.
 *
 * 2) We would prefer to not have to copy received memory and instead bind the
 *    DMA memory directly into an mblk_t.
 *
 * To satisfy (1) we need to allocate at least as many rx buffers as there are
 * ring entries. The ring is sized by default to 512 entries, which is a
 * somewhat arbitrary, but common, size. We then say that we want to be able to
 * loan half of our entries up the stack at any given time. This leads to us
 * allocating 1.5x the ring size rx buffers.
 *
 * All of the rx buffers are stored in the irr_arena array. They are then split
 * between the free list and the ring's work list. The work list is an array
 * that is a 1:1 mapping to a location in the descriptor ring. That is index 4
 * of the work list (irr_work_list[4]) corresponds to index 4 of the descriptor
 * ring (irr_ring[4]). However, this may refer to any of the rx descriptors that
 * is in the irr_arena. When we start up the ring, the first ring size entries
 * are all inserted into the work list and then the remaining entries are
 * inserted into the free list.
 *
 * Entries that are in the work list are always given to hardware. We track the
 * next place for us to scan for received packets through the 'irr_next' index
 * into the descriptor ring. When an interrupt fires, we start at irr_next and
 * iterate through the descriptor ring continuing while we find valid, received
 * packets. When we process a packet, we look at two things to consider whether
 * we bind it or copy it to a new mblk_t. The first piece is the received
 * packet's length. If the packet is small, there is not much value in binding
 * it and instead we just allocate and copy a new buffer for the packet.
 *
 * The second is if there are free rx descriptors. To keep goal (1) valid, we
 * only will loan a packet up if there is an entry on the free list that can
 * replace the rx buffer, as otherwise we'd want to make sure we don't stall the
 * ring. If an rx buffer is loaned, the entry on the free list takes its place
 * in the descriptor ring and when the networking stack is finally done with the
 * mblk_t, it'll be returned to us as part of the freemsg()/freeb() destructor.
 * This lifetime is illustrated in the following diagram:
 *
 *
 *    +-------------+                        +-----------+
 *    | Work List   |<---*-------------------| Free List |
 *    | Owned by HW |    . . Used to replace |   Idle    |
 *    +-------------+        loaned buffers  +-----------+
 *      |     | ^                                  ^
 *      |     | . . . Reused if a                  |
 *      |     +-+     copy is done                 . . . Returned to driver via
 *      |                                          |     freemsg() which calls
 *      |                                          |     igc_rx_recycle().
 *      v                                          |
 *    +-------------------+                        |
 *    | Loaned            |------------------------+
 *    | Owned by netstack |
 *    +-------------------+
 *
 * Currently the rx data path uses rx buffers that are equal to the maximum size
 * of a packet (rounded up based on hardware's 1 KiB alignment requirement).
 * This was mostly done for initial simplicity, though it comes at a memory
 * cost. It is possible to design this to be more like the tx subsystem where we
 * use fixed page size buffers and just cons up an mblk_t chain with b_cont
 * pointers.
 *
 * -------------------
 * TX Data Path Design
 * -------------------
 *
 * The tx data path is a bit different in design from the rx data path. When the
 * system wants to tx data there are two fundamental building blocks that we
 * use, both of which leverage the igc_tx_buffer_t:
 *
 * 1) We use the DMA memory that is allocated with the buffer and copy the
 *    mblk_t data into it. This is used when we have small mblk_t's.
 *
 * 2) We utilize the DMA handle that is in the tx buffer (but not the buffer's
 *    DMA memory) to perform DMA binding. This can result in multiple cookies
 *    and therefore descriptors mapping to the single buffer.
 *
 * Because a given tx buffer may end up using more than one descriptor and we
 * have to account for transmit context descriptors, which are used for
 * indicating checksum and segmentation offloads, we end up only allocating a
 * number of transmit buffers equal to the ring size. In addition, the tx data
 * buffer's maximum size is capped at the size of a single page. This is done
 * because we often aren't going to be copying and if we are, we don't need that
 * much more memory. The actual size may be smaller depending on the MTU.
 *
 * The tx descriptor ring is used in a bit of a different way. While part of the
 * reason for this is that we are filling it based on the stack's demands and
 * therefore only need to fill in descriptors when there's a need, the second
 * reason is because of how the hardware reports back events. There are two
 * major kinds of descriptors that can be entered into the ring. There are the
 * aforementioned context descriptors and then data descriptors. While data
 * descriptors support an interrupt on completion, context descriptors do not.
 *
 * When an mblk_t comes in to be transmitted, we walk all of the mblk_t's
 * associated with it via the b_cont pointer. For each one, we look at the size
 * of the data and determine whether or not to perform DMA binding or to copy it
 * into the current tx buffer. A given tx buffer can be used to copy multiple
 * different mblk_t's. Imagine a pathological case where we had a 500 byte
 * packet split into 125 byte chunks, this would end up using a single tx data
 * buffer.  However, if you imagine a large chunk of TCP data, this may be
 * spread across several mblk_t's so we may end up leveraging multiple tx data
 * buffers.
 *
 * The transmit buffers that are available are stored on a free list. This is
 * managed as a list_t as we end up needing to often track groups of descriptors
 * to allocate and free across packet transmit and recycling. We don't count the
 * number of transmit buffers that are free per se, but it generally tracks the
 * number of free descriptors which do track as in the worst case there is a 1:1
 * relationship between buffers and descriptors and more generally it's 1:n,
 * that is there are multiple descriptors used for a single buffer.
 *
 * The transmit ring is managed through a combination of three integers, the
 * itr_ring_head, the itr_ring_tail, and the itr_ring_free. The ring's tail
 * represents the place where the driver will place new data to transmit. The
 * ring's head represents the first place that we should check for a packet's
 * completion when we're performing recycling (the act of acknowledging what
 * hardware has processed internal to the driver) due to a tx interrupt or
 * manual recycling in the transmit path.
 *
 * When placing a packet as a series of descriptor rings we'll end up doing the
 * following:
 *
 * 1) First we determine how to map each mblk_t as mentioned above.
 * 2) This will then be turned into descriptors in the ring. Each tx data buffer
 *    that is used is placed in the itr_work_list at the corresponding index
 *    that they are used in the ring. There is one special case here, if a
 *    context descriptor is used, the first transmit buffer will refer to the
 *    context descriptor's entry (which always comes before data).
 * 3) We'll ensure that there are enough descriptors for this packet to fit into
 *    the ring or if it would exceed our mandatory gap threshold. If so, then
 *    we'll undo all the work we just did and return the mblk_t to MAC and
 *    indicate that the ring is blocked. MAC will be notified later when we free
 *    up transmit descriptors.
 * 4) In the first transmit data buffer we'll store both the mblk_t and then
 *    we'll store what the index of the last descriptor that's used is. This is
 *    important for recycling. We also indicate that the last descriptor should
 *    be the one that reports its status on interrupt completion.
 * 5) We'll notify hardware that there is data for it to transmit by writing to
 *    the ring's tail pointer.
 *
 * This all works reasonably okay, except for the small problem of the bill,
 * which we pay off in the form of recycling. Recycling is going through the
 * ring and seeing which descriptors are free. While the transmit path described
 * above is the only path that is allowed to move the tail, the recycling path
 * is the only one that's allowed to adjust the head.
 *
 * When we perform recycling we look at the current head and its corresponding
 * tx buffer. There will always be a tx buffer in the same index in the
 * itr_work_list[] unless a serious programmer error has occurred. This buffer
 * will tell us what the index to check for completion is via its itb_last_desc
 * member (only valid when itb_first is set to true). If this index indicates
 * that it has been processed by hardware, then we process all entries between
 * here and there.
 *
 * When we process descriptors, we bunch up the transmit descriptors and
 * mblk_t's. We'll reset the transmit descriptor (freeing any DMA binding if
 * used) and append the mblk_t if it exists to be freed in one large
 * freemsgchain() at the end. The fact that we won't free any tx buffers
 * associated with a packet until they're all done is important. This makes
 * sure that any memory that we have bound from the mblk_t remains valid the
 * entire time.
 *
 * If we have freed enough descriptors as part of this to allow mac to send data
 * again, then once we have finished all processing and dropped the lock, we
 * will notify MAC.
 *
 * When we are processing descriptors here we try to avoid holding the itr_lock
 * except for the start and end of the process. This is an important way to
 * ensure that we don't block transmits. Because of this, there can only be one
 * thread performing a recycle at any given time between the interrupt path and
 * the transmit path trying to clean up. This is maintained using the
 * 'itr_recycle' boolean. If a recycle is already in progress then there's
 * generally not much reason to perform one simultaneously and so the caller
 * will just return. This is why the head (and thus returning descriptors) is
 * only used by the recycle path.
 *
 * -------
 * Locking
 * -------
 *
 * Mutexes exist on three different structures in the driver:
 *
 * 1) igc_t (igc_lock)
 * 2) igc_rx_ring_t (irr_lock, irr_free_lock)
 * 3) igc_tx_ring_t (itr_lock)
 *
 * The following rules hold for locking in the driver:
 *
 * 1) One should not hold locks for both the rx rings and tx rings at the same
 *    time. If this is required, please determine if it is absolutely necessary.
 * 2) You should always take the controller's lock ahead of any ring's locks.
 * 3) The general rx ring lock (irr_lock) should be taken ahead of the free list
 *    lock (irr_free_lock) if both are required.
 *
 * -------------------
 * Future Improvements
 * -------------------
 *
 * This driver was initially written with an eye towards getting something that
 * had broad use for folks with this hardware and not towards enabling every
 * feature immediately. Here are some areas that can be improved upon in the
 * driver.
 *
 *  - Multiple ring, RSS support: As the OS changes towards offering more
 *    interrupts or opting to participate in IRM, then you can more easily
 *    offer RSS and related features. This should likely show up as a single
 *    rx group with multiple rings and leverage the tx pseudo-group support.
 *
 *  - TCP segmentation offload support: Right now the driver does not support
 *    TSO. It'd potentially be a useful addition and help out folks. Fetching
 *    information for TSO is in the tx data path right now.
 *
 *  - FMA Support: Currently the driver does not rig up support for FMA.
 *    Participating in that and more generally being able to reset the device
 *    while it is operating in the face of fatal errors would be good.
 *
 *  - TX stall detection: Related to the above, carefully designing a tx stall
 *    detection and resetting the device when that happens would probably be
 *    useful.
 *
 *  - UFM support: Exposing the NVM and PBA (printed board assembly) through the
 *    UFM subsystem would be a good thing to do.
 *
 *  - Dynamic MTU changing: Right now the driver takes advantage of the
 *    simplification of not allowing the MTU to change once the device has been
 *    started. This isn't great, but it is far from the first (igb, e1000g,
 *    ixgbe, etc.) to do this. It would be nice if this was lifted.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/bitext.h>

#include "igc.h"

/*
 * The core code expects the igc_mcast_raw to be a uint8_t packed array. We use
 * the ether_addr_t to make this a little more explicit and easy to reason
 * about, but that means we are relying on this size.
 */
CTASSERT(sizeof (ether_addr_t) == 6);

uint32_t
igc_read32(igc_t *igc, uint32_t reg)
{
	uint32_t *addr;
	ASSERT3U(reg, <, igc->igc_regs_size);
	addr = (uint32_t *)(igc->igc_regs_base + reg);
	return (ddi_get32(igc->igc_regs_hdl, addr));
}

void
igc_write32(igc_t *igc, uint32_t reg, uint32_t val)
{
	uint32_t *addr;
	ASSERT3U(reg, <, igc->igc_regs_size);
	addr = (uint32_t *)(igc->igc_regs_base + reg);
	ddi_put32(igc->igc_regs_hdl, addr, val);
}

/*
 * Ask hardware if the link is up and ready. Note, this assumes that we're on a
 * copper phy and short circuits a few things. See igb_is_link_up() for what
 * this looks like for non-copper PHYs if that ever becomes relevant.
 */
static bool
igc_link_up(igc_t *igc)
{
	ASSERT(MUTEX_HELD(&igc->igc_lock));

	/*
	 * When the link is up, then the core code will clear the value below.
	 * Otherwise we likely need to assume it's down.
	 */
	(void) igc_check_for_link(&igc->igc_hw);
	return (!igc->igc_hw.mac.get_link_status);
}

static void
igc_intr_lsc(igc_t *igc)
{
	link_state_t orig_state, new_state;
	uint32_t mmd_base;

	mutex_enter(&igc->igc_lock);
	orig_state = igc->igc_link_state;

	/*
	 * Always force a check of the link.
	 */
	igc->igc_hw.mac.get_link_status = true;
	if (igc_link_up(igc)) {
		uint16_t duplex = 0;

		(void) igc_get_speed_and_duplex(&igc->igc_hw,
		    &igc->igc_link_speed, &duplex);

		switch (duplex) {
		case HALF_DUPLEX:
			igc->igc_link_duplex = LINK_DUPLEX_HALF;
			break;
		case FULL_DUPLEX:
			igc->igc_link_duplex = LINK_DUPLEX_FULL;
			break;
		default:
			igc->igc_link_duplex = LINK_DUPLEX_UNKNOWN;
			break;
		}
		igc->igc_link_state = LINK_STATE_UP;
	} else {
		igc->igc_link_state = LINK_STATE_DOWN;
		igc->igc_link_speed = 0;
		igc->igc_link_duplex = LINK_DUPLEX_UNKNOWN;
	}
	new_state = igc->igc_link_state;

	/*
	 * Next, grab a bunch of information from the PHY for future us.
	 */
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_CONTROL, &igc->igc_phy_ctrl);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_STATUS, &igc->igc_phy_status);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_AUTONEG_ADV,
	    &igc->igc_phy_an_adv);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_LP_ABILITY,
	    &igc->igc_phy_lp);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_AUTONEG_EXP,
	    &igc->igc_phy_an_exp);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_1000T_CTRL,
	    &igc->igc_phy_1000t_ctrl);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_1000T_STATUS,
	    &igc->igc_phy_1000t_status);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_EXT_STATUS,
	    &igc->igc_phy_ext_status);
	(void) igc_read_phy_reg(&igc->igc_hw, PHY_EXT_STATUS,
	    &igc->igc_phy_ext_status);

	mmd_base = STANDARD_AN_REG_MASK << MMD_DEVADDR_SHIFT;
	(void) igc_read_phy_reg(&igc->igc_hw, mmd_base | ANEG_MULTIGBT_AN_CTRL,
	    &igc->igc_phy_mmd_ctrl);
	(void) igc_read_phy_reg(&igc->igc_hw, mmd_base | ANEG_MULTIGBT_AN_STS1,
	    &igc->igc_phy_mmd_sts);
	mutex_exit(&igc->igc_lock);

	if (orig_state != new_state) {
		mac_link_update(igc->igc_mac_hdl, new_state);
	}
}

static uint_t
igc_intr_rx_queue(caddr_t arg1, caddr_t arg2)
{
	igc_t *igc = (igc_t *)arg1;
	uintptr_t queue = (uintptr_t)arg2;
	igc_rx_ring_t *ring;
	mblk_t *mp = NULL;

	ASSERT3U(queue, <, igc->igc_nrx_rings);
	ring = &igc->igc_rx_rings[queue];

	mutex_enter(&ring->irr_lock);
	if ((ring->irr_flags & IGC_RXR_F_POLL) == 0) {
		mp = igc_ring_rx(ring, IGC_RX_POLL_INTR);
	}
	mutex_exit(&ring->irr_lock);

	if (mp != NULL) {
		mac_rx_ring(igc->igc_mac_hdl, ring->irr_rh, mp, ring->irr_gen);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
igc_intr_tx_other(caddr_t arg1, caddr_t arg2)
{
	igc_t *igc = (igc_t *)arg1;
	uint32_t icr = igc_read32(igc, IGC_ICR);

	igc_tx_recycle(igc, &igc->igc_tx_rings[0]);

	if ((icr & IGC_ICR_LSC) != 0) {
		igc_intr_lsc(igc);
	}

	return (DDI_INTR_CLAIMED);
}

static bool
igc_setup_regs(igc_t *igc)
{
	int ret;
	ddi_device_acc_attr_t da;

	if (pci_config_setup(igc->igc_dip, &igc->igc_cfgspace) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to map config space");
		return (false);
	}

	if (ddi_dev_regsize(igc->igc_dip, IGC_PCI_BAR, &igc->igc_regs_size) !=
	    DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get BAR %u size",
		    IGC_PCI_BAR - 1);
		return (false);
	}

	bzero(&da, sizeof (ddi_device_acc_attr_t));
	da.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	da.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	da.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	da.devacc_attr_access = DDI_DEFAULT_ACC;

	if ((ret = ddi_regs_map_setup(igc->igc_dip, IGC_PCI_BAR,
	    &igc->igc_regs_base, 0, igc->igc_regs_size, &da,
	    &igc->igc_regs_hdl)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to map registers: %d",
		    ret);
		return (false);
	}

	return (true);
}

/*
 * Go through the process of initializing the igc core code. First we have to
 * fill in the information that the common code requires to identify the
 * hardware and set the mac type. After that we can go through and set up all of
 * the function initialization.
 */
static bool
igc_core_code_init(igc_t *igc)
{
	int ret;
	int *regs;
	uint_t nprop;

	igc->igc_hw.back = igc;
	igc->igc_hw.vendor_id = pci_config_get16(igc->igc_cfgspace,
	    PCI_CONF_VENID);
	igc->igc_hw.device_id = pci_config_get16(igc->igc_cfgspace,
	    PCI_CONF_DEVID);
	igc->igc_hw.revision_id = pci_config_get8(igc->igc_cfgspace,
	    PCI_CONF_REVID);
	igc->igc_hw.subsystem_vendor_id = pci_config_get16(igc->igc_cfgspace,
	    PCI_CONF_SUBVENID);
	igc->igc_hw.subsystem_device_id = pci_config_get16(igc->igc_cfgspace,
	    PCI_CONF_SUBSYSID);

	if ((ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, igc->igc_dip,
	    DDI_PROP_DONTPASS, "reg", &regs, &nprop)) != DDI_PROP_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to look up 'reg' "
		    "property: %d", ret);
		return (false);
	}

	/*
	 * We fill out the function and command word. We currently don't fill
	 * out the bus type, speed, and width as it's not used by the common
	 * code, leaving it all at unknown. We can grab that information when it
	 * needs it. We do fill out the function and command word as the former
	 * is important and the latter is easy to grab.
	 */
	igc->igc_hw.bus.func = PCI_REG_FUNC_G(regs[0]);
	igc->igc_hw.bus.pci_cmd_word = pci_config_get16(igc->igc_cfgspace,
	    PCI_CONF_COMM);
	ddi_prop_free(regs);

	/*
	 * The common code asks for the memory mapped address to be set in its
	 * structure. Though in theory it promises not to use it.
	 */
	igc->igc_hw.hw_addr = (uint8_t *)igc->igc_regs_base;

	if ((ret = igc_set_mac_type(&igc->igc_hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to set mac type: %d",
		    ret);
		return (false);
	}

	if ((ret = igc_setup_init_funcs(&igc->igc_hw, true)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to setup core code "
		    "function pointers: %d", ret);
		return (false);
	}

	/*
	 * Go ahead and attempt to get the bus information even though this
	 * doesn't actually do anything right now.
	 */
	if ((ret = igc_get_bus_info(&igc->igc_hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "core code failed to get bus "
		    "info: %d", ret);
		return (false);
	}

	return (true);
}

static bool
igc_limits_init(igc_t *igc)
{
	switch (igc->igc_hw.mac.type) {
	case igc_i225:
		igc->igc_limits.il_max_rx_rings = IGC_MAX_RX_RINGS_I225;
		igc->igc_limits.il_max_tx_rings = IGC_MAX_RX_RINGS_I225;
		igc->igc_limits.il_max_mtu = IGC_MAX_MTU_I225;
		break;
	default:
		dev_err(igc->igc_dip, CE_WARN, "unknown MAC type: %u",
		    igc->igc_hw.mac.type);
		return (false);
	}

	return (true);
}

/*
 * Determine the hardware buffer sizes that are required for the given MTU.
 * There are a few different constraints that we try to enforce here that come
 * from the hardware and others that come from us:
 *
 * 1) The hardware requires that the rx and tx sizes all be 1 KiB (0x400) byte
 * aligned.
 * 2) Our tx engine can handle copying across multiple descriptors, so we cap
 * the maximum tx buffer size at one page.
 * 3) Right now our rx engine does not handle scanning multiple buffers for rx
 * (see the theory statement), so we end up making the rx buffer have to fix the
 * maximum frame size.
 * 4) rx buffers need to also account for IP alignment, so we make sure to
 * allocate extra bytes for that.
 */
void
igc_hw_buf_update(igc_t *igc)
{
	unsigned long pagesize = ddi_ptob(igc->igc_dip, 1);
	uint32_t tx_mtu;

	igc->igc_max_frame = igc->igc_mtu + sizeof (struct ether_vlan_header) +
	    ETHERFCSL;
	igc->igc_rx_buf_size = P2ROUNDUP_TYPED(igc->igc_max_frame +
	    IGC_RX_BUF_IP_ALIGN, IGC_BUF_ALIGN, uint32_t);
	tx_mtu = P2ROUNDUP_TYPED(igc->igc_max_frame, IGC_BUF_ALIGN, uint32_t);
	igc->igc_tx_buf_size = MIN(tx_mtu, pagesize);
}

static bool
igc_intr_init(igc_t *igc)
{
	int ret, types, nintrs, navail, req;
	const int min_nintrs = 2;

	if ((ret = ddi_intr_get_supported_types(igc->igc_dip, &types)) !=
	    DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get supported "
		    "interrupts: %d", ret);
		return (false);
	}

	/*
	 * For now, we simplify our lives and device support by only supporting
	 * MSI-X interrupts. When we find versions of this without MSI-X
	 * support, we can go and add what we need.
	 */
	if ((types & DDI_INTR_TYPE_MSIX) == 0) {
		dev_err(igc->igc_dip, CE_WARN, "device does not support MSI-X, "
		    "found %d", types);
		return (false);
	}

	if ((ret = ddi_intr_get_nintrs(igc->igc_dip, DDI_INTR_TYPE_MSIX,
	    &nintrs)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get number of "
		    "supported MSI-X interrupts: %d", ret);
		return (false);
	}

	if (nintrs < min_nintrs) {
		dev_err(igc->igc_dip, CE_WARN, "igc driver currently requires "
		    "%d MSI-X interrupts be supported, found %d", min_nintrs,
		    nintrs);
		return (false);
	}

	if ((ret = ddi_intr_get_navail(igc->igc_dip, DDI_INTR_TYPE_MSIX,
	    &navail)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get number of "
		    "available MSI-X interrupts: %d", ret);
		return (false);
	}

	if (navail < min_nintrs) {
		dev_err(igc->igc_dip, CE_WARN, "igc driver currently requires "
		    "%d MSI-X interrupts be available, found %d", min_nintrs,
		    navail);
		return (false);
	}

	/*
	 * In the future this could be based upon the multiple queues that the
	 * device supports, but for now it's limited to two. See 'Rings and
	 * Interrupts' in the theory statement for more background.
	 */
	req = min_nintrs;
	req = MIN(req, navail);
	igc->igc_intr_size = req * sizeof (ddi_intr_handle_t);
	igc->igc_intr_handles = kmem_alloc(igc->igc_intr_size, KM_SLEEP);

	if ((ret = ddi_intr_alloc(igc->igc_dip, igc->igc_intr_handles,
	    DDI_INTR_TYPE_MSIX, 0, req, &igc->igc_nintrs,
	    DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to allocate interrupts: "
		    "%d", ret);
		return (false);
	}

	igc->igc_intr_type = DDI_INTR_TYPE_MSIX;
	igc->igc_attach |= IGC_ATTACH_INTR_ALLOC;
	if (igc->igc_nintrs < min_nintrs) {
		dev_err(igc->igc_dip, CE_WARN, "received %d interrupts, but "
		    "needed at least %d", igc->igc_nintrs, min_nintrs);
		return (false);
	}

	if ((ret = ddi_intr_get_pri(igc->igc_intr_handles[0],
	    &igc->igc_intr_pri)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get interrupt "
		    "priority: %d", ret);
		return (false);
	}

	if ((ret = ddi_intr_get_cap(igc->igc_intr_handles[0],
	    &igc->igc_intr_cap)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get interrupt "
		    "capabilities: %d", ret);
		return (false);
	}

	return (true);
}

/*
 * As part of allocating our rings we make the following assumptions about
 * interrupt assignments. All tx rings share interrupt 0. All rx rings have
 * separate interrupts starting from interrupt 1. This design may likely change
 * in the face of actual multi-ring support
 */
static bool
igc_rings_alloc(igc_t *igc)
{
	uint32_t intr = 0;
	igc->igc_tx_rings = kmem_zalloc(sizeof (igc_tx_ring_t) *
	    igc->igc_ntx_rings, KM_SLEEP);

	for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
		igc->igc_tx_rings[i].itr_igc = igc;
		igc->igc_tx_rings[i].itr_idx = i;
		igc->igc_tx_rings[i].itr_intr_idx = intr;
		mutex_init(&igc->igc_tx_rings[i].itr_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(igc->igc_intr_pri));
		if (!igc_tx_ring_stats_init(igc, &igc->igc_tx_rings[i])) {
			return (false);
		}
	}

	igc->igc_rx_rings = kmem_zalloc(sizeof (igc_rx_ring_t) *
	    igc->igc_nrx_rings, KM_SLEEP);
	intr = 1;

	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++, intr++) {
		igc->igc_rx_rings[i].irr_igc = igc;
		igc->igc_rx_rings[i].irr_idx = i;
		igc->igc_rx_rings[i].irr_intr_idx = intr;
		mutex_init(&igc->igc_rx_rings[i].irr_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(igc->igc_intr_pri));
		mutex_init(&igc->igc_rx_rings[i].irr_free_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igc->igc_intr_pri));
		cv_init(&igc->igc_rx_rings[i].irr_free_cv, NULL, CV_DRIVER,
		    NULL);
		if (!igc_rx_ring_stats_init(igc, &igc->igc_rx_rings[i])) {
			return (false);
		}
	}

	ASSERT3U(intr, ==, igc->igc_nintrs);

	return (true);
}

/*
 * Allocate our interrupts. Note, we have more or less constrained the device
 * right now to only request two interrupts which we use in a fixed way. If we
 * end up with more varied queue support then this should be changed around.
 */
static bool
igc_intr_hdlr_init(igc_t *igc)
{
	int ret;

	if ((ret = ddi_intr_add_handler(igc->igc_intr_handles[0],
	    igc_intr_tx_other, igc, NULL)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to add tx/other "
		    "interrupt handler: %d", ret);
		return (false);
	}

	if ((ret = ddi_intr_add_handler(igc->igc_intr_handles[1],
	    igc_intr_rx_queue, igc, (uintptr_t)0)) != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to add rx interrupt "
		    "handler: %d", ret);
		if ((ret = ddi_intr_remove_handler(igc->igc_intr_handles[0])) !=
		    DDI_SUCCESS) {
			dev_err(igc->igc_dip, CE_WARN, "failed to remove "
			    "tx/other interrupt handler");
		}
		return (false);
	}

	return (true);
}

static void
igc_hw_control(igc_t *igc, bool take)
{
	uint32_t ctrl = igc_read32(igc, IGC_CTRL_EXT);

	if (take) {
		ctrl |= IGC_CTRL_EXT_DRV_LOAD;
	} else {
		ctrl &= ~IGC_CTRL_EXT_DRV_LOAD;
	}

	igc_write32(igc, IGC_CTRL_EXT, ctrl);
}

/*
 * Basic device initialization and sanity check. This covers that we can
 * properly reset the device, validate its checksum, and get a valid MAC
 * address.
 */
static bool
igc_hw_init(igc_t *igc)
{
	int ret;
	uint32_t eecd;

	if ((ret = igc_reset_hw(&igc->igc_hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to reset device: %d",
		    ret);
		return (false);
	}

	/*
	 * Goodbye firmware.
	 */
	igc_hw_control(igc, true);

	/*
	 * Check the NVM validiity if a device is present.
	 */
	eecd = igc_read32(igc, IGC_EECD);
	if ((eecd & IGC_EECD_EE_DET) != 0) {
		if ((ret = igc_validate_nvm_checksum(&igc->igc_hw)) !=
		    IGC_SUCCESS) {
			dev_err(igc->igc_dip, CE_WARN, "failed to validate "
			    "igc NVM checksum: %d", ret);
			return (false);
		}
	}

	if ((ret = igc_read_mac_addr(&igc->igc_hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to read MAC address: %d",
		    ret);
		return (false);
	}

	if ((ret = igc_get_phy_id(&igc->igc_hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to get PHY id: %d", ret);
		return (false);
	}

	return (true);
}

/*
 * In case the user has modified the LED state through MAC_CAPAB_LED, restore
 * that back to the defaults we got when we started up the device.
 */
static void
igc_led_fini(igc_t *igc)
{
	igc_write32(igc, IGC_LEDCTL, igc->igc_ledctl);
}

/*
 * Traditionally the Intel NIC drivers avoid touching activity pins as part of
 * their behavior for what we use. We also don't touch a pin if it's in SDP mode
 * and not being used to drive an LED as it means it's likely not for us.
 */
static bool
igc_led_ignore(i225_led_mode_t mode)
{
	switch (mode) {
	case I225_LED_M_FILTER_ACT:
	case I225_LED_M_LINK_ACT:
	case I225_LED_M_SDP:
	case I225_LED_M_PAUSE:
	case I225_LED_M_ACT:
		return (true);
	default:
		return (false);
	}
}

static inline uint32_t
igc_led_bitoff(uint32_t led)
{
	VERIFY3U(led, <, 3);
	return (led * 8);
}

static inline uint32_t
igc_led_get_mode(uint32_t led, uint32_t reg)
{
	uint32_t off = igc_led_bitoff(led);
	return (bitx32(reg, 3 + off, off));
}

static inline uint32_t
igc_led_set_mode(uint32_t led, uint32_t reg, i225_led_mode_t mode)
{
	uint32_t off = igc_led_bitoff(led);
	return (bitset32(reg, 3 + off, off, mode));
}

static inline uint32_t
igc_led_get_ivrt(uint32_t led, uint32_t reg)
{
	uint32_t off = igc_led_bitoff(led) + 6;
	return (bitx32(reg, off, off));
}

static inline uint32_t
igc_led_set_blink(uint32_t led, uint32_t reg, bool en)
{
	uint32_t off = igc_led_bitoff(led) + 7;
	return (bitset32(reg, off, off, en));
}

/*
 * There are three LEDs on the chip. The reference defines LED0 for 1 GbE link
 * up, LED1 for a 2.5GbE link up, and LED 2 for activity. However, this is all
 * controllable in the NVM so we shouldn't assume that these have any of their
 * default values. We instead read the LEDCTL register to see how it was set up
 * by default (though the NVM would likely be better). We then create pre-canned
 * LEDCTL register values for on, off, and default. See igc_osdep.h for some of
 * the caveats in definitions here. Note, we only tweak the non-activity LEDs
 * and if an LED has been indicated that it's being used for SDP, we don't touch
 * it.
 */
static void
igc_led_init(igc_t *igc)
{
	uint32_t led = igc_read32(igc, IGC_LEDCTL);

	igc->igc_ledctl = led;
	igc->igc_ledctl_on = led;
	igc->igc_ledctl_off = led;
	igc->igc_ledctl_blink = led;

	for (uint32_t i = 0; i < IGC_I225_NLEDS; i++) {
		i225_led_mode_t mode = igc_led_get_mode(i, led);
		if (!igc_led_ignore(mode)) {
			/*
			 * If the inversion logic is on, that changes what the
			 * on and off modes mean, so we need to change how we
			 * set that appropriately.
			 */
			if (igc_led_get_ivrt(i, led) != 0) {
				igc->igc_ledctl_on = igc_led_set_mode(i,
				    igc->igc_ledctl_on, I225_LED_M_OFF);
				igc->igc_ledctl_off = igc_led_set_mode(i,
				    igc->igc_ledctl_off, I225_LED_M_ON);
				igc->igc_ledctl_blink = igc_led_set_mode(i,
				    igc->igc_ledctl_blink, I225_LED_M_OFF);
			} else {
				igc->igc_ledctl_on = igc_led_set_mode(i,
				    igc->igc_ledctl_on, I225_LED_M_ON);
				igc->igc_ledctl_off = igc_led_set_mode(i,
				    igc->igc_ledctl_off, I225_LED_M_OFF);
				igc->igc_ledctl_blink = igc_led_set_mode(i,
				    igc->igc_ledctl_blink, I225_LED_M_ON);
			}
		}

		igc->igc_ledctl_blink = igc_led_set_blink(i,
		    igc->igc_ledctl_blink, true);
	}

	igc->igc_led_mode = MAC_LED_DEFAULT;
}

static void
igc_write_ivar(igc_t *igc, uint32_t queue, bool rx, uint32_t msix)
{
	const uint32_t ivarno = queue >> 1;
	const uint32_t reg = IGC_IVAR0 + ivarno * 4;
	const uint32_t val = msix | IGC_IVAR_VALID;
	uint32_t bitoff, bitend, ivar;

	if (rx) {
		if ((queue % 2) == 0) {
			bitoff = IGC_IVAR_RX0_START;
		} else {
			bitoff = IGC_IVAR_RX1_START;
		}
	} else {
		if ((queue % 2) == 0) {
			bitoff = IGC_IVAR_TX0_START;
		} else {
			bitoff = IGC_IVAR_TX1_START;
		}
	}
	bitend = bitoff + IGC_IVAR_ENT_LEN - 1;

	ivar = igc_read32(igc, reg);
	ivar = bitset32(ivar, bitend, bitoff, val);
	igc_write32(igc, reg, ivar);
	igc->igc_eims |= 1 << msix;
}

/*
 * Here we need to go through and initialize the hardware's notion of how
 * interrupts are mapped to causes. The device must be specifically enabled for
 * MSI-X and then this is also where we go ensure that all of our interrupt
 * coalescing is properly enabled. Note, we must first touch the GPIE register
 * to enable MSI-X settings otherwise later settings won't do anything.
 */
static void
igc_hw_intr_init(igc_t *igc)
{
	uint32_t gpie, ivar;

	gpie = IGC_GPIE_NSICR | IGC_GPIE_MSIX_MODE | IGC_GPIE_EIAME |
	    IGC_GPIE_PBA;
	igc_write32(igc, IGC_GPIE, gpie);

	/*
	 * Other causes are always explicitly mapped to cause 0. Each ring then
	 * has its own mapping. In the MISC IVAR, these start at bit 8. We leave
	 * the '0 |' out below just to avoid a compiler complaining. We also
	 * must unamsk this interrupt cause, which is in bit 0.
	 */
	ivar = IGC_IVAR_VALID << 8;
	igc_write32(igc, IGC_IVAR_MISC, ivar);
	igc->igc_eims = 1;

	/*
	 * There are a few IVAR registers available in hardware. Each IVAR
	 * register handles mapping a given queue to an MSI-X. Each IVAR handles
	 * two queues.
	 */
	for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
		igc_write_ivar(igc, i, false,
		    igc->igc_tx_rings[i].itr_intr_idx);
	}

	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_write_ivar(igc, i, true, igc->igc_rx_rings[i].irr_intr_idx);
	}

	for (uint32_t i = 0; i < igc->igc_nintrs; i++) {
		igc_write32(igc, IGC_EITR(i), igc->igc_eitr);
	}
}

/*
 * Synchronize our sense of the unicast table over to the device. If this is the
 * first time that we're here due to attach, we need to go through and allocate
 * the tracking table.
 */
static void
igc_unicast_sync(igc_t *igc)
{
	ASSERT(MUTEX_HELD(&igc->igc_lock));

	if (igc->igc_ucast == NULL) {
		igc->igc_nucast = igc->igc_hw.mac.rar_entry_count;
		igc->igc_ucast = kmem_zalloc(sizeof (igc_addr_t) *
		    igc->igc_nucast, KM_SLEEP);
	}

	for (uint16_t i = 0; i < igc->igc_nucast; i++) {
		int ret = igc_rar_set(&igc->igc_hw, igc->igc_ucast[i].ia_mac,
		    i);
		/*
		 * Common code today guarantees this can't fail. Put this here
		 * to ensure to guard against future updates.
		 */
		VERIFY3S(ret, ==, IGC_SUCCESS);
	}

}

/*
 * The core code interface to the multicast table requires us to give them a
 * packed uint8_t array that they manually walk through in ETHERADDRL (6 byte)
 * chunks. This must be packed. To deal with this we opt to preserve a normal
 * list of multicast addresses and then a secondary version that's serialized as
 * the core code wants it. We allocate the memory for this secondary version at
 * the start.
 */
void
igc_multicast_sync(igc_t *igc)
{
	uint16_t nvalid;

	ASSERT(MUTEX_HELD(&igc->igc_lock));

	if (igc->igc_mcast == NULL) {
		igc->igc_nmcast = igc->igc_hw.mac.mta_reg_count;
		igc->igc_mcast = kmem_zalloc(sizeof (igc_addr_t) *
		    igc->igc_nmcast, KM_SLEEP);
		igc->igc_mcast_raw = kmem_alloc(sizeof (ether_addr_t) *
		    igc->igc_nmcast, KM_SLEEP);
	}

	bzero(igc->igc_mcast_raw, sizeof (ether_addr_t) * igc->igc_nmcast);
	nvalid = 0;
	for (uint16_t i = 0; i < igc->igc_nmcast; i++) {
		ether_addr_t *targ = &igc->igc_mcast_raw[nvalid];

		if (!igc->igc_mcast[i].ia_valid)
			continue;
		bcopy(igc->igc_mcast[i].ia_mac, targ, sizeof (ether_addr_t));
		nvalid++;
	}

	igc_update_mc_addr_list(&igc->igc_hw, (uint8_t *)igc->igc_mcast_raw,
	    nvalid);
}

/*
 * This function is used to reinitialize the PBA, our various flow control
 * settings, reset hardware, ensure that the EEE, DPLU, and related power modes
 * are in the correct state.
 */
bool
igc_hw_common_init(igc_t *igc)
{
	int ret;
	uint32_t pba, hwm, hwmp, hwm2x;
	struct igc_hw *hw = &igc->igc_hw;

	/*
	 * The PBA register determines which portion is used for the receive
	 * buffers and which is used for the transmit buffers. This follows from
	 * the I210 and reference drivers which use 34K as the default. We
	 * currently leave the RXPBS and TXPBS at their power-on-reset defaults.
	 *
	 * We set the watermark based settings similar to igb, ensuring that we
	 * have 16-byte granularity. The general guidelines from there was that
	 * when it comes to automatic Ethernet PAUSE frame generation we should:
	 *
	 * - After an XOFF, you want to receive at least two frames. We use
	 *   whichever is smaller of 9/10ths and two frames.
	 * - The low water mark apparently wants to be closer to the high water
	 *   mark.
	 *
	 * See igb_init_adapter() for more information. We basically use the
	 * same calculation it did, given that the MAC is basically the same.
	 */
	pba = IGC_PBA_34K;
	hwmp = (pba << 10) * 9 / 10;
	hwm2x = (pba << 10) - 2 * igc->igc_max_frame;
	hwm = MIN(hwmp, hwm2x);

	hw->fc.high_water = hwm & 0xfffffff0;
	hw->fc.low_water = igc->igc_hw.fc.high_water - 16;

	/*
	 * Use the suggested default pause time.
	 */
	hw->fc.pause_time = IGC_FC_PAUSE_TIME;
	hw->fc.send_xon = true;

	if ((ret = igc_reset_hw(hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to reset device: %d",
		    ret);
		return (false);
	}

	if ((ret = igc_init_hw(hw)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to init hardware: %d",
		    ret);
		return (false);
	}

	/*
	 * Clear wake on LAN and set other power states. In addition, disable
	 * EEE for now.
	 */
	igc_write32(igc, IGC_WUC, 0);

	if ((ret = igc_set_d0_lplu_state(hw, false)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to set D0 LPLU mode: %d",
		    ret);
		return (false);
	}

	/*
	 * There have been reports that enabling EEE for some 2.5G devices has
	 * led to issues with the I225/226. It's not entirely clear, but we
	 * default to disabling this like in igb/e1000g for now.
	 */
	if ((ret = igc_set_eee_i225(hw, false, false, false)) != IGC_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "failed to set EEE mode: %d",
		    ret);
		return (false);
	}

	igc_hw_intr_init(igc);

	mutex_enter(&igc->igc_lock);
	igc_unicast_sync(igc);
	igc_multicast_sync(igc);

	igc->igc_hw.mac.get_link_status = true;
	(void) igc_get_phy_info(hw);
	(void) igc_check_for_link(hw);
	mutex_exit(&igc->igc_lock);

	return (true);
}

static bool
igc_intr_en(igc_t *igc)
{
	int ret;

	if ((igc->igc_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
		ret = ddi_intr_block_enable(igc->igc_intr_handles,
		    igc->igc_nintrs);
		if (ret != DDI_SUCCESS) {
			dev_err(igc->igc_dip, CE_WARN, "failed to block "
			    "enable interrupts: %d", ret);
			return (false);
		}
	} else {
		for (int i = 0; i < igc->igc_nintrs; i++) {
			ret = ddi_intr_enable(igc->igc_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				dev_err(igc->igc_dip, CE_WARN, "failed to "
				    "enable interrupt %d: %d", i, ret);
				for (int clean = 0; clean < i; clean++) {
					ret = ddi_intr_disable(
					    igc->igc_intr_handles[clean]);
					if (ret != DDI_SUCCESS) {
						dev_err(igc->igc_dip, CE_WARN,
						    "failed to disable "
						    "interrupt %d while "
						    "unwinding: %d", i, ret);
					}
				}
				return (false);
			}
		}
	}

	/*
	 * Now that we've enabled interrupts here, clear any pending interrupts
	 * and make sure hardware interrupts are enabled.
	 */
	(void) igc_read32(igc, IGC_ICR);

	return (true);
}

/*
 * Undo interrupt enablement.
 */
void
igc_hw_intr_disable(igc_t *igc)
{
	igc_write32(igc, IGC_EIMC, UINT32_MAX);
	igc_write32(igc, IGC_EIAC, 0);
	igc_write32(igc, IGC_IMC, UINT32_MAX);
}

/*
 * This is used during the GLDv3 mc_start(9E) entry point to enable interrupts
 * on the device itself.
 */
void
igc_hw_intr_enable(igc_t *igc)
{
	uint32_t ims;

	/*
	 * First we clear pending interrupts.
	 */
	(void) igc_read32(igc, IGC_ICR);

	/*
	 * The hardware has extended and non-extended interrupt masks and
	 * auto-clear registers. We always disable auto-clear for the
	 * non-extended portions. See the I210 datasheet 'Setting Interrupt
	 * Registers' for a better sense of what's going on here.
	 *
	 * In the IMS register we always register link status change events and
	 * device reset assertions.
	 */
	ims = IGC_IMS_LSC | IGC_IMS_DRSTA;

	igc_write32(igc, IGC_EIAC, igc->igc_eims);
	igc_write32(igc, IGC_EIMS, igc->igc_eims);
	igc_write32(igc, IGC_IMS, ims);
	igc_write32(igc, IGC_IAM, 0);
}

static void
igc_cleanup(igc_t *igc)
{
	if (igc->igc_mcast != NULL) {
		ASSERT3U(igc->igc_nmcast, !=, 0);
		kmem_free(igc->igc_mcast_raw, sizeof (ether_addr_t) *
		    igc->igc_nmcast);
		kmem_free(igc->igc_mcast, sizeof (igc_addr_t) *
		    igc->igc_nmcast);
		igc->igc_nmcast = 0;
		igc->igc_mcast = NULL;
	}

	if (igc->igc_ucast != NULL) {
		ASSERT3U(igc->igc_nucast, !=, 0);
		kmem_free(igc->igc_ucast, sizeof (igc_addr_t) *
		    igc->igc_nucast);
		igc->igc_nucast = 0;
		igc->igc_ucast = NULL;
	}

	if ((igc->igc_attach & IGC_ATTACH_INTR_EN) != 0) {
		int ret;
		if ((igc->igc_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
			ret = ddi_intr_block_disable(igc->igc_intr_handles,
			    igc->igc_nintrs);
			if (ret != DDI_SUCCESS) {
				dev_err(igc->igc_dip, CE_WARN, "failed to "
				    "block disable interrupts: %d", ret);
			}
		} else {
			for (int i = 0; i < igc->igc_nintrs; i++) {
				ret = ddi_intr_disable(
				    igc->igc_intr_handles[i]);
				if (ret != DDI_SUCCESS) {
					dev_err(igc->igc_dip, CE_WARN, "failed "
					    "to disable interrupt %d: %d", i,
					    ret);
				}
			}
		}
		igc->igc_attach &= ~IGC_ATTACH_INTR_EN;
	}

	if ((igc->igc_attach & IGC_ATTACH_MAC) != 0) {
		int ret = mac_unregister(igc->igc_mac_hdl);
		if (ret != 0) {
			dev_err(igc->igc_dip, CE_WARN, "failed to unregister "
			    "MAC handle: %d", ret);
		}
		igc->igc_attach &= ~IGC_ATTACH_MAC;
	}

	if ((igc->igc_attach & IGC_ATTACH_STATS) != 0) {
		igc_stats_fini(igc);
		igc->igc_attach &= ~IGC_ATTACH_STATS;
	}

	if ((igc->igc_attach & IGC_ATTACH_LED) != 0) {
		igc_led_fini(igc);
		igc->igc_attach &= ~IGC_ATTACH_LED;
	}

	if ((igc->igc_attach & IGC_ATTACH_INTR_HANDLER) != 0) {
		for (int i = 0; i < igc->igc_nintrs; i++) {
			int ret =
			    ddi_intr_remove_handler(igc->igc_intr_handles[i]);
			if (ret != 0) {
				dev_err(igc->igc_dip, CE_WARN, "failed to "
				    "remove interrupt %d handler: %d", i, ret);
			}
		}
		igc->igc_attach &= ~IGC_ATTACH_INTR_HANDLER;
	}

	if (igc->igc_tx_rings != NULL) {
		for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
			igc_tx_ring_stats_fini(&igc->igc_tx_rings[i]);
			mutex_destroy(&igc->igc_tx_rings[i].itr_lock);
		}
		kmem_free(igc->igc_tx_rings, sizeof (igc_tx_ring_t) *
		    igc->igc_ntx_rings);
		igc->igc_tx_rings = NULL;
	}

	if (igc->igc_rx_rings != NULL) {
		for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
			igc_rx_ring_stats_fini(&igc->igc_rx_rings[i]);
			cv_destroy(&igc->igc_rx_rings[i].irr_free_cv);
			mutex_destroy(&igc->igc_rx_rings[i].irr_free_lock);
			mutex_destroy(&igc->igc_rx_rings[i].irr_lock);
		}
		kmem_free(igc->igc_rx_rings, sizeof (igc_rx_ring_t) *
		    igc->igc_nrx_rings);
		igc->igc_rx_rings = NULL;
	}

	if ((igc->igc_attach & IGC_ATTACH_MUTEX) != 0) {
		mutex_destroy(&igc->igc_lock);
		igc->igc_attach &= ~IGC_ATTACH_MUTEX;
	}

	if ((igc->igc_attach & IGC_ATTACH_INTR_ALLOC) != 0) {
		for (int i = 0; i < igc->igc_nintrs; i++) {
			int ret = ddi_intr_free(igc->igc_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				dev_err(igc->igc_dip, CE_WARN, "unexpected "
				    "failure freeing interrupt %d: %d", i, ret);
			}
		}
		igc->igc_attach &= ~IGC_ATTACH_INTR_ALLOC;
	}

	if (igc->igc_intr_handles != NULL) {
		ASSERT3U(igc->igc_intr_size, !=, 0);
		kmem_free(igc->igc_intr_handles, igc->igc_intr_size);
	}

	/*
	 * Now that we're almost done, begrudgingly let firmware know we're
	 * done.
	 */
	igc_hw_control(igc, false);

	if (igc->igc_regs_hdl != NULL) {
		ddi_regs_map_free(&igc->igc_regs_hdl);
		igc->igc_regs_base = NULL;
	}

	if (igc->igc_cfgspace != NULL) {
		pci_config_teardown(&igc->igc_cfgspace);
	}
	igc->igc_attach &= ~IGC_ATTACH_REGS;

	ddi_set_driver_private(igc->igc_dip, NULL);
	igc->igc_dip = NULL;

	VERIFY0(igc->igc_attach);

	kmem_free(igc, sizeof (igc_t));
}

static int
igc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	igc_t *igc;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	igc = kmem_zalloc(sizeof (igc_t), KM_SLEEP);
	ddi_set_driver_private(dip, igc);
	igc->igc_dip = dip;

	/*
	 * Initialize a few members that are not zero-based.
	 */
	igc->igc_link_duplex = LINK_DUPLEX_UNKNOWN;
	igc->igc_link_state = LINK_STATE_UNKNOWN;

	/*
	 * Set up all the register spaces that hardware requires.
	 */
	if (!igc_setup_regs(igc)) {
		goto err;
	}
	igc->igc_attach |= IGC_ATTACH_REGS;

	/*
	 * Setup the common code.
	 */
	if (!igc_core_code_init(igc)) {
		goto err;
	}

	if (!igc_limits_init(igc)) {
		goto err;
	}

	/*
	 * Go allocate and set up all of our interrupts.
	 */
	if (!igc_intr_init(igc)) {
		goto err;
	}

	/*
	 * Initialize our main mutex for the device now that we have an
	 * interrupt priority.
	 */
	mutex_init(&igc->igc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(igc->igc_intr_pri));
	igc->igc_attach |= IGC_ATTACH_MUTEX;

	/*
	 * We now want to determine the total number of rx and tx rings that we
	 * have based on our interrupt allocation so we can go through and
	 * perform the rest of the device setup that is required. The various
	 * queues that we have are mapped to a given MSI-X through the IVAR
	 * registers in the device. There is also an IVAR_MISC register that
	 * maps link state change events and other issues up to two vectors.
	 *
	 * There isn't strictly per-queue interrupt generation control. Instead,
	 * when in MSI-X mode, the device has an extended interrupt cause and
	 * mask register. The mask register allows us to mask the five bits
	 * described above.
	 *
	 * Because of all this we end up limiting the number of queues that we
	 * use to 2 for now: 1 for tx and 1 for rx. Interrupt 0 is for tx/other
	 * and 1 for rx.
	 */
	igc->igc_nrx_rings = 1;
	igc->igc_ntx_rings = 1;

	/*
	 * Default to a 1500 byte MTU.
	 */
	igc->igc_mtu = ETHERMTU;
	igc_hw_buf_update(igc);

	/*
	 * Initialize default descriptor limits and thresholds. We allocate 1.5
	 * times the number of rx descriptors so that way we can loan up to
	 * 1/3rd of them. We allocate an even number of tx descriptors.
	 */
	igc->igc_rx_ndesc = IGC_DEF_RX_RING_SIZE;
	igc->igc_tx_ndesc = IGC_DEF_TX_RING_SIZE;
	igc->igc_rx_nbuf = igc->igc_rx_ndesc + (igc->igc_rx_ndesc >> 1);
	igc->igc_tx_nbuf = igc->igc_tx_ndesc;
	igc->igc_rx_nfree = igc->igc_rx_nbuf - igc->igc_rx_ndesc;
	igc->igc_rx_intr_nframes = IGC_DEF_RX_RING_INTR_LIMIT;
	igc->igc_rx_bind_thresh = IGC_DEF_RX_BIND;
	igc->igc_tx_bind_thresh = IGC_DEF_TX_BIND;
	igc->igc_tx_notify_thresh = IGC_DEF_TX_NOTIFY_MIN;
	igc->igc_tx_recycle_thresh = IGC_DEF_TX_RECYCLE_MIN;
	igc->igc_tx_gap = IGC_DEF_TX_GAP;
	igc->igc_eitr = IGC_DEF_EITR;

	if (!igc_rings_alloc(igc)) {
		goto err;
	}

	if (!igc_intr_hdlr_init(igc)) {
		goto err;
	}
	igc->igc_attach |= IGC_ATTACH_INTR_HANDLER;

	/*
	 * Next reset the device before we begin initializing anything else. As
	 * part of this, validate the flash checksum if present. This is all
	 * initialization that we would only do once per device. Other
	 * initialization that we want to do after any reset is done is
	 * igc_hw_common_init().
	 */
	if (!igc_hw_init(igc)) {
		goto err;
	}

	igc_led_init(igc);
	igc->igc_attach |= IGC_ATTACH_LED;

	/*
	 * Snapshot our basic settings that users can eventually control in the
	 * device. We start with always enabling auto-negotiation and
	 * advertising the basic supported speeds. The I225v1 does have
	 * substantial problems with enabling 2.5G due to the fact that it
	 * doesn't maintain a proper inter-packet gap. Despite that, we default
	 * to enabling 2.5G for now as its supposedly not broken with all link
	 * partners and the NVM. We also don't have a way of actually
	 * identifying and mapping that to something in the driver today,
	 * unfortunately.
	 */
	igc->igc_hw.mac.autoneg = true;
	igc->igc_hw.phy.autoneg_wait_to_complete = false;
	igc->igc_hw.phy.autoneg_advertised = IGC_DEFAULT_ADV;
	igc->igc_hw.fc.requested_mode = igc_fc_default;
	igc->igc_hw.fc.current_mode = igc_fc_default;

	if (!igc_hw_common_init(igc)) {
		goto err;
	}

	if (!igc_stats_init(igc)) {
		goto err;
	}
	igc->igc_attach |= IGC_ATTACH_STATS;

	/*
	 * Register with MAC
	 */
	if (!igc_mac_register(igc)) {
		goto err;
	}
	igc->igc_attach |= IGC_ATTACH_MAC;

	/*
	 * Enable interrupts and get going.
	 */
	if (!igc_intr_en(igc)) {
		goto err;
	}
	igc->igc_attach |= IGC_ATTACH_INTR_EN;

	return (DDI_SUCCESS);

err:
	igc_cleanup(igc);
	return (DDI_FAILURE);
}

static int
igc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	igc_t *igc;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	igc = ddi_get_driver_private(dip);
	if (igc == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing igc_t");
		return (DDI_FAILURE);
	}

	igc_cleanup(igc);
	return (DDI_SUCCESS);
}

static struct cb_ops igc_cb_ops = {
	.cb_open = nulldev,
	.cb_close = nulldev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops igc_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = igc_attach,
	.devo_detach = igc_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &igc_cb_ops
};

static struct modldrv igc_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel I226/226 Ethernet Controller",
	.drv_dev_ops = &igc_dev_ops
};

static struct modlinkage igc_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &igc_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	mac_init_ops(&igc_dev_ops, IGC_MOD_NAME);

	if ((ret = mod_install(&igc_modlinkage)) != 0) {
		mac_fini_ops(&igc_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&igc_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&igc_modlinkage)) == 0) {
		mac_fini_ops(&igc_dev_ops);
	}

	return (ret);
}
