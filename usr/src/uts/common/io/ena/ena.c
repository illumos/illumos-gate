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

#include "ena_hw.h"
#include "ena.h"

/*
 * Elastic Network Adapter (ENA) Driver
 * ------------------------------------
 *
 * The ena driver provides support for the AWS ENA device, also
 * referred to as their "enhanced networking". This device is present
 * on "Nitro"-based instances. It presents itself with the following
 * PCI Vendor/Device IDs
 *
 *    o 1d0f:0ec2 -- ENA PF
 *    o 1d0f:1ec2 -- ENA PF (Reserved)
 *    o 1d0f:ec20 -- ENA VF
 *    o 1d0f:ec21 -- ENA VF (Reserved)
 *
 * This driver provides support for only the essential features needed
 * to drive traffic on an ENA device. Support for the following
 * features IS NOT currently implemented.
 *
 *    o Admin Queue Interrupts: queue completion events are always polled
 *    o FMA
 *    o Rx checksum offloads
 *    o Tx checksum offloads
 *    o Tx DMA bind (borrow buffers)
 *    o Rx DMA bind (loaned buffers)
 *    o TSO
 *    o RSS
 *    o Low Latency Queues (LLQ)
 *    o Support for different Tx completion policies
 *    o More controlled Tx recycling and Rx refill
 *
 * Even without these features the ena driver should perform
 * reasonably well.
 *
 * Driver vs. Hardware Types
 * -------------------------
 *
 * To properly communicate with the ENA device the driver must
 * populate memory (registers and buffers) with specific types. These
 * types are defined by the device and are found under the "common"
 * (ena_com) code of the AWS Linux and FreeBSD drivers [1]. We have
 * simplified this a bit by defining all device-specific types in the
 * ena_hw.h file. Furthermore, all device-specific types are given an
 * "enahw" prefix. This makes it clear when we are dealing with a
 * device type and when we are dealing with a driver type.
 *
 * [1]: https://github.com/amzn/amzn-drivers
 *
 * Groups, Rings (Queues), and Interrupts
 * --------------------------------------
 *
 * The ENA device presents one mac group. This single mac group
 * represents the single unicast address that this device represents
 * in your AWS instance. The ENA device presents no option for
 * configuring additional MAC addresses, multicast, or promisc mode --
 * you receive only what AWS wants you to receive.
 *
 * This single mac group may have one or more rings. The ENA driver
 * refers to rings as queues, for no special reason other than it was
 * the dominant language in the Linux and FreeBSD drivers, and it
 * spilled over into this port. The upper bound on number of queues is
 * presented by the device. However, we don't just go with whatever
 * number of queues the device reports; but rather we limit the queues
 * based on other factors such as an absolute maximum, number of
 * online CPUs, and number of available interrupts. The upper bound is
 * calculated by ena_set_max_io_queues(), and that is used and
 * possibly further restricted in ena_attach_intr_alloc(). As this
 * point, ultimately, it is the number of available interrupts (minus
 * one for the admin queue) that determines the number of queues: one
 * Tx and one Rx on each I/O interrupt.
 *
 * NOTE: Perhaps it is overly restrictive to limit the number of
 * queues to the number of I/O interrupts. Something worth considering
 * on larger instances if they present far less interrupts than they
 * do queues + CPUs.
 *
 * The ENA device presents MSI-X interrupts only. During attach the
 * driver queries the number of available interrupts and sets aside
 * one for admin/AENQ (vector 0) and the rest for I/O (vector 1 to N).
 * This means that a Tx/Rx queue at index 0 will map to vector 1, and
 * so on.
 *
 * NOTE: The ENA driver currently doesn't make full use of the Admin
 * Queue interrupt. This interrupt is used both to notify the driver
 * when a command response is ready, and when an async event is posted.
 * The ENA driver always polls the Admin Queue for responses.
 *
 * Tx Queue Workings
 * -----------------
 *
 * A single Tx queue (ena_txq_t) is made up of one submission queue
 * (SQ) and its paired completion queue (CQ). These two queues form a
 * logical descriptor ring which is used to send packets out of the
 * device -- where each SQ entry describes the packet to be sent
 * (enahw_tx_desc_t) and each CQ entry describes the result of sending
 * a packet (enahw_tx_cdesc_t). For this to work the host and device
 * must agree on which descriptors are currently owned by the host
 * (free for sending) and which are owned by the device (pending
 * device completion). This state is tracked on the host side via head
 * and tail indexes along with a phase value.
 *
 * The head and tail values represent the head and tail of the FIFO
 * queue of pending packets -- the next packet to be sent by the
 * device is head, and all descriptors up to tail are ready for
 * sending. The phase allows the host to determine which CQ
 * descriptors represent completed events when using per-SQ completion
 * events (as opposed to queue head pointer updates). As the queues
 * represent a logical ring buffer, the phase must alternate on
 * wrap-around. The device initializes the phase to zero, and the host
 * starts with a phase of 1. The first packet descriptor writes, and
 * their corresponding completions, are indicated with a phase of 1.
 *
 *
 * For example, the diagram below represents the SQ/CQ state after the
 * first 6 packets have been sent by the host and 2 of them have been
 * completed by the device (and these completions have been processed
 * by the driver). In this state the host could send 4 more packets
 * before needing to wait on completion events.
 *
 *
 *    +---+---+---+---+---+---+---+---+
 * SQ | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |   phase = 1
 *    +---+---+---+---+---+---+---+---+
 *                              ^
 *                              |
 *                            tail
 *            head
 *              |
 *              v
 *    +---+---+---+---+---+---+---+---+
 * CQ | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |   phase = 1
 *    +---+---+---+---+---+---+---+---+
 *
 *
 * The next diagram shows how the state changes as 5 more packets are
 * sent (for a total of 11) and 7 more are completed (for a total of
 * 9). Notice that as the SQ and CQ have wrapped around their phases
 * have been complemented. In this state the host could send 6 more
 * packets before needing to wait on completion events.
 *
 *    +---+---+---+---+---+---+---+---+
 * SQ | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 |   phase = 0
 *    +---+---+---+---+---+---+---+---+
 *                  ^
 *                  |
 *                tail
 *        head
 *          |
 *          v
 *    +---+---+---+---+---+---+---+---+
 * CQ | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |   phase = 0
 *    +---+---+---+---+---+---+---+---+
 *
 *
 * Currently, all packets are copied for Tx. At ring start we allocate
 * a Tx Control Buffer (TCB) for each queue descriptor. Each TCB has
 * DMA buffer associated with it; and each buffer is large enough to
 * hold the MTU. Therefore, Tx descriptors and TCBs currently have a
 * 1:1 mapping. When a packet is sent, the mblk's buffer is copied to
 * the TCB's DMA buffer, and a new descriptor is written to the SQ
 * describing said TCB buffer. If and when we add more advanced
 * features like DMA binding of mblks and TSO, this 1:1 guarantee will
 * no longer hold.
 *
 * Rx Queue Workings
 * -----------------
 *
 * In terms of implementing the logical descriptor ring, the Rx queues
 * are very much like the Tx queues. There is a paired SQ and CQ for
 * each logical ring. The difference is that in Rx the SQ is for
 * handing buffers to the device to fill, and the CQ is for describing
 * the contents of those buffers for a given received frame. At Rx
 * ring start we allocate a Rx Control Buffer (RCB) for each
 * descriptor in the ring. Each RCB has a DMA buffer associated with
 * it; and each buffer is large enough to hold the MTU. For each
 * received frame we copy the contents out of the RCB and into its own
 * mblk, immediately returning the RCB for reuse. As with Tx, this
 * gives us a simple 1:1 mapping currently, but if more advanced
 * features are implemented later this could change.
 *
 * Asynchronous Event Notification Queue (AENQ)
 * --------------------------------------------
 *
 * Each ENA device comes with a mechanism for sending out-of-band
 * notifications to the driver. This includes events like link state
 * changes, fatal errors, and a watchdog/keep alive signal. The AENQ
 * delivery mechanism is via interrupt, handled by the ena_aenq_work()
 * function, which dispatches via the eaenq_hdlrs table. If no handler
 * is registered, the ena_aenq_default_hdlr() handler is used. A given
 * device may not support all the different event types
 * (enahw_aenq_groups_t); and the driver may choose to enable a subset
 * of the supported events. During attach we call ena_aenq_configure()
 * to negotiate the supported/enabled events. The enabled group is
 * stored at ena_aenq_enabled_groups.
 *
 * Queues and Unsigned Wraparound
 * ------------------------------
 *
 * All the queues use a uint16_t value as their head/tail values, e.g.
 * the Rx queue's er_cq_head_idx value. You might notice that we only
 * ever increment these values, letting them perform implicit unsigned
 * integer wraparound. This is intended. This is the same behavior as
 * the common code, and seems to be what the hardware expects. Of
 * course, when accessing our own descriptor arrays we must make sure
 * to first perform a modulo of this value or risk running off into
 * space.
 *
 * Watchdog and Device Reset
 * -------------------------
 *
 * While the device is running, the driver periodically invokes a
 * watchdog function to check that all is well, and to reset the
 * device if not. The device will be reset if any of the following is
 * true:
 *
 *    o The device's status register fatal error bit is set. A device
 *      in this state will no longer process any queues;
 *    o No asynchronous event keepalives have been received for some
 *      time -- see ENA_DEVICE_KEEPALIVE_TIMEOUT_NS;
 *    o A Tx queue has remained blocked for some time -- see
 *      ENA_TX_STALL_TIMEOUT;
 *    o The device has requested, via an asynchronous event, that we
 *      perform a reset;
 *    o Driver code has detected an error and set the EN_STATE_ERROR
 *      bit in ena_state.
 *
 * There is a "fatal error" asynchronous event, but common code does
 * not use that as a reason to trigger a reset, and so neither do we.
 *
 * The global `ena_force_reset` variable can be used as a simple means
 * to trigger a reset during driver development and testing. If there
 * are multiple instances, it is likely that only one of them will
 * reset when this variable is changed to `true`.
 *
 * Attach Sequencing
 * -----------------
 *
 * Most drivers implement their attach/detach/cleanup functions as a
 * sequential stream of function calls used to allocate and initialize
 * resources in an order determined by the device's programming manual
 * combined with any requirements imposed by the kernel and its
 * relevant modules. These functions can become quite long. It is
 * often hard to see the order in which steps are taken, and even
 * harder to tell if detach/cleanup undoes them in the correct order,
 * or even if it undoes them at all! The only sure way to understand
 * the flow is to take good notes while closely inspecting each line
 * of code. Even then, it's easy for attach and detach to get out of
 * sync.
 *
 * Some more recent drivers have improved on this situation by using a
 * bit vector to track the sequence of events in attach/detach. Each
 * bit is declared in as an enum value, in the same order it is
 * expected attach would run, and thus detach would run in the exact
 * opposite order. This has three main benefits:
 *
 *    1. It makes it easier to determine sequence order at a
 *       glance.
 *
 *    2. It gives a better idea of what state the device is in during
 *       debugging (the sequence bit vector is kept with the instance
 *       state).
 *
 *    3. The detach function can verify that all sequence bits are
 *       cleared, indicating that everything done in attach was
 *       successfully undone.
 *
 * These are great improvements. However, the attach/detach functions
 * can still become unruly, and there is still no guarantee that
 * detach is done in opposite order of attach (this is not always
 * strictly required, but is probably the best way to write detach).
 * There is still a lot of boilerplate and chance for programmer
 * error.
 *
 * The ena driver takes the sequence idea a bit further, creating a
 * descriptor table of the attach sequence (ena_attach_tbl). This
 * table is used by attach/detach to generically, declaratively, and
 * programmatically enforce the precise sequence order and verify that
 * anything that is done is undone. This provides several benefits:
 *
 *    o Correct order is enforced implicitly by the descriptor table.
 *      It is impossible for the detach sequence to run in any other
 *      order other than opposite that of attach.
 *
 *    o It is obvious what the precise attach sequence is. While the
 *      bit vector enum helps a lot with this it doesn't prevent
 *      programmer error. With the sequence defined as a declarative
 *      table it makes it easy for the programmer to see the order and
 *      know it's followed exactly.
 *
 *    o It is impossible to modify the attach sequence without also
 *      specifying a callback for its dual in the detach sequence.
 *
 *    o Common and repetitive code like error checking, logging, and bit
 *      vector modification is eliminated and centralized, again
 *      reducing the chance of programmer error.
 *
 * The ena attach sequence is defined under ena_attach_seq_t. The
 * descriptor table is defined under ena_attach_tbl.
 */

/*
 * These are some basic data layout invariants on which development
 * assumptions where made.
 */
CTASSERT(sizeof (enahw_tx_data_desc_t) == 16);
CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_meta_desc_t));
CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (enahw_tx_meta_desc_t) == sizeof (enahw_tx_desc_t));

/*
 * Amazon does not specify the endianess of the ENA device. We assume
 * it's the same as the bus, and we assume the CPU/bus is always
 * little endian.
 */
#ifdef _BIG_ENDIAN
#error "ENA driver is little-endian only"
#endif

/*
 * These values are used to communicate the driver version to the AWS
 * hypervisor via the ena_set_host_info() function. We don't know what
 * exactly AWS does with this info, but it's fairly safe to assume
 * it's used solely for debug/informational purposes. The Linux driver
 * updates these values frequently as bugs are fixed and features are
 * added.
 */
#define	ENA_DRV_VER_MAJOR	1
#define	ENA_DRV_VER_MINOR	0
#define	ENA_DRV_VER_SUBMINOR	0

uint64_t ena_admin_cmd_timeout_ns = ENA_ADMIN_CMD_DEF_TIMEOUT_NS;

/*
 * Log an error message. We leave the destination (console or system
 * log) up to the caller
 */
void
ena_err(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ena != NULL && ena->ena_dip != NULL) {
		vdev_err(ena->ena_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

void
ena_panic(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ena != NULL && ena->ena_dip != NULL) {
		vdev_err(ena->ena_dip, CE_PANIC, fmt, ap);
	} else {
		vcmn_err(CE_PANIC, fmt, ap);
	}
	va_end(ap);
}

/*
 * Set this to true to enable debug messages.
 */
bool ena_debug = false;

/*
 * Log a debug message. We force all debug messages to go to the
 * system log.
 */
void
ena_dbg(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	if (ena_debug) {
		char msg[1024];

		va_start(ap, fmt);
		(void) vsnprintf(msg, sizeof (msg), fmt, ap);
		va_end(ap);

		if (ena != NULL && ena->ena_dip != NULL) {
			dev_err(ena->ena_dip, CE_NOTE, "!%s", msg);
		} else {
			cmn_err(CE_NOTE, "!%s", msg);
		}
	}
}

void
ena_trigger_reset(ena_t *ena, enahw_reset_reason_t reason)
{
	mutex_enter(&ena->ena_lock);
	ena->ena_reset_reason = reason;
	mutex_exit(&ena->ena_lock);
	atomic_or_32(&ena->ena_state, ENA_STATE_ERROR);
}

/*
 * Determine if a given feature is available on this device.
 */
bool
ena_is_feat_avail(ena_t *ena, const enahw_feature_id_t feat_id)
{
	VERIFY3U(feat_id, <=, ENAHW_FEAT_NUM);
	uint32_t mask = 1U << feat_id;

	/*
	 * The device attributes feature is always supported, as
	 * indicated by the common code.
	 */
	if (feat_id == ENAHW_FEAT_DEVICE_ATTRIBUTES)
		return (true);

	return ((ena->ena_supported_features & mask) != 0);
}

/*
 * Determine if a given capability is available on this device.
 */
bool
ena_is_cap_avail(ena_t *ena, const enahw_capability_id_t cap_id)
{
	VERIFY3U(cap_id, <=, ENAHW_CAP_NUM);
	uint32_t mask = 1U << cap_id;

	return ((ena->ena_capabilities & mask) != 0);
}

static bool
ena_device_reset(ena_t *ena, enum enahw_reset_reason_types reason)
{
	uint32_t rval, wval, reason_lsb, reason_msb;
	hrtime_t timeout, expired;

	rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);
	if ((rval & ENAHW_DEV_STS_READY_MASK) == 0) {
		ena_err(ena, "reset: device is not ready");
		return (false);
	}

	rval = ena_hw_bar_read32(ena, ENAHW_REG_CAPS);

	/*
	 * The device stores the reset timeout at 100ms resolution; we
	 * normalize that to nanoseconds.
	 */
	timeout = MSEC2NSEC(ENAHW_CAPS_RESET_TIMEOUT(rval) * 100);

	if (timeout == 0) {
		ena_err(ena, "device gave invalid (0) reset timeout");
		return (false);
	}

	expired = gethrtime() + timeout;

	wval = ENAHW_DEV_CTL_DEV_RESET_MASK;

	reason_lsb = ENAHW_RESET_REASON_LSB(reason);
	reason_msb = ENAHW_RESET_REASON_MSB(reason);

	wval |= (reason_lsb << ENAHW_DEV_CTL_RESET_REASON_SHIFT) &
	    ENAHW_DEV_CTL_RESET_REASON_MASK;
	if (ena_is_cap_avail(ena, ENAHW_CAP_EXTENDED_RESET_REASONS)) {
		wval |= (reason_msb << ENAHW_DEV_CTL_RESET_REASON_EXT_SHIFT) &
		    ENAHW_DEV_CTL_RESET_REASON_EXT_MASK;
	} else if (reason_msb != 0) {
		/* Fall back to "generic" which we know will fit */
		wval = ENAHW_DEV_CTL_DEV_RESET_MASK;
		wval |= (ENAHW_RESET_GENERIC <<
		    ENAHW_DEV_CTL_RESET_REASON_SHIFT) &
		    ENAHW_DEV_CTL_RESET_REASON_MASK;
	}

	ena_hw_bar_write32(ena, ENAHW_REG_DEV_CTL, wval);

	/*
	 * Make sure reset is in progress.
	 */
	for (;;) {
		rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);

		if ((rval & ENAHW_DEV_STS_RESET_IN_PROGRESS_MASK) != 0)
			break;

		if (gethrtime() > expired) {
			ena_err(ena, "device reset start timed out");
			return (false);
		}

		/* Sleep for 100 milliseconds. */
		delay(drv_usectohz(100 * 1000));
	}

	/*
	 * Reset the timeout counter for the next device request.
	 */
	expired = gethrtime() + timeout;

	/*
	 * Wait for the device reset to finish.
	 */
	ena_hw_bar_write32(ena, ENAHW_REG_DEV_CTL, 0);
	for (;;) {
		rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);

		if ((rval & ENAHW_DEV_STS_RESET_IN_PROGRESS_MASK) == 0) {
			break;
		}

		if (gethrtime() > expired) {
			ena_err(ena, "device reset timed out");
			return (false);
		}

		/* Sleep for 100 milliseconds. */
		delay(drv_usectohz(100 * 1000));
	}

	ena_dbg(ena, "device reset succeeded");

	return (true);
}

static bool
ena_attach_pci(ena_t *ena)
{
	ddi_acc_handle_t hdl;

	if (pci_config_setup(ena->ena_dip, &hdl) != 0) {
		return (false);
	}

	ena->ena_pci_hdl = hdl;
	ena->ena_pci_vid = pci_config_get16(hdl, PCI_CONF_VENID);
	ena->ena_pci_did = pci_config_get16(hdl, PCI_CONF_DEVID);
	ena->ena_pci_rev = pci_config_get8(hdl, PCI_CONF_REVID);
	ena->ena_pci_svid = pci_config_get16(hdl, PCI_CONF_SUBVENID);
	ena->ena_pci_sdid = pci_config_get16(hdl, PCI_CONF_SUBSYSID);
	ena_dbg(ena, "vid: 0x%x did: 0x%x rev: 0x%x svid: 0x%x sdid: 0x%x",
	    ena->ena_pci_vid, ena->ena_pci_did, ena->ena_pci_rev,
	    ena->ena_pci_svid, ena->ena_pci_sdid);

	return (true);
}

static void
ena_cleanup_pci(ena_t *ena, bool resetting)
{
	VERIFY0(resetting);
	pci_config_teardown(&ena->ena_pci_hdl);
}

static void
ena_cleanup_regs_map(ena_t *ena, bool resetting)
{
	VERIFY0(resetting);
	ddi_regs_map_free(&ena->ena_reg_hdl);
}

static bool
ena_attach_regs_map(ena_t *ena)
{
	int ret = 0;

	if (ddi_dev_regsize(ena->ena_dip, ENA_REG_NUMBER, &ena->ena_reg_size) !=
	    DDI_SUCCESS) {
		ena_err(ena, "failed to get register set %d size",
		    ENA_REG_NUMBER);
		return (false);
	}

	ena_dbg(ena, "register size: %ld", ena->ena_reg_size);
	bzero(&ena->ena_reg_attr, sizeof (ena->ena_reg_attr));
	ena->ena_reg_attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	ena->ena_reg_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	ena->ena_reg_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * This function can return several different failure values,
	 * so we make sure to capture its return value for the purpose
	 * of logging.
	 */
	ret = ddi_regs_map_setup(ena->ena_dip, ENA_REG_NUMBER,
	    &ena->ena_reg_base, 0, ena->ena_reg_size, &ena->ena_reg_attr,
	    &ena->ena_reg_hdl);

	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to map register set %d: %d",
		    ENA_REG_NUMBER, ret);
		return (false);
	}

	ena_dbg(ena, "registers mapped to base: 0x%p",
	    (void *)ena->ena_reg_base);

	return (true);
}

/*
 * Free any resources related to the admin submission queue.
 */
static void
ena_admin_sq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aq.ea_sq.eas_dma);
}

/*
 * Initialize the admin submission queue.
 */
static bool
ena_admin_sq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *dma = &aq->ea_sq.eas_dma;
	size_t size = aq->ea_qlen * sizeof (*aq->ea_sq.eas_entries);
	uint32_t addr_low, addr_high, wval;

	if (aq->ea_sq.eas_entries == NULL) {
		ena_dma_conf_t conf = {
			.edc_size = size,
			.edc_align = ENAHW_ADMIN_SQ_DESC_BUF_ALIGNMENT,
			.edc_sgl = 1,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = false,
		};

		if (!ena_dma_alloc(ena, dma, &conf, size)) {
			ena_err(ena, "failed to allocate DMA for Admin SQ");
			return (false);
		}

		ENA_DMA_VERIFY_ADDR(ena, dma->edb_cookie->dmac_laddress);
		aq->ea_sq.eas_entries = (void *)dma->edb_va;
	} else {
		ena_dma_bzero(dma);
	}

	aq->ea_sq.eas_tail = 0;
	aq->ea_sq.eas_phase = 1;
	aq->ea_sq.eas_dbaddr =
	    (uint32_t *)(ena->ena_reg_base + ENAHW_REG_ASQ_DB);
	addr_low = (uint32_t)(dma->edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(dma->edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_BASE_HI, addr_high);
	wval = ENAHW_ASQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENAHW_ASQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_sq.eas_entries));
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_CAPS, wval);

	return (true);
}

/*
 * Free any resources related to the admin completion queue.
 */
static void
ena_admin_cq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aq.ea_cq.eac_dma);
}

/*
 * Initialize the admin completion queue.
 */
static bool
ena_admin_cq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *dma = &aq->ea_cq.eac_dma;
	uint32_t addr_low, addr_high, wval;

	if (aq->ea_cq.eac_entries == NULL) {
		size_t size = aq->ea_qlen * sizeof (*aq->ea_cq.eac_entries);
		ena_dma_conf_t conf = {
			.edc_size = size,
			.edc_align = ENAHW_ADMIN_CQ_DESC_BUF_ALIGNMENT,
			.edc_sgl = 1,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = false,
		};

		if (!ena_dma_alloc(ena, dma, &conf, size)) {
			ena_err(ena, "failed to allocate DMA for Admin CQ");
			return (false);
		}

		ENA_DMA_VERIFY_ADDR(ena, dma->edb_cookie->dmac_laddress);
		aq->ea_cq.eac_entries = (void *)dma->edb_va;
	} else {
		ena_dma_bzero(dma);
	}

	aq->ea_cq.eac_head = 0;
	aq->ea_cq.eac_phase = 1;
	addr_low = (uint32_t)(dma->edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(dma->edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_BASE_HI, addr_high);
	wval = ENAHW_ACQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENAHW_ACQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_cq.eac_entries));
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_CAPS, wval);

	return (true);
}

void
ena_update_hints(ena_t *ena, enahw_device_hints_t *hints)
{
	ena->ena_device_hints.eh_mmio_read_timeout =
	    hints->edh_mmio_read_timeout;
	ena->ena_device_hints.eh_keep_alive_timeout =
	    hints->edh_keep_alive_timeout;
	ena->ena_device_hints.eh_tx_comp_timeout = hints->edh_tx_comp_timeout;
	ena->ena_device_hints.eh_missed_tx_reset_threshold =
	    hints->edh_missed_tx_reset_threshold;
	ena->ena_device_hints.eh_admin_comp_timeout =
	    hints->edh_admin_comp_timeout;
	ena->ena_device_hints.eh_max_tx_sgl = hints->edh_max_tx_sgl;
	ena->ena_device_hints.eh_max_rx_sgl = hints->edh_max_rx_sgl;
}

/*
 * We limit the max number of I/O queues based on several aspects of
 * the underlying hardware.
 *
 * 1. The absolute upper limit is set by ENAHW_MAX_NUM_IO_QUEUES,
 *    which comes from the common code and presumably is based on device
 *    constraints.
 *
 * 2. Next we latch the number of I/O queues to the number of online
 *    CPUs. The idea being that each queue is a parallel work stream,
 *    and having more queues than CPUs to flush them will not improve
 *    performance. The number of online CPUs can change dynamically,
 *    and that's okay, everything should still work fine, it just
 *    might not be ideal.
 *
 * 3. Next we latch the number of I/O queues to the smallest of the
 *    max Tx queues and max Rx queues. We could probably loosen this
 *    restriction in the future, and have separate max I/O queues for
 *    Tx and Rx. This is what Linux does, and seems like a fine place
 *    to start.
 */
static void
ena_set_max_io_queues(ena_t *ena)
{
	uint32_t max = ENAHW_MAX_NUM_IO_QUEUES;

	max = MIN(ncpus_online, max);
	/*
	 * Supposedly a device could present a different number of SQs
	 * and CQs. This driver is designed in a way that requires
	 * each SQ to have a corresponding and dedicated CQ (how would
	 * it work otherwise). Therefore, we must check both values
	 * and find the minimum between them.
	 */
	max = MIN(ena->ena_tx_max_sq_num, max);
	max = MIN(ena->ena_tx_max_cq_num, max);
	max = MIN(ena->ena_rx_max_sq_num, max);
	max = MIN(ena->ena_rx_max_cq_num, max);


	/* This shouldn't happen, but just in case. */
	if (max == 0) {
		max = 1;
	}

	ena->ena_max_io_queues = max;
}

/*
 * We require that an Rx or Tx buffer be able to hold the maximum MTU
 * along with the maximum frame header length. In this case we know
 * ENA is presenting us an Ethernet frame so we add the size of an
 * Ethernet VLAN header. Rx has the additional requirement of needing
 * additional margin for the sake of IP header alignment.
 */
static void
ena_update_buf_sizes(ena_t *ena)
{
	ena->ena_max_frame_hdr = sizeof (struct ether_vlan_header);
	ena->ena_max_frame_total = ena->ena_max_frame_hdr + ena->ena_mtu;
	ena->ena_tx_buf_sz = P2ROUNDUP_TYPED(ena->ena_max_frame_total,
	    ena->ena_page_sz, uint32_t);
	ena->ena_rx_buf_sz = P2ROUNDUP_TYPED(ena->ena_max_frame_total +
	    ENA_RX_BUF_IPHDR_ALIGNMENT, ena->ena_page_sz, uint32_t);
}

static bool
ena_get_hints(ena_t *ena)
{
	int ret;
	enahw_resp_desc_t resp;
	enahw_device_hints_t *hints = &resp.erd_resp.erd_get_feat.ergf_hints;

	ena_dbg(ena, "Requesting hints");

	bzero(&resp, sizeof (resp));
	ret = ena_get_feature(ena, &resp, ENAHW_FEAT_HW_HINTS,
	    ENAHW_FEAT_HW_HINTS_VER);

	if (ret == ENOTSUP) {
		/* In this case the device does not support querying hints */
		ena_dbg(ena, "Hints are unsupported");
		return (true);
	} else if (ret != 0) {
		ena_err(ena, "Error getting hints: %d", ret);
		return (false);
	}

	ena_update_hints(ena, hints);

	return (true);
}

static bool
ena_get_offloads(ena_t *ena)
{
	int ret = 0;
	enahw_resp_desc_t resp;
	enahw_feat_offload_t *feat = &resp.erd_resp.erd_get_feat.ergf_offload;

	ena->ena_tx_l3_ipv4_csum = false;

	ena->ena_tx_l4_ipv4_part_csum = false;
	ena->ena_tx_l4_ipv4_full_csum = false;
	ena->ena_tx_l4_ipv4_lso = false;

	ena->ena_tx_l4_ipv6_part_csum = false;
	ena->ena_tx_l4_ipv6_full_csum = false;
	ena->ena_tx_l4_ipv6_lso = false;

	ena->ena_rx_l3_ipv4_csum = false;
	ena->ena_rx_l4_ipv4_csum = false;
	ena->ena_rx_l4_ipv6_csum = false;
	ena->ena_rx_hash = false;

	bzero(&resp, sizeof (resp));
	ret = ena_get_feature(ena, &resp, ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG,
	    ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG_VER);

	if (ret == ENOTSUP) {
		/*
		 * In this case the device does not support querying
		 * for hardware offloads. We take that as a sign that
		 * the device provides no offloads.
		 */
		return (true);
	} else if (ret != 0) {
		ena_err(ena, "error getting stateless offload: %d", ret);
		return (false);
	}

	ena->ena_tx_l3_ipv4_csum = ENAHW_FEAT_OFFLOAD_TX_L3_IPV4_CSUM(feat);

	ena->ena_tx_l4_ipv4_part_csum =
	    ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_PART(feat);
	ena->ena_tx_l4_ipv4_full_csum =
	    ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL(feat);
	ena->ena_tx_l4_ipv4_lso = ENAHW_FEAT_OFFLOAD_TSO_IPV4(feat);

	ena->ena_tx_l4_ipv6_part_csum =
	    ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_PART(feat);
	ena->ena_tx_l4_ipv6_full_csum =
	    ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_FULL(feat);
	ena->ena_tx_l4_ipv6_lso = ENAHW_FEAT_OFFLOAD_TSO_IPV6(feat);

	ena->ena_rx_l3_ipv4_csum = ENAHW_FEAT_OFFLOAD_RX_L3_IPV4_CSUM(feat);
	ena->ena_rx_l4_ipv4_csum = ENAHW_FEAT_OFFLOAD_RX_L4_IPV4_CSUM(feat);
	ena->ena_rx_l4_ipv6_csum = ENAHW_FEAT_OFFLOAD_RX_L4_IPV6_CSUM(feat);
	return (true);
}

static int
ena_get_prop(ena_t *ena, char *propname, const int minval, const int maxval,
    const int defval)
{
	int value = ddi_prop_get_int(DDI_DEV_T_ANY, ena->ena_dip,
	    DDI_PROP_DONTPASS, propname, defval);

	if (value > maxval) {
		ena_err(ena, "user value %s=%d exceeded maximum, setting to %d",
		    propname, value, maxval);
		value = maxval;
	}

	if (value < minval) {
		ena_err(ena, "user value %s=%d below minimum, setting to %d",
		    propname, value, minval);
		value = minval;
	}

	return (value);
}

static bool
ena_set_mtu(ena_t *ena)
{
	int ret = 0;
	enahw_cmd_desc_t cmd;
	enahw_feat_mtu_t *feat = &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_mtu;
	enahw_resp_desc_t resp;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	feat->efm_mtu = ena->ena_mtu;

	if ((ret = ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_MTU,
	    ENAHW_FEAT_MTU_VER)) != 0) {
		ena_err(ena, "failed to set device MTU to %u: %d", ena->ena_mtu,
		    ret);
		return (false);
	}

	return (true);
}

static void
ena_get_link_config(ena_t *ena)
{
	enahw_resp_desc_t resp;
	enahw_feat_link_conf_t *feat =
	    &resp.erd_resp.erd_get_feat.ergf_link_conf;
	bool full_duplex;

	bzero(&resp, sizeof (resp));

	if (ena_get_feature(ena, &resp, ENAHW_FEAT_LINK_CONFIG,
	    ENAHW_FEAT_LINK_CONFIG_VER) != 0) {
		/*
		 * Some ENA devices do no support this feature. In
		 * those cases we report a 1Gbps link, full duplex.
		 * For the most accurate information on bandwidth
		 * limits see the official AWS documentation.
		 */
		ena->ena_link_speed_mbits = 1000;
		ena->ena_link_speeds = ENAHW_LINK_SPEED_1G;
		ena->ena_link_duplex = LINK_DUPLEX_FULL;
		ena->ena_link_autoneg = true;
		return;
	}

	ena->ena_link_speed_mbits = feat->eflc_speed;
	ena->ena_link_speeds = feat->eflc_supported;
	full_duplex = ENAHW_FEAT_LINK_CONF_FULL_DUPLEX(feat);
	ena->ena_link_duplex = full_duplex ? LINK_DUPLEX_FULL :
	    LINK_DUPLEX_HALF;
	ena->ena_link_autoneg = ENAHW_FEAT_LINK_CONF_AUTONEG(feat);
}

/*
 * Retrieve all configuration values which are modifiable via
 * ena.conf, and set ena_t members accordingly. While the conf values
 * have priority, they may be implicitly modified by the driver to
 * meet resource constraints on a given platform. If no value is
 * specified in the conf file, the driver will attempt to use the
 * largest value supported. While there should be no value large
 * enough, keep in mind that ena_get_prop() will cast the values to an
 * int.
 *
 * This function should be called after the device is initialized,
 * admin queue is established, and the hardware features/capabs have
 * been queried; it should be called before mac registration.
 */
static bool
ena_attach_read_conf(ena_t *ena)
{
	uint32_t gcv;	/* Greatest Common Value */

	/*
	 * We expect that the queue lengths are the same for both the
	 * CQ and SQ, but technically the device could return
	 * different lengths. For now the driver locks them together.
	 */
	gcv = min(ena->ena_rx_max_sq_num_descs, ena->ena_rx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_rxq_num_descs = ena_get_prop(ena, ENA_PROP_RXQ_NUM_DESCS,
	    ENA_PROP_RXQ_NUM_DESCS_MIN, gcv, gcv);

	ena->ena_rxq_intr_limit = ena_get_prop(ena, ENA_PROP_RXQ_INTR_LIMIT,
	    ENA_PROP_RXQ_INTR_LIMIT_MIN, ENA_PROP_RXQ_INTR_LIMIT_MAX,
	    ENA_PROP_RXQ_INTR_LIMIT_DEF);

	gcv = min(ena->ena_tx_max_sq_num_descs, ena->ena_tx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_txq_num_descs = ena_get_prop(ena, ENA_PROP_TXQ_NUM_DESCS,
	    ENA_PROP_TXQ_NUM_DESCS_MIN, gcv, gcv);

	return (true);
}

/*
 * Perform any necessary device configuration after the driver.conf
 * has been read.
 */
static bool
ena_attach_dev_cfg(ena_t *ena)
{
	ASSERT3U(ena->ena_attach_seq, >=, ENA_ATTACH_READ_CONF);

	if (!ena_set_mtu(ena)) {
		/*
		 * We don't expect this to fail, but we try a fallback
		 * first before failing the attach sequence.
		 */
		ena->ena_mtu = 1500;
		ena_err(ena, "trying fallback MTU: %u", ena->ena_mtu);

		if (!ena_set_mtu(ena)) {
			return (false);
		}
	}

	return (true);
}

static bool
ena_check_versions(ena_t *ena)
{
	uint32_t dev_vsn = ena_hw_bar_read32(ena, ENAHW_REG_VERSION);
	uint32_t ctrl_vsn =
	    ena_hw_bar_read32(ena, ENAHW_REG_CONTROLLER_VERSION);

	ena->ena_dev_major_vsn = ENAHW_DEV_MAJOR_VSN(dev_vsn);
	ena->ena_dev_minor_vsn = ENAHW_DEV_MINOR_VSN(dev_vsn);

	ena->ena_ctrl_major_vsn = ENAHW_CTRL_MAJOR_VSN(ctrl_vsn);
	ena->ena_ctrl_minor_vsn = ENAHW_CTRL_MINOR_VSN(ctrl_vsn);
	ena->ena_ctrl_subminor_vsn = ENAHW_CTRL_SUBMINOR_VSN(ctrl_vsn);
	ena->ena_ctrl_impl_id = ENAHW_CTRL_IMPL_ID(ctrl_vsn);

	ena_dbg(ena, "device version: %u.%u",
	    ena->ena_dev_major_vsn, ena->ena_dev_minor_vsn);
	ena_dbg(ena, "controller version: %u.%u.%u implementation %u",
	    ena->ena_ctrl_major_vsn, ena->ena_ctrl_minor_vsn,
	    ena->ena_ctrl_subminor_vsn, ena->ena_ctrl_impl_id);

	if (ena->ena_ctrl_subminor_vsn < ENA_CTRL_SUBMINOR_VSN_MIN) {
		ena_err(ena, "unsupported controller version: %u.%u.%u",
		    ena->ena_ctrl_major_vsn, ena->ena_ctrl_minor_vsn,
		    ena->ena_ctrl_subminor_vsn);
		return (false);
	}

	return (true);
}

static bool
ena_adminq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;

	/*
	 * As we are not using an interrupt for admin queue completion
	 * signaling, we do not need a priority on these mutexes. If
	 * that changes, we will have to rejigger some code to create
	 * the admin queue interrupt before this function.
	 */
	mutex_init(&aq->ea_sq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&aq->ea_cq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&aq->ea_stat_lock, NULL, MUTEX_DRIVER, NULL);
	aq->ea_qlen = ENA_ADMINQ_DEPTH;
	aq->ea_pending_cmds = 0;

	aq->ea_cmd_ctxs = kmem_zalloc(sizeof (ena_cmd_ctx_t) * aq->ea_qlen,
	    KM_SLEEP);
	list_create(&aq->ea_cmd_ctxs_free, sizeof (ena_cmd_ctx_t),
	    offsetof(ena_cmd_ctx_t, ectx_node));
	list_create(&aq->ea_cmd_ctxs_used, sizeof (ena_cmd_ctx_t),
	    offsetof(ena_cmd_ctx_t, ectx_node));

	ena_create_cmd_ctx(ena);

	/*
	 * Start in polling mode until we've determined the number of queues
	 * and are ready to configure and enable interrupts.
	 */
	ena_hw_bar_write32(ena, ENAHW_REG_INTERRUPT_MASK, ENAHW_INTR_MASK);
	aq->ea_poll_mode = true;

	return (true);
}

/*
 * Free all resources allocated as part of ena_device_init().
 */
static void
ena_cleanup_device_init(ena_t *ena, bool resetting)
{
	ena_adminq_t *aq = &ena->ena_aq;

	VERIFY0(resetting);

	ena_free_host_info(ena);
	mutex_destroy(&aq->ea_sq_lock);
	mutex_destroy(&aq->ea_cq_lock);
	mutex_destroy(&aq->ea_stat_lock);
	list_destroy(&aq->ea_cmd_ctxs_free);
	list_destroy(&aq->ea_cmd_ctxs_used);
	kmem_free(aq->ea_cmd_ctxs, sizeof (ena_cmd_ctx_t) * aq->ea_qlen);
	ena_admin_sq_free(ena);
	ena_admin_cq_free(ena);
	ena_aenq_free(ena);
	ena_stat_device_cleanup(ena);
	ena_stat_device_basic_cleanup(ena);
	ena_stat_device_extended_cleanup(ena);
	ena_stat_aenq_cleanup(ena);
}

static bool
ena_attach_device_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	uint32_t rval;
	uint8_t dma_width;
	hrtime_t cmd_timeout;
	enahw_resp_desc_t resp;
	enahw_feat_dev_attr_t *feat = &resp.erd_resp.erd_get_feat.ergf_dev_attr;
	uint8_t *maddr;
	uint32_t supported_features;
	int ret = 0;

	ena->ena_reset_reason = ENAHW_RESET_NORMAL;
	if (!ena_device_reset(ena, ena->ena_reset_reason))
		return (false);

	if (!ena_check_versions(ena))
		return (false);

	ena_init_regcache(ena);

	rval = ena_hw_bar_read32(ena, ENAHW_REG_CAPS);
	dma_width = ENAHW_CAPS_DMA_ADDR_WIDTH(rval);
	ena->ena_dma_width = dma_width;

	/*
	 * The value stored in the device register is in the
	 * resolution of 100 milliseconds. We normalize that to
	 * nanoseconds.
	 */
	cmd_timeout = MSEC2NSEC(ENAHW_CAPS_ADMIN_CMD_TIMEOUT(rval) * 100);
	aq->ea_cmd_timeout_ns = max(cmd_timeout, ena_admin_cmd_timeout_ns);

	if (aq->ea_cmd_timeout_ns == 0)
		aq->ea_cmd_timeout_ns = ENA_ADMIN_CMD_DEF_TIMEOUT_NS;

	if (!ena_adminq_init(ena))
		return (false);

	if (!ena_admin_sq_init(ena))
		return (false);

	if (!ena_admin_cq_init(ena))
		return (false);

	if (!ena_aenq_init(ena))
		return (false);

	bzero(&resp, sizeof (resp));
	ret = ena_get_feature(ena, &resp, ENAHW_FEAT_DEVICE_ATTRIBUTES,
	    ENAHW_FEAT_DEVICE_ATTRIBUTES_VER);

	if (ret != 0) {
		ena_err(ena, "failed to get device attributes: %d", ret);
		return (false);
	}

	ena_dbg(ena, "impl ID: %u", feat->efda_impl_id);
	ena_dbg(ena, "device version: %u", feat->efda_device_version);
	ena_dbg(ena, "supported features: 0x%x",
	    feat->efda_supported_features);
	ena_dbg(ena, "device capabilities: 0x%x", feat->efda_capabilities);
	ena_dbg(ena, "phys addr width: %u", feat->efda_phys_addr_width);
	ena_dbg(ena, "virt addr width: %u", feat->efda_virt_addr_with);
	maddr = feat->efda_mac_addr;
	ena_dbg(ena, "mac addr: %x:%x:%x:%x:%x:%x", maddr[0], maddr[1],
	    maddr[2], maddr[3], maddr[4], maddr[5]);
	ena_dbg(ena, "max MTU: %u", feat->efda_max_mtu);

	bcopy(maddr, ena->ena_mac_addr, ETHERADDRL);
	ena->ena_max_mtu = feat->efda_max_mtu;
	ena->ena_capabilities = feat->efda_capabilities;
	supported_features = feat->efda_supported_features;
	ena->ena_supported_features = supported_features;
	feat = NULL;
	bzero(&resp, sizeof (resp));

	if (ena_is_feat_avail(ena, ENAHW_FEAT_MAX_QUEUES_EXT)) {
		enahw_feat_max_queue_ext_t *feat_mqe =
		    &resp.erd_resp.erd_get_feat.ergf_max_queue_ext;

		ret = ena_get_feature(ena, &resp, ENAHW_FEAT_MAX_QUEUES_EXT,
		    ENAHW_FEAT_MAX_QUEUES_EXT_VER);

		if (ret != 0) {
			ena_err(ena, "failed to query max queues ext: %d", ret);
			return (false);
		}

		ena->ena_tx_max_sq_num = feat_mqe->efmqe_max_tx_sq_num;
		ena->ena_tx_max_sq_num_descs = feat_mqe->efmqe_max_tx_sq_depth;
		ena->ena_tx_max_cq_num = feat_mqe->efmqe_max_tx_cq_num;
		ena->ena_tx_max_cq_num_descs = feat_mqe->efmqe_max_tx_cq_depth;
		ena->ena_tx_max_desc_per_pkt =
		    feat_mqe->efmqe_max_per_packet_tx_descs;
		ena->ena_tx_max_hdr_len = feat_mqe->efmqe_max_tx_header_size;

		ena->ena_rx_max_sq_num = feat_mqe->efmqe_max_rx_sq_num;
		ena->ena_rx_max_sq_num_descs = feat_mqe->efmqe_max_rx_sq_depth;
		ena->ena_rx_max_cq_num = feat_mqe->efmqe_max_rx_cq_num;
		ena->ena_rx_max_cq_num_descs = feat_mqe->efmqe_max_rx_cq_depth;
		ena->ena_rx_max_desc_per_pkt =
		    feat_mqe->efmqe_max_per_packet_rx_descs;

		ena_set_max_io_queues(ena);
	} else {
		enahw_feat_max_queue_t *feat_mq =
		    &resp.erd_resp.erd_get_feat.ergf_max_queue;

		ret = ena_get_feature(ena, &resp, ENAHW_FEAT_MAX_QUEUES_NUM,
		    ENAHW_FEAT_MAX_QUEUES_NUM_VER);

		if (ret != 0) {
			ena_err(ena, "failed to query max queues: %d", ret);
			return (false);
		}

		ena->ena_tx_max_sq_num = feat_mq->efmq_max_sq_num;
		ena->ena_tx_max_sq_num_descs = feat_mq->efmq_max_sq_depth;
		ena->ena_tx_max_cq_num = feat_mq->efmq_max_cq_num;
		ena->ena_tx_max_cq_num_descs = feat_mq->efmq_max_cq_depth;
		ena->ena_tx_max_desc_per_pkt =
		    feat_mq->efmq_max_per_packet_tx_descs;
		ena->ena_tx_max_hdr_len = feat_mq->efmq_max_header_size;

		ena->ena_rx_max_sq_num = feat_mq->efmq_max_sq_num;
		ena->ena_rx_max_sq_num_descs = feat_mq->efmq_max_sq_depth;
		ena->ena_rx_max_cq_num = feat_mq->efmq_max_cq_num;
		ena->ena_rx_max_cq_num_descs = feat_mq->efmq_max_cq_depth;
		ena->ena_rx_max_desc_per_pkt =
		    feat_mq->efmq_max_per_packet_rx_descs;

		ena_set_max_io_queues(ena);
	}

	ena->ena_mtu = ena->ena_max_mtu;
	ena_update_buf_sizes(ena);

	if (!ena_get_hints(ena))
		return (false);

	ena->ena_tx_sgl_max_sz = 1;
	ena->ena_rx_sgl_max_sz = 1;
	if (ena->ena_device_hints.eh_max_tx_sgl != 0)
		ena->ena_tx_sgl_max_sz = ena->ena_device_hints.eh_max_tx_sgl;
	if (ena->ena_device_hints.eh_max_rx_sgl != 0)
		ena->ena_rx_sgl_max_sz = ena->ena_device_hints.eh_max_rx_sgl;

	if (!ena_init_host_info(ena))
		return (false);

	if (!ena_aenq_configure(ena))
		return (false);

	ena_get_link_config(ena);

	if (!ena_get_offloads(ena))
		return (false);

	if (!ena_stat_device_init(ena))
		return (false);

	if (!ena_stat_device_basic_init(ena))
		return (false);

	if (!ena_stat_device_extended_init(ena))
		return (false);

	if (!ena_stat_aenq_init(ena))
		return (false);

	ena_update_regcache(ena);

	return (true);
}

static void
ena_cleanup_intr_alloc(ena_t *ena, bool resetting)
{
	VERIFY0(resetting);

	for (int i = 0; i < ena->ena_num_intrs; i++) {
		int ret = ddi_intr_free(ena->ena_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to free interrupt %d: %d", i, ret);
		}
	}

	if (ena->ena_intr_handles != NULL) {
		kmem_free(ena->ena_intr_handles, ena->ena_intr_handles_sz);
		ena->ena_intr_handles = NULL;
		ena->ena_intr_handles_sz = 0;
	}
}

/*
 * The Linux driver supports only MSI-X interrupts. We do the same,
 * with the assumption that it's the only type of interrupt the device
 * can present.
 */
static bool
ena_attach_intr_alloc(ena_t *ena)
{
	int ret;
	int types;
	int min, req, ideal, avail, actual;

	ret = ddi_intr_get_supported_types(ena->ena_dip, &types);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt types: %d", ret);
		return (false);
	}

	ena_dbg(ena, "supported interrupt types: 0x%x", types);
	if ((types & DDI_INTR_TYPE_MSIX) == 0) {
		ena_err(ena, "the ena driver only supports MSI-X interrupts");
		return (false);
	}

	/* One for I/O, one for adminq. */
	min = 2;
	ideal = ena->ena_max_io_queues + 1;
	ret = ddi_intr_get_nintrs(ena->ena_dip, DDI_INTR_TYPE_MSIX, &avail);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get number of MSI-X interrupts: %d",
		    ret);
		return (false);
	}

	if (avail < min) {
		ena_err(ena, "number of MSI-X interrupts is %d, but the driver "
		    "requires a minimum of %d", avail, min);
		return (false);
	}

	ena_dbg(ena, "%d MSI-X interrupts available", avail);

	ret = ddi_intr_get_navail(ena->ena_dip, DDI_INTR_TYPE_MSIX, &avail);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get available interrupts: %d", ret);
		return (false);
	}

	if (avail < min) {
		ena_err(ena, "number of available MSI-X interrupts is %d, "
		    "but the driver requires a minimum of %d", avail, min);
		return (false);
	}

	req = MIN(ideal, avail);
	ena->ena_intr_handles_sz = req * sizeof (ddi_intr_handle_t);
	ena->ena_intr_handles = kmem_zalloc(ena->ena_intr_handles_sz, KM_SLEEP);

	ret = ddi_intr_alloc(ena->ena_dip, ena->ena_intr_handles,
	    DDI_INTR_TYPE_MSIX, 0, req, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to allocate %d MSI-X interrupts: %d",
		    req, ret);
		return (false);
	}

	if (actual < min) {
		ena_err(ena, "number of allocated interrupts is %d, but the "
		    "driver requires a minimum of %d", actual, min);
		return (false);
	}

	ena->ena_num_intrs = actual;

	ret = ddi_intr_get_cap(ena->ena_intr_handles[0], &ena->ena_intr_caps);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt capability: %d", ret);
		return (false);
	}

	ret = ddi_intr_get_pri(ena->ena_intr_handles[0], &ena->ena_intr_pri);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt priority: %d", ret);
		return (false);
	}

	ena_dbg(ena, "MSI-X interrupts allocated: %d, cap: 0x%x, pri: %u",
	    actual, ena->ena_intr_caps, ena->ena_intr_pri);

	/*
	 * The ena_lock should not be held in the data path, but it is
	 * held as part of the AENQ handler, which runs in interrupt
	 * context. Therefore, we delayed the initialization of this
	 * mutex until after the interrupts are allocated.
	 */
	mutex_init(&ena->ena_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ena->ena_intr_pri));
	mutex_init(&ena->ena_watchdog_lock, NULL, MUTEX_DRIVER, NULL);

	return (true);
}

/*
 * Allocate the parent Rx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as queues are started.
 */
static bool
ena_attach_alloc_rxqs(ena_t *ena)
{
	bool resetting = false;

	if (ena->ena_rxqs == NULL) {
		/*
		 * We rely on the interrupt priority for initializing the
		 * mutexes.
		 */
		VERIFY3U(ena->ena_attach_seq, >=, ENA_ATTACH_INTR_ALLOC);
		ena->ena_num_rxqs = ena->ena_num_intrs - 1;
		ASSERT3U(ena->ena_num_rxqs, >, 0);
		ena->ena_rxqs = kmem_zalloc(
		    ena->ena_num_rxqs * sizeof (*ena->ena_rxqs), KM_SLEEP);
	} else {
		resetting = true;
	}

	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		rxq->er_rxqs_idx = i;
		/* The 0th vector is for Admin + AENQ. */
		rxq->er_intr_vector = i + 1;
		rxq->er_mrh = NULL;

		if (!resetting) {
			mutex_init(&rxq->er_lock, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(ena->ena_intr_pri));
			mutex_init(&rxq->er_stat_lock, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(ena->ena_intr_pri));
		}

		rxq->er_ena = ena;
		rxq->er_sq_num_descs = ena->ena_rxq_num_descs;
		rxq->er_cq_num_descs = ena->ena_rxq_num_descs;

		if (!ena_stat_rxq_init(rxq)) {
			return (false);
		}

		if (!ena_alloc_rxq(rxq)) {
			ena_stat_rxq_cleanup(rxq);
			return (false);
		}
	}

	return (true);
}

static void
ena_cleanup_rxqs(ena_t *ena, bool resetting)
{
	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		ena_cleanup_rxq(rxq, resetting);
		if (!resetting) {
			mutex_destroy(&rxq->er_lock);
			mutex_destroy(&rxq->er_stat_lock);
		}
		ena_stat_rxq_cleanup(rxq);
	}

	if (!resetting) {
		kmem_free(ena->ena_rxqs,
		    ena->ena_num_rxqs * sizeof (*ena->ena_rxqs));
		ena->ena_rxqs = NULL;
	}
}

/*
 * Allocate the parent Tx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as a queue is started.
 */
static bool
ena_attach_alloc_txqs(ena_t *ena)
{
	bool resetting = false;

	if (ena->ena_txqs == NULL) {
		/*
		 * We rely on the interrupt priority for initializing the
		 * mutexes.
		 */
		VERIFY3U(ena->ena_attach_seq, >=, ENA_ATTACH_INTR_ALLOC);
		ena->ena_num_txqs = ena->ena_num_intrs - 1;
		ASSERT3U(ena->ena_num_txqs, >, 0);
		ena->ena_txqs = kmem_zalloc(
		    ena->ena_num_txqs * sizeof (*ena->ena_txqs), KM_SLEEP);
	} else {
		resetting = true;
	}

	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		txq->et_txqs_idx = i;
		/* The 0th vector is for Admin + AENQ. */
		txq->et_intr_vector = i + 1;
		txq->et_mrh = NULL;

		if (!resetting) {
			mutex_init(&txq->et_lock, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(ena->ena_intr_pri));
			mutex_init(&txq->et_stat_lock, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(ena->ena_intr_pri));
		}

		txq->et_ena = ena;
		txq->et_sq_num_descs = ena->ena_txq_num_descs;
		txq->et_cq_num_descs = ena->ena_txq_num_descs;

		if (!ena_stat_txq_init(txq)) {
			return (false);
		}

		if (!ena_alloc_txq(txq)) {
			ena_stat_txq_cleanup(txq);
			return (false);
		}
	}

	return (true);
}

static void
ena_cleanup_txqs(ena_t *ena, bool resetting)
{
	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		ena_cleanup_txq(txq, resetting);
		if (!resetting) {
			mutex_destroy(&txq->et_lock);
			mutex_destroy(&txq->et_stat_lock);
		}
		ena_stat_txq_cleanup(txq);
	}

	if (!resetting) {
		kmem_free(ena->ena_txqs,
		    ena->ena_num_txqs * sizeof (*ena->ena_txqs));
		ena->ena_txqs = NULL;
	}
}

/*
 * To reset the device we need to unwind some of the steps taken during attach
 * but, since the device could well be in a failed state, we cannot rely on
 * being able to talk via the admin queue to do things such as explicitly
 * destroy rings. We call selected cleanup handlers with the second parameter
 * set to "true" to indicate that we are resetting and should avoid such
 * communication.
 *
 * The existing DMA memory regions for the admin queue, async event queue and
 * host information are preserved but have their contents zeroed.
 * Experimentation has shown that the device hangs onto old async event queue
 * addresses, even through a reset, with surprising results if the addresses
 * happen to change.
 *
 * We clean up all of the Tx and Rx ring descriptors and the TCBs but leave the
 * allocated memory for the ring data and mutexes intact. Pointers to this
 * memory have already been provided to MAC, and the mutexes keep the rings
 * locked until we're ready to start them again.
 *
 * To ensure that other driver activity is excluded, we hold the mutexes on the
 * Tx and Rx rings throughout, and unset the `ENA_STATE_STARTED` bit in the
 * state, which causes the interrupt handlers to return without doing any work.
 * The admin interrupt, used for notifications of admin completions or new
 * asynchronous events, is masked after the device is reset until we're ready
 * to process them again.
 */
bool
ena_reset(ena_t *ena, const enahw_reset_reason_t reason)
{
	ena_txq_state_t tx_state[ena->ena_num_txqs];
	ena_rxq_state_t rx_state[ena->ena_num_rxqs];
	bool ret = false;

	ena_err(ena, "resetting device with reason 0x%x [%s]",
	    reason, enahw_reset_reason(reason));

	VERIFY0(ena->ena_state & ENA_STATE_RESETTING);
	atomic_or_32(&ena->ena_state, ENA_STATE_RESETTING);

	VERIFY(ena->ena_state & ENA_STATE_STARTED);
	atomic_and_32(&ena->ena_state, ~ENA_STATE_STARTED);

	mutex_enter(&ena->ena_lock);

	ena_update_regcache(ena);

	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		mutex_enter(&txq->et_lock);
		tx_state[i] = txq->et_state;
		if (txq->et_state & ENA_TXQ_STATE_RUNNING)
			ena_ring_tx_stop((mac_ring_driver_t)txq);
	}

	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		mutex_enter(&rxq->er_lock);
		rx_state[i] = rxq->er_state;
		if (rxq->er_state & ENA_RXQ_STATE_RUNNING)
			ena_ring_rx_stop((mac_ring_driver_t)rxq);
	}

	if (!ena_device_reset(ena, reason)) {
		ena_err(ena, "reset: failed to reset device");
		goto out;
	}

	/* This masks the admin/aenq interrupt */
	ena_hw_bar_write32(ena, ENAHW_REG_INTERRUPT_MASK, ENAHW_INTR_MASK);

	ena_cleanup_txqs(ena, true);
	ena_cleanup_rxqs(ena, true);

	ena_release_all_cmd_ctx(ena);

	if (!ena_admin_cq_init(ena) || !ena_admin_sq_init(ena)) {
		ena_err(ena, "reset: failed to program admin queues");
		goto out;
	}

	if (!ena_init_host_info(ena)) {
		ena_err(ena, "reset: failed to set host info");
		goto out;
	}

	if (!ena_aenq_init(ena) || !ena_aenq_configure(ena)) {
		ena_err(ena, "reset: failed to configure aenq");
		goto out;
	}

	if (!ena_set_mtu(ena)) {
		ena_err(ena, "reset: failed to set MTU");
		goto out;
	}

	if (!ena_attach_alloc_txqs(ena) || !ena_attach_alloc_rxqs(ena)) {
		ena_err(ena, "reset: failed to program IO queues");
		goto out;
	}

	ena_aenq_enable(ena);
	ena_hw_bar_write32(ena, ENAHW_REG_INTERRUPT_MASK, ENAHW_INTR_UNMASK);

	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		mutex_exit(&rxq->er_lock);
		if (rx_state[i] & ENA_RXQ_STATE_RUNNING) {
			(void) ena_ring_rx_start((mac_ring_driver_t)rxq,
			    rxq->er_m_gen_num);
		}
	}

	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		mutex_exit(&txq->et_lock);
		if (tx_state[i] & ENA_TXQ_STATE_RUNNING) {
			(void) ena_ring_tx_start((mac_ring_driver_t)txq,
			    txq->et_m_gen_num);
		}
	}

	atomic_or_32(&ena->ena_state, ENA_STATE_STARTED);
	ret = true;

out:
	atomic_and_32(&ena->ena_state, ~ENA_STATE_RESETTING);
	mutex_exit(&ena->ena_lock);

	ena_update_regcache(ena);

	return (ret);
}

ena_attach_desc_t ena_attach_tbl[ENA_ATTACH_NUM_ENTRIES] = {
	{
		.ead_seq = ENA_ATTACH_PCI,
		.ead_name = "PCI config",
		.ead_attach_fn = ena_attach_pci,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_pci,
	},

	{
		.ead_seq = ENA_ATTACH_REGS,
		.ead_name = "BAR mapping",
		.ead_attach_fn = ena_attach_regs_map,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_regs_map,
	},

	{
		.ead_seq = ENA_ATTACH_DEV_INIT,
		.ead_name = "device initialization",
		.ead_attach_fn = ena_attach_device_init,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_device_init,
	},

	{
		.ead_seq = ENA_ATTACH_READ_CONF,
		.ead_name = "ena.conf",
		.ead_attach_fn = ena_attach_read_conf,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = NULL,
	},

	{
		.ead_seq = ENA_ATTACH_DEV_CFG,
		.ead_name = "device config",
		.ead_attach_fn = ena_attach_dev_cfg,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = NULL,
	},

	{
		.ead_seq = ENA_ATTACH_INTR_ALLOC,
		.ead_name = "interrupt allocation",
		.ead_attach_fn = ena_attach_intr_alloc,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_intr_alloc,
	},

	{
		.ead_seq = ENA_ATTACH_INTR_HDLRS,
		.ead_name = "interrupt handlers",
		.ead_attach_fn = ena_intr_add_handlers,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_intr_remove_handlers,
	},

	{
		.ead_seq = ENA_ATTACH_TXQS_ALLOC,
		.ead_name = "Tx queues",
		.ead_attach_fn = ena_attach_alloc_txqs,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_txqs,
	},

	{
		.ead_seq = ENA_ATTACH_RXQS_ALLOC,
		.ead_name = "Rx queues",
		.ead_attach_fn = ena_attach_alloc_rxqs,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = ena_cleanup_rxqs,
	},

	/*
	 * The chance of mac_unregister() failure poses a problem to
	 * cleanup. We address interrupt disablement and mac
	 * unregistration explicitly in the attach/detach routines.
	 */
	{
		.ead_seq = ENA_ATTACH_MAC_REGISTER,
		.ead_name = "mac registration",
		.ead_attach_fn = ena_mac_register,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = NULL,
	},

	{
		.ead_seq = ENA_ATTACH_INTRS_ENABLE,
		.ead_name = "enable interrupts",
		.ead_attach_fn = ena_intrs_enable,
		.ead_attach_hard_fail = true,
		.ead_cleanup_fn = NULL,
	}
};

/*
 * This function undoes any work done by ena_attach(), either in
 * response to a failed attach or a planned detach. At the end of this
 * function ena_attach_seq should be zero, otherwise it means
 * something has not be freed/uninitialized.
 */
static void
ena_cleanup(ena_t *ena)
{
	if (ena == NULL || ena->ena_attach_seq == 0) {
		return;
	}

	/*
	 * We VERIFY this because if the seq is greater than entries
	 * we drift into space and execute god knows what.
	 */
	VERIFY3U(ena->ena_attach_seq, <, ENA_ATTACH_NUM_ENTRIES);

	while (ena->ena_attach_seq > 0) {
		int idx = ena->ena_attach_seq - 1;
		ena_attach_desc_t *desc = &ena_attach_tbl[idx];

		ena_dbg(ena, "running cleanup sequence: %s (%d)",
		    desc->ead_name, idx);

		if (desc->ead_cleanup_fn != NULL)
			desc->ead_cleanup_fn(ena, false);
		ena->ena_attach_seq--;
	}

	ASSERT3U(ena->ena_attach_seq, ==, 0);
	mutex_destroy(&ena->ena_lock);
	mutex_destroy(&ena->ena_watchdog_lock);
}

static int
ena_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ena_t *ena;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	ena = kmem_zalloc(sizeof (ena_t), KM_SLEEP);
	ena->ena_instance = ddi_get_instance(dip);
	ena->ena_dip = dip;
	ena->ena_instance = ddi_get_instance(dip);
	ena->ena_page_sz = ddi_ptob(dip, 1);

	for (int i = 0; i < ENA_ATTACH_NUM_ENTRIES; i++) {
		bool success;
		ena_attach_desc_t *desc = &ena_attach_tbl[i];

		ena_dbg(ena, "running attach sequence: %s (%d)", desc->ead_name,
		    i);

		if (!(success = desc->ead_attach_fn(ena))) {
			ena_err(ena, "attach sequence failed: %s (%d)",
			    desc->ead_name, i);

			if (ena->ena_attach_seq == ENA_ATTACH_MAC_REGISTER) {
				/*
				 * In this specific case
				 * ENA_ATTACH_INTRS_ENABLE has failed,
				 * and we may or may not be able to
				 * unregister the mac, depending on if
				 * something in userspace has created
				 * a client on top.
				 *
				 * NOTE: Something that would be nice
				 * to add to mac is the ability to
				 * register a provider separate from
				 * "publishing" it to the rest of the
				 * system. This would allow a driver
				 * to register its mac, do some
				 * additional work that might fail,
				 * and then unregister if that work
				 * fails without concern for any
				 * chance of failure when calling
				 * unregister. This would remove the
				 * complexity of the situation we are
				 * trying to address here, as we would
				 * know that until the mac has been
				 * "published", there is no chance for
				 * mac_unregister() to fail.
				 */
				if (ena_mac_unregister(ena) != 0) {
					return (DDI_FAILURE);
				}

				ena->ena_attach_seq--;
			} else {
				/*
				 * Since the ead_seq is predicated on
				 * successful ead_attach_fn we must
				 * run the specific cleanup handler
				 * before calling the global cleanup
				 * routine. This also means that all
				 * cleanup functions must be able to
				 * deal with partial success of the
				 * corresponding ead_attach_fn.
				 */
				if (desc->ead_cleanup_fn != NULL)
					desc->ead_cleanup_fn(ena, false);
			}

			ena_cleanup(ena);
			kmem_free(ena, sizeof (ena_t));
			return (DDI_FAILURE);
		}

		if (success) {
			ena_dbg(ena, "attach sequence completed: %s (%d)",
			    desc->ead_name, i);
		}

		ena->ena_attach_seq = desc->ead_seq;
	}

	/*
	 * Now that interrupts are enabled, unmask the admin interrupt.
	 * Note that this interrupt is generated for both the admin queue and
	 * the AENQ, but this driver always polls the admin queue. The surplus
	 * interrupt for admin command completion triggers a harmless check of
	 * the AENQ.
	 */
	ena_hw_bar_write32(ena, ENAHW_REG_INTERRUPT_MASK, ENAHW_INTR_UNMASK);
	ena_aenq_enable(ena);

	ddi_set_driver_private(dip, ena);

	ena_update_regcache(ena);

	atomic_or_32(&ena->ena_state, ENA_STATE_INITIALIZED);

	return (DDI_SUCCESS);
}

static int
ena_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ena_t *ena = ddi_get_driver_private(dip);

	if (ena == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Before we can proceed to cleanup we have to treat
	 * mac_unregister() explicitly -- if there are still
	 * outstanding clients, then we can't proceed with detach or
	 * cleanup.
	 */

	/*
	 * Why this would fail I don't know, but if we proceed to mac
	 * unregister, then there is a good chance we will panic in
	 * the Rx interrupt handler when calling mac_rx_ring()
	 */
	if (!ena_intrs_disable(ena)) {
		return (DDI_FAILURE);
	}

	/* We can't detach if clients are actively using the device. */
	if (ena_mac_unregister(ena) != 0) {
		(void) ena_intrs_enable(ena);
		return (DDI_FAILURE);
	}

	/*
	 * At this point we can proceed with the rest of cleanup on a
	 * best-effort basis.
	 */
	ena->ena_attach_seq = ENA_ATTACH_RXQS_ALLOC;
	ena_cleanup(ena);
	ddi_set_driver_private(dip, NULL);
	kmem_free(ena, sizeof (ena_t));
	return (DDI_SUCCESS);
}

static struct cb_ops ena_cb_ops = {
	.cb_open = nodev,
	.cb_close = nodev,
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

static struct dev_ops ena_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ena_attach,
	.devo_detach = ena_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ena_cb_ops
};

static struct modldrv ena_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AWS ENA Ethernet",
	.drv_dev_ops = &ena_dev_ops
};

static struct modlinkage ena_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ena_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	mac_init_ops(&ena_dev_ops, ENA_MODULE_NAME);

	if ((ret = mod_install(&ena_modlinkage)) != 0) {
		mac_fini_ops(&ena_dev_ops);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ena_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ena_modlinkage)) != 0) {
		return (ret);
	}

	mac_fini_ops(&ena_dev_ops);
	return (ret);
}
