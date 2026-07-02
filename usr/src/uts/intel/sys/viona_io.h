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
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_VIONA_IO_H_
#define	_VIONA_IO_H_

#include <sys/sysmacros.h>
#include <sys/ethernet.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#define	VNA_IOC				(('V' << 16)|('C' << 8))
#define	VNA_IOC_CREATE			(VNA_IOC | 0x01)
#define	VNA_IOC_DELETE			(VNA_IOC | 0x02)
#define	VNA_IOC_VERSION			(VNA_IOC | 0x03)
#define	VNA_IOC_DEFAULT_PARAMS		(VNA_IOC | 0x04)

#define	VNA_IOC_RING_INIT		(VNA_IOC | 0x10)
#define	VNA_IOC_RING_RESET		(VNA_IOC | 0x11)
#define	VNA_IOC_RING_KICK		(VNA_IOC | 0x12)
#define	VNA_IOC_RING_SET_MSI		(VNA_IOC | 0x13)
#define	VNA_IOC_RING_INTR_CLR		(VNA_IOC | 0x14)
#define	VNA_IOC_RING_SET_STATE		(VNA_IOC | 0x15)
#define	VNA_IOC_RING_GET_STATE		(VNA_IOC | 0x16)
#define	VNA_IOC_RING_PAUSE		(VNA_IOC | 0x17)
#define	VNA_IOC_RING_INIT_MODERN	(VNA_IOC | 0x18)

#define	VNA_IOC_INTR_POLL		(VNA_IOC | 0x20)
#define	VNA_IOC_SET_FEATURES		(VNA_IOC | 0x21)
#define	VNA_IOC_GET_FEATURES		(VNA_IOC | 0x22)
#define	VNA_IOC_SET_NOTIFY_IOP		(VNA_IOC | 0x23)
#define	VNA_IOC_SET_PROMISC		(VNA_IOC | 0x24)
#define	VNA_IOC_GET_PARAMS		(VNA_IOC | 0x25)
#define	VNA_IOC_SET_PARAMS		(VNA_IOC | 0x26)
#define	VNA_IOC_GET_MTU			(VNA_IOC | 0x27)
#define	VNA_IOC_SET_MTU			(VNA_IOC | 0x28)
#define	VNA_IOC_SET_NOTIFY_MMIO		(VNA_IOC | 0x29)
#define	VNA_IOC_INTR_POLL_MQ		(VNA_IOC | 0x2a)
#define	VNA_IOC_SET_MAC_FILTERS		(VNA_IOC | 0x2b)
#define	VNA_IOC_GET_MAC_FILTERS		(VNA_IOC | 0x2c)
#define	VNA_IOC_SET_MAC_ADDR		(VNA_IOC | 0x2d)
#define	VNA_IOC_GET_MAC_ADDR		(VNA_IOC | 0x2e)

/*
 * While the VirtIO specification allows for up to 0x8000 queue pairs, we
 * impose a lower limit in Viona.
 */
#define	VIONA_MIN_QPAIR			1
#define	VIONA_MAX_QPAIR			0x100
#define	VNA_IOC_GET_PAIRS		(VNA_IOC | 0x30)
#define	VNA_IOC_SET_PAIRS		(VNA_IOC | 0x31)
#define	VNA_IOC_GET_USEPAIRS		(VNA_IOC | 0x32)
#define	VNA_IOC_SET_USEPAIRS		(VNA_IOC | 0x33)

/*
 * Viona Interface Version
 *
 * Like bhyve, viona exposes Private interfaces which are nonetheless consumed
 * by out-of-gate consumers.  While those consumers assume all risk of breakage
 * incurred by subsequent changes, it would be nice to equip them to potentially
 * detect (and handle) those modifications.
 *
 * There are no established criteria for the magnitude of change which requires
 * this version to be incremented, and maintenance of it is considered a
 * best-effort activity.  Nothing is to be inferred about the magnitude of a
 * change when the version is modified.  It follows no rules like semver.
 *
 */
#define	VIONA_CURRENT_INTERFACE_VERSION	7

typedef struct vioc_create {
	datalink_id_t	c_linkid;
	int		c_vmfd;
} vioc_create_t;

typedef struct vioc_ring_init {
	uint16_t	ri_index;
	uint16_t	ri_qsize;
	uint64_t	ri_qaddr;
} vioc_ring_init_t;

typedef struct vioc_ring_init_modern {
	uint16_t	rim_index;
	uint16_t	rim_qsize;
	uint64_t	rim_qaddr_desc;
	uint64_t	rim_qaddr_avail;
	uint64_t	rim_qaddr_used;
} vioc_ring_init_modern_t;

typedef struct vioc_ring_state {
	uint16_t	vrs_index;
	uint16_t	vrs_avail_idx;
	uint16_t	vrs_used_idx;
	uint16_t	vrs_qsize;
	uint64_t	vrs_qaddr_desc;
	uint64_t	vrs_qaddr_avail;
	uint64_t	vrs_qaddr_used;
} vioc_ring_state_t;

typedef struct vioc_ring_msi {
	uint16_t	rm_index;
	uint64_t	rm_addr;
	uint64_t	rm_msg;
} vioc_ring_msi_t;

typedef enum {
	VIONA_PROMISC_NONE = 0,
	VIONA_PROMISC_MULTI,
	VIONA_PROMISC_ALL,
	VIONA_PROMISC_MAX,
} viona_promisc_t;

/*
 * MAC Address Filter Interface
 *
 * A guest which negotiates VIRTIO_NET_F_CTRL_RX communicates its unicast and
 * multicast address tables to the device via the control queue
 * (VIRTIO_NET_CTRL_MAC).  VNA_IOC_SET_MAC_FILTERS allows the device emulation
 * to install the multicast table onto the underlying MAC client, so that
 * classified delivery of the listed groups can replace promiscuous-multicast
 * reception.  The interface presumes Ethernet addressing throughout;
 * VNA_IOC_CREATE refuses links of any other media type with ENOTSUP.
 *
 * The table is complete, mirroring VIRTIO_NET_CTRL_MAC_TABLE_SET semantics.
 * It replaces any previously installed table, with only the differences
 * applied to the MAC client.  A count of zero clears all filters.
 * Broadcast and duplicate entries are dropped rather than refused.  A MAC
 * client is joined to broadcast for the lifetime of its unicast address, so
 * no filter is needed.  The table read back via VNA_IOC_GET_MAC_FILTERS
 * reflects the compaction.
 *
 * Only the multicast table is carried here.  A MAC client supports a single
 * unicast address, so a guest unicast table cannot be honored with filters.
 * Consumers whose guests configure unicast addresses beyond the primary MAC
 * of the link must instead fall back to a promiscuous mode.  The policy
 * question behind refusing guest unicast tables is discussed in the theory
 * statement of viona_main.c.
 *
 * VIRTIO_NET_CTRL_MAC_ADDR_SET, the other command of the class (advertised
 * via VIRTIO_NET_F_CTRL_MAC_ADDR), replaces the default address of the
 * device rather than adding a table entry.  VNA_IOC_SET_MAC_ADDR mirrors
 * it, replacing the classified unicast address of the MAC client, meaning
 * that a guest which changes its default address retains classified unicast
 * delivery rather than forfeiting it to a promiscuous fallback.  The ioctl
 * reaches only the MAC client; a device which offers VIRTIO_NET_F_MAC
 * remains responsible for updating the mac field of its config space.  On
 * a VNIC, which carries exactly one unicast address, the replacement
 * updates that address in place.  On other links the current address is
 * removed from the client before the new one is installed, so consumers
 * are expected to hold VIONA_PROMISC_ALL across the replacement, narrowing
 * reception only after it succeeds.  VIONA_PROMISC_MULTI does not suffice,
 * as it delivers only multicast and cannot cover the unicast gap left by
 * the removal.
 *
 * This swap also carries any installed multicast table.  Its filters are
 * removed ahead of the unicast removal and reinstalled once an address is
 * in place; holding VIONA_PROMISC_ALL also covers the resulting multicast
 * delivery gap.  Entries refused on reinstallation are dropped from the
 * table and observable via VNA_IOC_GET_MAC_FILTERS.  If that is the only
 * failure, it is reported through VMA_ERR_MCAST_RESTORE.  If address
 * installation fails, the previous address is restored where possible.
 * If even that fails, the client is left with no unicast address and an
 * empty filter table, and filter installation is refused
 * (VMF_ERR_NO_UNICAST) until an address is installed.
 *
 * VNA_IOC_GET_MAC_ADDR reads back the active address, with vma_present
 * distinguishing an installed address from none at all.
 *
 * The table is passed out-of-band rather than embedded in the ioctl
 * structure, so the capacity of the device is not fixed in the ABI.  Both
 * SET ioctls return nonzero only when no result was returned, whether the
 * request went unprocessed on a copyin failure or was processed and the
 * copyout of its result failed; otherwise, vmf_err and vma_err report the
 * semantic error, with vmf_erraddr naming the offending entry for the checks
 * that implicate one, giving the consumer more than a single errno could.
 * Failures prior to installation leave the existing filters untouched.
 * VMF_ERR_INSTALL is the exception, arising after obsolete entries have been
 * removed and earlier new entries installed, leaving a consistent but partial
 * table.  VNA_IOC_GET_MAC_FILTERS reads back the installed table, allowing a
 * consumer to verify what actually took effect.
 *
 * Filter installation is independent of VNA_IOC_SET_PROMISC.  A populated
 * filter table is not mutually exclusive with either promiscuous mode.  While
 * the link remains in VIONA_PROMISC_MULTI, multicast flows through the
 * promiscuous-multicast callback, and viona drops classified copies of those
 * packets, including ones matching installed filters, so the overlap does not
 * duplicate delivery.
 *
 * This overlap is intentional.  Consumers are expected to pair populated
 * filter tables with VIONA_PROMISC_NONE, installing the filters before
 * dropping out of a promiscuous mode and restoring a promiscuous mode before
 * clearing filters when fallback is required, including after a partial
 * installation failure.  This favors transient duplicates during mode
 * transitions over gaps in delivery.  The absence of gaps applies to new
 * arrivals, for which both delivery paths remain active across the
 * transition.  Packets already queued for classified processing when the
 * mode changes are filtered under the new mode.  For example, a unicast
 * packet destined for the client's primary address can be queued before a
 * transition from VIONA_PROMISC_NONE to VIONA_PROMISC_ALL installs the
 * promiscuous callback, then be discarded from the classified path after the
 * new mode is published, despite being accepted in both modes.
 */

/*
 * Current multicast table capacity, which matches the 64-entry convention of
 * other virtio-net devices (QEMU).  A property of the device rather than a
 * promise of the ABI: it may change, and consumers can discover it at runtime
 * via vmf_nmcast on a VMF_ERR_COUNT failure.
 */
#define	VIONA_MAX_MCAST_FILTERS		64

/* Semantic error codes reported through vmf_err */
typedef enum {
	VMF_OK = 0,
	/* Entry count exceeds device capacity (rewritten into vmf_nmcast) */
	VMF_ERR_COUNT,
	/* Entry (in vmf_erraddr) is not a multicast address */
	VMF_ERR_NOT_MCAST,
	/* MAC layer refused installation of the entry (in vmf_erraddr) */
	VMF_ERR_INSTALL,
	/* Client holds no unicast address (after a failed restoration) */
	VMF_ERR_NO_UNICAST,
} vioc_mac_filter_err_t;

/*
 * vmf_addrs holds the user address of an array of vmf_nmcast Ethernet
 * addresses, carried as a uint64_t so the structure layout is datamodel
 * independent.  The array is a compact sequence of ETHERADDRL-byte entries
 * with no per-entry padding (not an array of a struct type which could pad).
 *
 * For VNA_IOC_SET_MAC_FILTERS, vmf_nmcast counts the entries of the table to
 * install.  The ioctl returns nonzero only when no result was returned: the
 * request went unprocessed on a copyin failure, or was processed and the
 * copyout of its result failed.  On a zero return, vmf_err reports the
 * semantic error (VMF_OK on success), with vmf_erraddr naming the offending
 * entry for the checks that implicate one.  On VMF_ERR_COUNT, vmf_nmcast is
 * rewritten with the capacity of the device.
 *
 * For VNA_IOC_GET_MAC_FILTERS, vmf_nmcast counts the entries the buffer at
 * vmf_addrs can hold.  Up to that many installed entries are copied out, and
 * vmf_nmcast is rewritten with the installed count.  A call with vmf_nmcast of
 * zero thus returns the installed count alone.
 */
typedef struct vioc_mac_filters {
	uint32_t	vmf_nmcast;
	uint32_t	vmf_err;	/* vioc_mac_filter_err_t */
	uint8_t		vmf_erraddr[ETHERADDRL];
	uint8_t		vmf_pad[2];
	uint64_t	vmf_addrs;
} vioc_mac_filters_t;

CTASSERT(sizeof (vioc_mac_filters_t) == 24);
CTASSERT(offsetof(vioc_mac_filters_t, vmf_addrs) == 16);

/* Semantic error codes reported through vma_err */
typedef enum {
	VMA_OK = 0,
	/* Requested address has the group bit set (IEEE 802.3) */
	VMA_ERR_NOT_UNICAST,
	/* MAC layer refused installation of the address */
	VMA_ERR_INSTALL,
	/* A multicast filter could not be reinstalled after the swap */
	VMA_ERR_MCAST_RESTORE,
} vioc_mac_addr_err_t;

/*
 * For VNA_IOC_SET_MAC_ADDR, vma_addr carries the unicast address to install
 * in place of the current one.  The ioctl returns nonzero only when no
 * result was returned: the request went unprocessed on a copyin failure, or
 * was processed and the copyout of its result failed.  On a zero return,
 * vma_err reports the semantic error (VMA_OK on success) and vma_present
 * whether an address remains installed, as a failed restoration leaves none.
 *
 * For VNA_IOC_GET_MAC_ADDR, vma_addr is copied out with the active unicast
 * address of the client and vma_present is nonzero.  When no address is
 * installed, such as after a failed restoration, vma_present is zero.
 */
typedef struct vioc_mac_addr {
	uint8_t		vma_addr[ETHERADDRL];
	uint8_t		vma_present;
	uint8_t		vma_pad;
	uint32_t	vma_err;	/* vioc_mac_addr_err_t */
} vioc_mac_addr_t;

CTASSERT(sizeof (vioc_mac_addr_t) == 12);

/*
 * The older VNA_IOC_INTR_POLL API, superseded by VNA_IOC_INTR_POLL_MQ, only
 * polls interrupt status for the first queue pair (two rings).
 */
typedef struct vioc_intr_poll {
	uint32_t	vip_status[2];
} vioc_intr_poll_t;

#define	VIONA_INTR_WORD_BITS	32
#define	VIONA_INTR_WORDS	\
	howmany(VIONA_MAX_QPAIR * 2, VIONA_INTR_WORD_BITS)
#define	VIONA_INTR_WORD(q)	((q) / VIONA_INTR_WORD_BITS)
#define	VIONA_INTR_BIT(q)	(1u << ((q) % VIONA_INTR_WORD_BITS))
#define	VIONA_INTR_SET(vipm, q) \
	(vipm)->vipm_status[VIONA_INTR_WORD(q)] |= VIONA_INTR_BIT(q)
#define	VIONA_INTR_TEST(vipm, q) \
	(((vipm)->vipm_status[VIONA_INTR_WORD(q)] & VIONA_INTR_BIT(q)) != 0)
typedef struct vioc_intr_poll_mq {
	uint16_t	vipm_nrings;
	uint32_t	vipm_status[VIONA_INTR_WORDS];
} vioc_intr_poll_mq_t;

typedef struct vioc_notify_mmio {
	uint64_t	vim_address;
	uint32_t	vim_size;
} vioc_notify_mmio_t;

/*
 * Viona Parameter Interfaces
 *
 * A viona link can have various configuration parameters set upon it.  This is
 * done using packed nvlists in order to communicate those parameters to/from
 * the device driver.
 *
 *
 * Currently supported parameters are:
 * - tx_copy_data (boolean): During packet transmission, should viona copy all
 *   of the packet data, rather than "loaning" those regions of guest memory
 *   (other than the packet headers) in the mblk.
 * - tx_header_pad (uint16): How many bytes (if any) should be left as empty
 *   padding on transmitted packets?  These could be used by subsequent
 *   encapsulation mechanisms in the network stack without the need to
 *   reallocate space for the then-longer header.
 *
 */

/* Maximum size for parameter (or error) packed nvlist buffers */
#define	VIONA_MAX_PARAM_NVLIST_SZ	4096

typedef struct vioc_get_params {
	void	*vgp_param;
	size_t	vgp_param_sz;
} vioc_get_params_t;

typedef struct vioc_set_params {
	void	*vsp_param;
	size_t	vsp_param_sz;
	void	*vsp_error;
	size_t	vsp_error_sz;
} vioc_set_params_t;

#endif	/* _VIONA_IO_H_ */
