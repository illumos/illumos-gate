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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Dataplane test for RX delivery semantics under VNA_IOC_SET_MAC_FILTERS,
 * VNA_IOC_SET_PROMISC, and VNA_IOC_SET_MAC_ADDR state changes.
 *
 * A legacy RX virtqueue is constructed by hand in guest memory and frames are
 * injected from a peered simnet via DLPI.  Across promiscuous modes and
 * installed filter tables, and live transitions between them, the test
 * asserts that unicast, broadcast, and multicast frames are each delivered
 * to the ring exactly once or dropped, as the settled state dictates.
 *
 * The ring is programmed through VNA_IOC_RING_INIT_MODERN, passing explicit
 * descriptor, available, and used ring addresses.  Userland VMMs use that
 * ioctl exclusively, even on behalf of guests that negotiated the legacy
 * transport, and the test does the same.  The transport itself remains
 * legacy, as VIRTIO_F_VERSION_1 is not negotiated, so the virtio-net
 * header and the page-aligned ring layout are those of a legacy guest.
 *
 * Two behaviors are relied upon from simnet.  First, it does not implement
 * MAC_CAPAB_RINGS, so its clients would ordinarily be software classified.
 * With a single active client, mac_rx_common() bypasses that classification
 * and sends every frame accepted by simnet into the client's SRS.  Second,
 * multicast filtering is still observable because simnet emulates a hardware
 * filter at the provider.  Outside of promiscuous mode, it drops multicast
 * frames whose group no MAC client has joined.  This exercises the full path
 * of the filter ioctl, from table installation through mac_multicast_add() to
 * the provider's multicst entry point.  Together, the assertions pin both the
 * viona/MAC delivery contract in each settled state (no duplicates, no gaps
 * for frames arriving once a filter or promiscuity transition completes) and
 * the propagation of table membership to the provider.
 *
 * A final phase recreates the link atop a VNIC, where VNA_IOC_SET_MAC_ADDR
 * follows the in-place update path with no removal ahead of installation,
 * and repeats the unicast delivery assertions across an address swap at the
 * dataplane.
 *
 * Each state is probed only after its transition has settled.  Frames are
 * not injected concurrently with the ioctls themselves, so a defect confined
 * to the transition window would escape these assertions.
 */

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/ethernet.h>
#include <sys/vmm.h>
#include <sys/viona_io.h>
#include <vmmapi.h>
#include <virtio_spec.h>

#include "common.h"
#include "in_guest.h"
#include "viona_suite.h"

/*
 * Guest physical layout for the RX ring and its buffers.
 *
 * The ring size is chosen so that the available ring, which immediately
 * follows the descriptor table in the legacy layout, lands on a page
 * boundary.  viona_ring_layout() requires page alignment for every part of a
 * legacy queue, which a smaller ring cannot satisfy.
 *
 * The addresses need only fall within guest RAM because the VM is backed
 * by MEM_TOTAL_SZ of memory mapped from guest physical address 0 (VM_MMAP_ALL),
 * and no payload executes in it.  Basing the layout at 1 MiB and ending it
 * below MEM_LOC_PAGE_TABLE_2M, the lowest location the common harness
 * populates, keeps it clear of anything else in the guest.
 */
#define	RX_QSZ		256
#define	RX_RING_GPA	0x100000
#define	RX_BUF_GPA	0x110000
#define	RX_BUF_SZ	2048
CTASSERT(RX_BUF_GPA + (RX_QSZ * RX_BUF_SZ) <= MEM_LOC_PAGE_TABLE_2M);

/*
 * Legacy virtio-net header preceding each delivered frame, per virtio 1.3
 * section 5.1.6 and the legacy note in 5.1.6.1 (VIRTIO_NET_F_MRG_RXBUF not
 * negotiated, so no num_buffers field).  Defined here because the in-kernel
 * definitions are private to their drivers. The split virtqueue structures
 * themselves come from the virtio framework's virtio_spec.h.
 */
struct vnet_hdr {
	uint8_t		vnh_flags;
	uint8_t		vnh_gso_type;
	uint16_t	vnh_hdr_len;
	uint16_t	vnh_gso_size;
	uint16_t	vnh_csum_start;
	uint16_t	vnh_csum_offset;
} __packed;
#define	VNET_HDR_SZ	(sizeof (struct vnet_hdr))
CTASSERT(VNET_HDR_SZ == 10);

#define	ETHER_HDR_SZ	(sizeof (struct ether_header))

/* IEEE 802 local experimental ethertype, and a payload tag of our own */
#define	TEST_ETHERTYPE	0x88b5
static const uint8_t test_magic[4] = { 'v', 'R', 'X', 'd' };

#define	MAX_SEQ		64
#define	WARMUP_SEQ	(MAX_SEQ - 1)

/* Polling cadence and wait bounds, in gethrtime(3C) units (nanoseconds) */
#define	POLL_INTERVAL_NS	MSEC2NSEC(10)
#define	WARMUP_RETRY_NS		MSEC2NSEC(100)
#define	DELIVER_TIMEOUT_NS	SEC2NSEC(5)
#define	SETTLE_NS		MSEC2NSEC(250)
#define	ABSENCE_NS		SEC2NSEC(1)

/* Two multicast groups whose filter table membership varies by test state */

/* 224.0.0.1 all-hosts (mapped per RFC 1112 section 6.4) */
static const uint8_t mcast_a[ETHERADDRL] = {
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x01
};
/* ff02::2 all-routers (mapped per RFC 2464 section 7) */
static const uint8_t mcast_b[ETHERADDRL] = {
	0x33, 0x33, 0x00, 0x00, 0x00, 0x02
};
/*
 * Locally administered unicast (default dladm VNIC prefix), standing in for
 * a guest-chosen replacement of its default address
 */
static const uint8_t ucast_repl[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x40
};
/* Fixed addresses of the two test VNICs (passed to create_vnic()) */
static const uint8_t vnic_mac[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x50
};
static const uint8_t vnic2_mac[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x70
};
/* Replacement address for the VNIC-hosted link */
static const uint8_t vnic_repl[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x60
};

/*
 * Volatile pointers ensure that the shared ring fields are accessed on each
 * use.  Explicit producer and consumer barriers below impose the ordering
 * required by virtio when publishing available entries and consuming used
 * entries respectively.
 */
static virtio_vq_desc_t *rx_desc;
static volatile virtio_vq_driver_t *rx_avail;
static volatile virtio_vq_device_t *rx_used;
static uint8_t *rx_bufs;
static uint16_t next_avail;
static uint16_t last_used;

static dlpi_handle_t peer_dh;
static uint8_t peer_mac[ETHERADDRL];
static uint8_t viona_mac[ETHERADDRL];

static uint32_t seq_counter;
static uint32_t seen_count[MAX_SEQ];

/*
 * Consume newly filled used-ring entries, tallying frames which carry the
 * test payload tag and returning their descriptors to the available ring.
 */
static void
drain_used(void)
{
	while (rx_used->vqde_index != last_used) {
		const volatile virtio_vq_elem_t *elem;

		membar_consumer();
		elem = &rx_used->vqde_ring[last_used & (RX_QSZ - 1)];
		const uint32_t id = elem->vqe_start;

		if (id >= RX_QSZ) {
			test_fail_msg("used ring produced bad id %u", id);
		}

		const uint8_t *frame = rx_bufs + (id * RX_BUF_SZ) + VNET_HDR_SZ;
		const struct ether_header *eh =
		    (const struct ether_header *)frame;
		const uint8_t *payload = frame + ETHER_HDR_SZ;

		if (ntohs(eh->ether_type) == TEST_ETHERTYPE &&
		    memcmp(payload, test_magic, sizeof (test_magic)) == 0) {
			uint32_t seq;

			(void) memcpy(&seq, payload + sizeof (test_magic),
			    sizeof (seq));
			if (seq >= MAX_SEQ) {
				test_fail_msg("frame with bad seq %u", seq);
			}
			seen_count[seq]++;
		}

		/*
		 * Return the consumed descriptor to the available ring.
		 * Virtio requires the ring entry store to precede the index
		 * store, so that the device observes a well-formed entry
		 * before the index moves (see the ordering note at the ring
		 * pointer declarations).
		 */
		rx_avail->vqdr_ring[next_avail & (RX_QSZ - 1)] = (uint16_t)id;
		next_avail++;
		membar_producer();
		rx_avail->vqdr_index = next_avail;
		last_used++;
	}
}

static void
send_frame(const uint8_t *dst, uint32_t seq)
{
	uint8_t frame[ETHERMIN] = { 0 };
	struct ether_header hdr = { 0 };
	int err;

	(void) memcpy(&hdr.ether_dhost, dst, ETHERADDRL);
	(void) memcpy(&hdr.ether_shost, peer_mac, ETHERADDRL);
	hdr.ether_type = htons(TEST_ETHERTYPE);
	(void) memcpy(frame, &hdr, sizeof (hdr));
	(void) memcpy(&frame[ETHER_HDR_SZ], test_magic, sizeof (test_magic));
	(void) memcpy(&frame[ETHER_HDR_SZ + sizeof (test_magic)], &seq,
	    sizeof (seq));

	err = dlpi_send(peer_dh, NULL, 0, frame, sizeof (frame), NULL);
	if (err != DLPI_SUCCESS) {
		test_fail_msg("dlpi_send failed: %s", dlpi_strerror(err));
	}
}

/*
 * Sleep one polling interval.  An interrupted, shortened sleep is
 * tolerated, where callers bound their waits with gethrtime(3C) rather than by
 * counting sleeps.
 */
static void
poll_delay(void)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = POLL_INTERVAL_NS,
	};

	(void) nanosleep(&ts, NULL);
}

/* Poll the used ring for a fixed duration, consuming any arrivals. */
static void
drain_for(hrtime_t dur)
{
	const hrtime_t start = gethrtime();

	while (gethrtime() - start < dur) {
		poll_delay();
		drain_used();
	}
}

/*
 * Send a frame to `dst` and require that exactly one copy arrives on the RX
 * ring: the frame must be delivered within the timeout, and no duplicate may
 * arrive within the settle window that follows.
 */
static void
expect_exactly_once(const char *label, const uint8_t *dst)
{
	const uint32_t seq = seq_counter++;
	const hrtime_t start = gethrtime();

	/* WARMUP_SEQ is reserved for warmup() probes */
	if (seq >= WARMUP_SEQ) {
		test_fail_msg("test sequence space exhausted");
	}

	send_frame(dst, seq);

	while (seen_count[seq] == 0) {
		if (gethrtime() - start >= DELIVER_TIMEOUT_NS) {
			test_fail_msg("%s: frame not delivered", label);
		}
		poll_delay();
		drain_used();
	}

	drain_for(SETTLE_NS);

	if (seen_count[seq] != 1) {
		test_fail_msg("%s: expected 1 copy, got %u", label,
		    seen_count[seq]);
	}
}

/*
 * Send a frame to `dst` and require that no copy of it arrives on the RX ring
 * within a bounded absence window.
 */
static void
expect_dropped(const char *label, const uint8_t *dst)
{
	const uint32_t seq = seq_counter++;

	/* WARMUP_SEQ is reserved for warmup() probes */
	if (seq >= WARMUP_SEQ) {
		test_fail_msg("test sequence space exhausted");
	}

	send_frame(dst, seq);
	drain_for(ABSENCE_NS);

	if (seen_count[seq] != 0) {
		test_fail_msg("%s: expected drop, got %u copies", label,
		    seen_count[seq]);
	}
}

/*
 * Unicast and broadcast are expected exactly once in every state.  Multicast
 * delivery depends on the state: under PROMISC_MULTI everything arrives
 * exactly once, with viona suppressing whichever overlapping delivery path
 * would provide a duplicate, while under PROMISC_NONE only groups present in
 * the installed filter table pass the provider's multicast filter.
 */
static void
expect_state(const char *state, bool a_member, bool b_member)
{
	char label[128];

	(void) snprintf(label, sizeof (label), "%s: unicast", state);
	expect_exactly_once(label, viona_mac);
	(void) snprintf(label, sizeof (label), "%s: broadcast", state);
	expect_exactly_once(label, bcast_addr);
	(void) snprintf(label, sizeof (label), "%s: mcast A", state);
	if (a_member) {
		expect_exactly_once(label, mcast_a);
	} else {
		expect_dropped(label, mcast_a);
	}
	(void) snprintf(label, sizeof (label), "%s: mcast B", state);
	if (b_member) {
		expect_exactly_once(label, mcast_b);
	} else {
		expect_dropped(label, mcast_b);
	}
}

static void
set_filters(int vfd, const uint8_t *maddr)
{
	vioc_mac_filters_t vmf;
	uint8_t tab[1][ETHERADDRL];

	(void) memset(&vmf, 0, sizeof (vmf));
	if (maddr != NULL) {
		(void) memcpy(tab[0], maddr, ETHERADDRL);
		vmf.vmf_nmcast = 1;
		vmf.vmf_addrs = (uintptr_t)tab;
	}
	if (ioctl(vfd, VNA_IOC_SET_MAC_FILTERS, &vmf) != 0) {
		test_fail_errno(errno, "VNA_IOC_SET_MAC_FILTERS");
	}
	if (vmf.vmf_err != VMF_OK) {
		test_fail_msg("VNA_IOC_SET_MAC_FILTERS: expected vmf_err "
		    "VMF_OK, got %s", vmf_err_name(vmf.vmf_err));
	}
}

static void
set_promisc(int vfd, viona_promisc_t mode)
{
	if (ioctl(vfd, VNA_IOC_SET_PROMISC, mode) != 0) {
		test_fail_errno(errno, "VNA_IOC_SET_PROMISC");
	}
}

static void
set_mac_addr(int vfd, const uint8_t addr[ETHERADDRL])
{
	vioc_mac_addr_t vma;

	(void) memset(&vma, 0, sizeof (vma));
	(void) memcpy(vma.vma_addr, addr, ETHERADDRL);
	if (ioctl(vfd, VNA_IOC_SET_MAC_ADDR, &vma) != 0) {
		test_fail_errno(errno, "VNA_IOC_SET_MAC_ADDR");
	}
	if (vma.vma_err != VMA_OK) {
		test_fail_msg("VNA_IOC_SET_MAC_ADDR: expected vma_err "
		    "VMA_OK, got %s", vma_err_name(vma.vma_err));
	}
}

static void
setup_rx_ring(struct vmctx *ctx, int vfd)
{
	const size_t map_len = (RX_BUF_GPA - RX_RING_GPA) +
	    (RX_QSZ * RX_BUF_SZ);
	uint8_t *base = vm_map_gpa(ctx, RX_RING_GPA, map_len);

	if (base == NULL) {
		test_fail_msg("could not map guest memory for RX ring");
	}
	(void) memset(base, 0, map_len);

	const size_t desc_sz = RX_QSZ * sizeof (virtio_vq_desc_t);
	/* Available ring, its trailing used_event slot included */
	const size_t avail_sz = sizeof (virtio_vq_driver_t) +
	    (RX_QSZ + 1) * sizeof (uint16_t);
	/* Legacy layout: used ring begins at the next page boundary */
	const size_t used_off = P2ROUNDUP(desc_sz + avail_sz,
	    VIRTIO_PAGE_SIZE);

	rx_desc = (virtio_vq_desc_t *)base;
	rx_avail = (volatile virtio_vq_driver_t *)(base + desc_sz);
	rx_used = (volatile virtio_vq_device_t *)(base + used_off);
	rx_bufs = base + (RX_BUF_GPA - RX_RING_GPA);

	for (uint16_t i = 0; i < RX_QSZ; i++) {
		rx_desc[i].vqd_addr = RX_BUF_GPA + (uint64_t)i * RX_BUF_SZ;
		rx_desc[i].vqd_len = RX_BUF_SZ;
		rx_desc[i].vqd_flags = VIRTQ_DESC_F_WRITE;
		rx_avail->vqdr_ring[i] = i;
	}
	next_avail = RX_QSZ;
	membar_producer();
	rx_avail->vqdr_index = next_avail;
	last_used = 0;

	vioc_ring_init_modern_t ring_ioc = {
		.rim_index = 0,
		.rim_qsize = RX_QSZ,
		.rim_qaddr_desc = RX_RING_GPA,
		.rim_qaddr_avail = RX_RING_GPA + desc_sz,
		.rim_qaddr_used = RX_RING_GPA + used_off,
	};
	if (ioctl(vfd, VNA_IOC_RING_INIT_MODERN, &ring_ioc) != 0) {
		test_fail_errno(errno, "VNA_IOC_RING_INIT_MODERN");
	}
	if (ioctl(vfd, VNA_IOC_RING_KICK, 0) != 0) {
		test_fail_errno(errno, "VNA_IOC_RING_KICK");
	}
}

/*
 * VNA_IOC_RING_KICK only requests ring startup.  The worker thread reaches
 * its running state asynchronously, and frames arriving before it does are
 * silently dropped (viona_rx_ring_deliver()).  No ioctl exposes the run
 * state (VNA_IOC_RING_GET_STATE reports only geometry and indices), and
 * exposing that internal state for a test-only consumer would grow the
 * ioctl ABI while saying nothing about the rest of the delivery path, so
 * delivery itself serves as the readiness signal end-to-end.
 * Probe with unicast frames until one is delivered, then drain whatever
 * probes remain in flight so that the exact-count assertions begin from a
 * clean slate.
 */
static void
warmup(const uint8_t *dst)
{
	/* Bound warmup by the same total wait as a delivery assertion */
	const uint_t max_attempts = DELIVER_TIMEOUT_NS / WARMUP_RETRY_NS;

	for (uint_t attempts = 0; attempts < max_attempts; attempts++) {
		send_frame(dst, WARMUP_SEQ);
		drain_for(WARMUP_RETRY_NS);
		if (seen_count[WARMUP_SEQ] != 0) {
			break;
		}
	}
	if (seen_count[WARMUP_SEQ] == 0) {
		test_fail_msg("no traffic delivered to RX ring after warmup");
	}

	drain_for(SETTLE_NS);

	/*
	 * Multiple warmup probes may have been delivered.  Clear the tally
	 * so no stale count remains if the sequence slot is ever reused.
	 */
	seen_count[WARMUP_SEQ] = 0;
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	int err;

	ctx = test_initialize_plain(suite_name);
	if (ctx == NULL) {
		test_fail_errno(errno, "could not open test VM");
	}
	err = vm_setup_memory(ctx, MEM_TOTAL_SZ, VM_MMAP_ALL);
	if (err != 0) {
		test_fail_errno(err, "could not set up VM memory");
	}

	int vfd = open_viona();
	if (vfd < 0) {
		test_fail_errno(errno, "could not open viona device");
	}

	datalink_id_t dlid;
	dladm_status_t dls = query_dlid(VIONA_TEST_IFACE_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_IFACE_NAME, dladm_status2str(dls, errbuf));
	}

	query_mac(VIONA_TEST_IFACE_NAME, viona_mac);
	create_link(vfd, ctx, dlid);

	/* Legacy virtqueues, no offloads, no VIRTIO_NET_F_MRG_RXBUF */
	uint64_t features = 0;
	if (ioctl(vfd, VNA_IOC_SET_FEATURES, &features) != 0) {
		test_fail_errno(errno, "VNA_IOC_SET_FEATURES");
	}

	setup_rx_ring(ctx, vfd);

	/* Open the injection side on the peered simnet in raw mode */
	err = dlpi_open(VIONA_TEST_PEER_NAME, &peer_dh, DLPI_RAW);
	if (err != DLPI_SUCCESS) {
		test_fail_msg("could not open %s: %s", VIONA_TEST_PEER_NAME,
		    dlpi_strerror(err));
	}
	err = dlpi_bind(peer_dh, TEST_ETHERTYPE, NULL);
	if (err != DLPI_SUCCESS) {
		test_fail_msg("could not bind %s: %s", VIONA_TEST_PEER_NAME,
		    dlpi_strerror(err));
	}
	query_mac(VIONA_TEST_PEER_NAME, peer_mac);

	warmup(viona_mac);

	/* Default state at link creation: PROMISC_MULTI, no filters */
	expect_state("multi promisc, no filters", true, true);

	/*
	 * Consumer transition toward classified multicast: install the table
	 * while multicast promiscuity is still active (the intentional
	 * overlap), then drop out of promiscuity.
	 */
	set_filters(vfd, mcast_a);
	expect_state("multi promisc, filters", true, true);

	set_promisc(vfd, VIONA_PROMISC_NONE);
	expect_state("no promisc, filters", true, false);

	/* Live table replacement, applied differentially by the kernel */
	set_filters(vfd, mcast_b);
	expect_state("no promisc, replaced filters", false, true);

	/* Fallback: widen back to promiscuity before clearing the table */
	set_promisc(vfd, VIONA_PROMISC_MULTI);
	set_filters(vfd, NULL);
	expect_state("multi promisc, filters cleared", true, true);

	/*
	 * VNA_IOC_SET_MAC_ADDR round trip that follows the protocol described
	 * in sys/viona_io.h: hold VIONA_PROMISC_ALL across each swap,
	 * narrowing reception only after it succeeds.  VIONA_PROMISC_MULTI
	 * cannot cover the unicast gap left by the removal.
	 *
	 * The assertions run under VIONA_PROMISC_NONE.  Viona registers both
	 * promiscuous modes without MAC_PROMISC_FLAGS_NO_PHYS (viona_rx.c),
	 * putting the provider itself into promiscuity, so even
	 * VIONA_PROMISC_MULTI would let foreign unicast past the provider's
	 * filter and defeat a dropped baseline.
	 *
	 * A frame for a foreign unicast address is dropped by the provider's
	 * filter until that address is installed in place of the primary.
	 * The explicit installation forces simnet, which lacks
	 * MAC_CAPAB_RINGS and thus any hardware address slots, into device
	 * promiscuity (mac_add_macaddr_vlan()), so frames for the old primary
	 * continue to arrive through the single-client bypass.  Their
	 * delivery is a property of the provider rather than of the
	 * interface, and is not asserted either way.  Returning to the
	 * primary address drops that promiscuous reference and must restore
	 * the original filtering, exercising the MAC_UNICAST_PRIMARY
	 * restoration path at the dataplane.
	 */
	set_promisc(vfd, VIONA_PROMISC_NONE);
	expect_dropped("pre-replacement: foreign unicast", ucast_repl);

	set_promisc(vfd, VIONA_PROMISC_ALL);
	set_mac_addr(vfd, ucast_repl);
	set_promisc(vfd, VIONA_PROMISC_NONE);
	expect_exactly_once("replaced address: unicast", ucast_repl);

	set_promisc(vfd, VIONA_PROMISC_ALL);
	set_mac_addr(vfd, viona_mac);
	set_promisc(vfd, VIONA_PROMISC_NONE);
	expect_exactly_once("restored primary: unicast", viona_mac);
	expect_dropped("restored primary: foreign unicast", ucast_repl);

	/*
	 * Repeat the address swap at the dataplane on a VNIC-hosted link,
	 * where VNA_IOC_SET_MAC_ADDR updates the address in place through
	 * mac_unicast_primary_set() rather than removing the current address
	 * first, so VIONA_PROMISC_ALL is not required around the swaps.
	 *
	 * The drop assertions depend on the second VNIC.  A VNIC's
	 * fixed address is a non-primary unicast, which a provider
	 * without MAC_CAPAB_RINGS can only satisfy via device promiscuity
	 * (mac_add_macaddr_vlan()).  With a single active client, MAC hands
	 * the entire inbound stream to that client without classification
	 * (mac_rx_common()), so every foreign unicast frame would reach the
	 * ring.  The second VNIC raises the simnet's active client count to
	 * two, forcing software classification, under which frames for
	 * uninstalled addresses are dropped.
	 */
	delete_link(vfd);
	create_vnic(VIONA_TEST_VNIC_NAME, vnic_mac);
	create_vnic(VIONA_TEST_VNIC2_NAME, vnic2_mac);

	dls = query_dlid(VIONA_TEST_VNIC_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_VNIC_NAME, dladm_status2str(dls, errbuf));
	}
	create_link(vfd, ctx, dlid);
	if (ioctl(vfd, VNA_IOC_SET_FEATURES, &features) != 0) {
		test_fail_errno(errno, "VNA_IOC_SET_FEATURES");
	}
	setup_rx_ring(ctx, vfd);

	warmup(vnic_mac);

	set_promisc(vfd, VIONA_PROMISC_NONE);
	/*
	 * The installed multicast membership must survive both address
	 * swaps.
	 */
	set_filters(vfd, mcast_a);
	expect_exactly_once("VNIC: unicast", vnic_mac);
	expect_exactly_once("VNIC: broadcast", bcast_addr);
	expect_exactly_once("VNIC: multicast", mcast_a);
	expect_dropped("VNIC: foreign unicast", vnic_repl);

	set_mac_addr(vfd, vnic_repl);
	expect_exactly_once("VNIC replaced: unicast", vnic_repl);
	expect_exactly_once("VNIC replaced: broadcast", bcast_addr);
	expect_exactly_once("VNIC replaced: multicast", mcast_a);
	expect_dropped("VNIC replaced: old unicast", vnic_mac);

	set_mac_addr(vfd, vnic_mac);
	expect_exactly_once("VNIC restored: unicast", vnic_mac);
	expect_exactly_once("VNIC restored: multicast", mcast_a);
	expect_dropped("VNIC restored: foreign unicast", vnic_repl);

	dlpi_close(peer_dh);
	delete_link(vfd);
	delete_vnic(VIONA_TEST_VNIC2_NAME);
	delete_vnic(VIONA_TEST_VNIC_NAME);

	test_pass();
	return (EXIT_SUCCESS);
}
