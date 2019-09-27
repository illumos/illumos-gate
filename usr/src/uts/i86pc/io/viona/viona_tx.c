/*
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 */


#include <sys/types.h>
#include <sys/smt.h>
#include <sys/strsubr.h>

#include <sys/pattr.h>
#include <sys/dlpi.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>

#include "viona_impl.h"

#define	BNXE_NIC_DRIVER		"bnxe"

/*
 * copy tx mbufs from virtio ring to avoid necessitating a wait for packet
 * transmission to free resources.
 */
kmutex_t viona_force_copy_lock;
static enum viona_force_copy {
	VFC_UNINITALIZED	= 0,
	VFC_COPY_UNEEDED	= 1,
	VFC_COPY_REQUIRED	= 2,
} viona_force_copy_state = VFC_UNINITALIZED;

struct viona_desb {
	frtn_t			d_frtn;
	viona_vring_t		*d_ring;
	uint_t			d_ref;
	uint32_t		d_len;
	uint16_t		d_cookie;
	uchar_t			*d_headers;
};

static void viona_tx(viona_link_t *, viona_vring_t *);
static void viona_desb_release(viona_desb_t *);

/*
 * Return the number of available descriptors in the vring taking care of the
 * 16-bit index wraparound.
 *
 * Note: If the number of apparently available descriptors is larger than the
 * ring size (due to guest misbehavior), this check will still report the
 * positive count of descriptors.
 */
static inline uint_t
viona_vr_num_avail(viona_vring_t *ring)
{
	uint16_t ndesc;

	/*
	 * We're just computing (a-b) in GF(216).
	 *
	 * The only glitch here is that in standard C, uint16_t promotes to
	 * (signed) int when int has more than 16 bits (almost always now).
	 * A cast back to unsigned is necessary for proper operation.
	 */
	ndesc = (unsigned)*ring->vr_avail_idx - (unsigned)ring->vr_cur_aidx;

	return (ndesc);
}

static void
viona_tx_wait_outstanding(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	while (ring->vr_xfer_outstanding != 0) {
		/*
		 * Paying heed to signals is counterproductive here.  This is a
		 * very tight loop if pending transfers take an extended amount
		 * of time to be reclaimed while the host process is exiting.
		 */
		cv_wait(&ring->vr_cv, &ring->vr_lock);
	}
}

/*
 * Check if full TX packet copying is needed.  This should not be called from
 * viona attach()/detach() context.
 */
static boolean_t
viona_tx_copy_needed(void)
{
	boolean_t result;

	mutex_enter(&viona_force_copy_lock);
	if (viona_force_copy_state == VFC_UNINITALIZED) {
		major_t bnxe_major;

		/*
		 * The original code for viona featured an explicit check for
		 * the bnxe driver which, when found present, necessitated that
		 * all transmissions be copied into their own mblks instead of
		 * passing guest memory to the underlying device.
		 *
		 * The motivations for this are unclear, but until it can be
		 * proven unnecessary, the check lives on.
		 */
		viona_force_copy_state = VFC_COPY_UNEEDED;
		if ((bnxe_major = ddi_name_to_major(BNXE_NIC_DRIVER))
		    != DDI_MAJOR_T_NONE) {
			if (ddi_hold_installed_driver(bnxe_major) != NULL) {
				viona_force_copy_state = VFC_COPY_REQUIRED;
				ddi_rele_driver(bnxe_major);
			}
		}
	}
	result = (viona_force_copy_state == VFC_COPY_REQUIRED);
	mutex_exit(&viona_force_copy_lock);

	return (result);
}

void
viona_tx_ring_alloc(viona_vring_t *ring, const uint16_t qsz)
{
	/* Allocate desb handles for TX ring if packet copying not disabled */
	if (!viona_tx_copy_needed()) {
		viona_desb_t *dp;

		dp = kmem_zalloc(sizeof (viona_desb_t) * qsz, KM_SLEEP);
		ring->vr_txdesb = dp;
		for (uint_t i = 0; i < qsz; i++, dp++) {
			dp->d_frtn.free_func = viona_desb_release;
			dp->d_frtn.free_arg = (void *)dp;
			dp->d_ring = ring;
			dp->d_headers = kmem_zalloc(VIONA_MAX_HDRS_LEN,
			    KM_SLEEP);
		}
	}

	/* Allocate ring-sized iovec buffers for TX */
	ring->vr_txiov = kmem_alloc(sizeof (struct iovec) * qsz, KM_SLEEP);
}

void
viona_tx_ring_free(viona_vring_t *ring, const uint16_t qsz)
{
	if (ring->vr_txdesb != NULL) {
		viona_desb_t *dp = ring->vr_txdesb;

		for (uint_t i = 0; i < qsz; i++, dp++) {
			kmem_free(dp->d_headers, VIONA_MAX_HDRS_LEN);
		}
		kmem_free(ring->vr_txdesb, sizeof (viona_desb_t) * qsz);
		ring->vr_txdesb = NULL;
	}

	if (ring->vr_txiov != NULL) {
		kmem_free(ring->vr_txiov, sizeof (struct iovec) * qsz);
		ring->vr_txiov = NULL;
	}
}

static void
viona_tx_done(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	vq_pushchain(ring, len, cookie);

	membar_enter();
	if ((*ring->vr_avail_flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
		viona_intr_ring(ring);
	}
}

void
viona_worker_tx(viona_vring_t *ring, viona_link_t *link)
{
	proc_t *p = ttoproc(curthread);

	(void) thread_vsetname(curthread, "viona_tx_%p", ring);

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3U(ring->vr_state, ==, VRS_RUN);

	mutex_exit(&ring->vr_lock);

	for (;;) {
		boolean_t bail = B_FALSE;
		boolean_t renew = B_FALSE;
		uint_t ntx = 0;

		*ring->vr_used_flags |= VRING_USED_F_NO_NOTIFY;
		while (viona_vr_num_avail(ring)) {
			viona_tx(link, ring);

			/*
			 * It is advantageous for throughput to keep this
			 * transmission loop tight, but periodic breaks to
			 * check for other events are of value too.
			 */
			if (ntx++ >= ring->vr_size)
				break;
		}
		*ring->vr_used_flags &= ~VRING_USED_F_NO_NOTIFY;

		VIONA_PROBE2(tx, viona_link_t *, link, uint_t, ntx);

		/*
		 * Check for available descriptors on the ring once more in
		 * case a late addition raced with the NO_NOTIFY flag toggle.
		 *
		 * The barrier ensures that visibility of the vr_used_flags
		 * store does not cross the viona_vr_num_avail() check below.
		 */
		membar_enter();
		bail = VRING_NEED_BAIL(ring, p);
		renew = vmm_drv_lease_expired(ring->vr_lease);
		if (!bail && !renew && viona_vr_num_avail(ring)) {
			continue;
		}

		if ((link->l_features & VIRTIO_F_RING_NOTIFY_ON_EMPTY) != 0) {
			viona_intr_ring(ring);
		}

		mutex_enter(&ring->vr_lock);

		while (!bail && !renew && !viona_vr_num_avail(ring)) {
			(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
			bail = VRING_NEED_BAIL(ring, p);
			renew = vmm_drv_lease_expired(ring->vr_lease);
		}

		if (bail) {
			break;
		} else if (renew) {
			ring->vr_state_flags |= VRSF_RENEW;
			/*
			 * When renewing the lease for the ring, no TX
			 * frames may be outstanding, as they contain
			 * references to guest memory.
			 */
			viona_tx_wait_outstanding(ring);

			if (!viona_ring_lease_renew(ring)) {
				break;
			}
			ring->vr_state_flags &= ~VRSF_RENEW;
		}
		mutex_exit(&ring->vr_lock);
	}

	ASSERT(MUTEX_HELD(&ring->vr_lock));

	ring->vr_state = VRS_STOP;
	viona_tx_wait_outstanding(ring);
}

static void
viona_desb_release(viona_desb_t *dp)
{
	viona_vring_t *ring = dp->d_ring;
	uint_t ref;
	uint32_t len;
	uint16_t cookie;

	ref = atomic_dec_uint_nv(&dp->d_ref);
	if (ref > 1) {
		return;
	}

	/*
	 * The desb corresponding to this index must be ready for reuse before
	 * the descriptor is returned to the guest via the 'used' ring.
	 */
	len = dp->d_len;
	cookie = dp->d_cookie;
	dp->d_len = 0;
	dp->d_cookie = 0;
	dp->d_ref = 0;

	viona_tx_done(ring, len, cookie);

	mutex_enter(&ring->vr_lock);
	if ((--ring->vr_xfer_outstanding) == 0) {
		cv_broadcast(&ring->vr_cv);
	}
	mutex_exit(&ring->vr_lock);
}

static boolean_t
viona_tx_csum(viona_vring_t *ring, const struct virtio_net_hdr *hdr,
    mblk_t *mp, uint32_t len)
{
	viona_link_t *link = ring->vr_link;
	const struct ether_header *eth;
	uint_t eth_len = sizeof (struct ether_header);
	ushort_t ftype;
	ipha_t *ipha = NULL;
	uint8_t ipproto = IPPROTO_NONE; /* NONE is not exactly right, but ok */
	uint16_t flags = 0;
	const uint_t csum_start = hdr->vrh_csum_start;
	const uint_t csum_stuff = hdr->vrh_csum_offset + csum_start;

	/*
	 * Validate that the checksum offsets provided by the guest are within
	 * the bounds of the packet.  Additionally, ensure that the checksum
	 * contents field is within the headers mblk copied by viona_tx().
	 */
	if (csum_start >= len || csum_start < eth_len || csum_stuff >= len ||
	    (csum_stuff + sizeof (uint16_t)) > MBLKL(mp)) {
		VIONA_PROBE2(fail_hcksum, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum);
		return (B_FALSE);
	}

	/*
	 * This is guaranteed to be safe thanks to the header copying
	 * done in viona_tx().
	 */
	eth = (const struct ether_header *)mp->b_rptr;
	ftype = ntohs(eth->ether_type);

	if (ftype == ETHERTYPE_VLAN) {
		const struct ether_vlan_header *veth;

		/* punt on QinQ for now */
		eth_len = sizeof (struct ether_vlan_header);
		veth = (const struct ether_vlan_header *)eth;
		ftype = ntohs(veth->ether_type);
	}

	if (ftype == ETHERTYPE_IP) {
		ipha = (ipha_t *)(mp->b_rptr + eth_len);

		ipproto = ipha->ipha_protocol;
	} else if (ftype == ETHERTYPE_IPV6) {
		ip6_t *ip6h = (ip6_t *)(mp->b_rptr + eth_len);

		ipproto = ip6h->ip6_nxt;
	}

	/*
	 * We ignore hdr_len because the spec says it can't be
	 * trusted. Besides, our own stack will determine the header
	 * boundary.
	 */
	if ((link->l_cap_csum & HCKSUM_INET_PARTIAL) != 0 &&
	    (hdr->vrh_gso_type & VIRTIO_NET_HDR_GSO_TCPV4) != 0 &&
	    ftype == ETHERTYPE_IP) {
		uint16_t	*cksump;
		uint32_t	cksum;
		ipaddr_t	src = ipha->ipha_src;
		ipaddr_t	dst = ipha->ipha_dst;

		/*
		 * Our native IP stack doesn't set the L4 length field
		 * of the pseudo header when LSO is in play. Other IP
		 * stacks, e.g. Linux, do include the length field.
		 * This is a problem because the hardware expects that
		 * the length field is not set. When it is set it will
		 * cause an incorrect TCP checksum to be generated.
		 * The reason this works in Linux is because Linux
		 * corrects the pseudo-header checksum in the driver
		 * code. In order to get the correct HW checksum we
		 * need to assume the guest's IP stack gave us a bogus
		 * TCP partial checksum and calculate it ourselves.
		 */
		cksump = IPH_TCPH_CHECKSUMP(ipha, IPH_HDR_LENGTH(ipha));
		cksum = IP_TCP_CSUM_COMP;
		cksum += (dst >> 16) + (dst & 0xFFFF) +
		    (src >> 16) + (src & 0xFFFF);
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		*(cksump) = (cksum & 0xFFFF) + (cksum >> 16);

		/*
		 * Since viona is a "legacy device", the data stored
		 * by the driver will be in the guest's native endian
		 * format (see sections 2.4.3 and 5.1.6.1 of the
		 * VIRTIO 1.0 spec for more info). At this time the
		 * only guests using viona are x86 and we can assume
		 * little-endian.
		 */
		lso_info_set(mp, LE_16(hdr->vrh_gso_size), HW_LSO);

		/*
		 * Hardware, like ixgbe, expects the client to request
		 * IP header checksum offload if it's sending LSO (see
		 * ixgbe_get_context()). Unfortunately, virtio makes
		 * no allowances for negotiating IP header checksum
		 * and HW offload, only TCP checksum. We add the flag
		 * and zero-out the checksum field. This mirrors the
		 * behavior of our native IP stack (which does this in
		 * the interest of HW that expects the field to be
		 * zero).
		 */
		flags |= HCK_IPV4_HDRCKSUM;
		ipha->ipha_hdr_checksum = 0;
	}

	/*
	 * Use DB_CKSUMFLAGS instead of mac_hcksum_get() to make sure
	 * HW_LSO, if present, is not lost.
	 */
	flags |= DB_CKSUMFLAGS(mp);

	/*
	 * Partial checksum support from the NIC is ideal, since it most
	 * closely maps to the interface defined by virtio.
	 */
	if ((link->l_cap_csum & HCKSUM_INET_PARTIAL) != 0 &&
	    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
		/*
		 * MAC expects these offsets to be relative to the
		 * start of the L3 header rather than the L2 frame.
		 */
		flags |= HCK_PARTIALCKSUM;
		mac_hcksum_set(mp, csum_start - eth_len, csum_stuff - eth_len,
		    len - eth_len, 0, flags);
		return (B_TRUE);
	}

	/*
	 * Without partial checksum support, look to the L3/L4 protocol
	 * information to see if the NIC can handle it.  If not, the
	 * checksum will need to calculated inline.
	 */
	if (ftype == ETHERTYPE_IP) {
		if ((link->l_cap_csum & HCKSUM_INET_FULL_V4) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			uint16_t *csump = (uint16_t *)(mp->b_rptr + csum_stuff);
			*csump = 0;
			flags |= HCK_FULLCKSUM;
			mac_hcksum_set(mp, 0, 0, 0, 0, flags);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum);
		return (B_FALSE);
	} else if (ftype == ETHERTYPE_IPV6) {
		if ((link->l_cap_csum & HCKSUM_INET_FULL_V6) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			uint16_t *csump = (uint16_t *)(mp->b_rptr + csum_stuff);
			*csump = 0;
			flags |= HCK_FULLCKSUM;
			mac_hcksum_set(mp, 0, 0, 0, 0, flags);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum6, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum6);
		return (B_FALSE);
	}

	/* Cannot even emulate hcksum for unrecognized protocols */
	VIONA_PROBE2(fail_hcksum_proto, viona_link_t *, link, mblk_t *, mp);
	VIONA_RING_STAT_INCR(ring, fail_hcksum_proto);
	return (B_FALSE);
}

static void
viona_tx(viona_link_t *link, viona_vring_t *ring)
{
	struct iovec		*iov = ring->vr_txiov;
	const uint_t		max_segs = ring->vr_size;
	uint16_t		cookie;
	int			i, n;
	uint32_t		len, base_off = 0;
	uint32_t		min_copy = VIONA_MAX_HDRS_LEN;
	mblk_t			*mp_head, *mp_tail, *mp;
	viona_desb_t		*dp = NULL;
	mac_client_handle_t	link_mch = link->l_mch;
	const struct virtio_net_hdr *hdr;

	mp_head = mp_tail = NULL;

	ASSERT(iov != NULL);

	n = vq_popchain(ring, iov, max_segs, &cookie);
	if (n == 0) {
		VIONA_PROBE1(tx_absent, viona_vring_t *, ring);
		VIONA_RING_STAT_INCR(ring, tx_absent);
		return;
	} else if (n < 0) {
		/*
		 * Any error encountered in vq_popchain has already resulted in
		 * specific probe and statistic handling.  Further action here
		 * is unnecessary.
		 */
		return;
	}

	/* Grab the header and ensure it is of adequate length */
	hdr = (const struct virtio_net_hdr *)iov[0].iov_base;
	len = iov[0].iov_len;
	if (len < sizeof (struct virtio_net_hdr)) {
		goto drop_fail;
	}

	/* Make sure the packet headers are always in the first mblk. */
	if (ring->vr_txdesb != NULL) {
		dp = &ring->vr_txdesb[cookie];

		/*
		 * If the guest driver is operating properly, each desb slot
		 * should be available for use when processing a TX descriptor
		 * from the 'avail' ring.  In the case of drivers that reuse a
		 * descriptor before it has been posted to the 'used' ring, the
		 * data is simply dropped.
		 */
		if (atomic_cas_uint(&dp->d_ref, 0, 1) != 0) {
			dp = NULL;
			goto drop_fail;
		}

		dp->d_cookie = cookie;
		mp_head = desballoc(dp->d_headers, VIONA_MAX_HDRS_LEN, 0,
		    &dp->d_frtn);

		/* Account for the successful desballoc. */
		if (mp_head != NULL)
			dp->d_ref++;
	} else {
		mp_head = allocb(VIONA_MAX_HDRS_LEN, 0);
	}

	if (mp_head == NULL)
		goto drop_fail;

	mp_tail = mp_head;

	/*
	 * We always copy enough of the guest data to cover the
	 * headers. This protects us from TOCTOU attacks and allows
	 * message block length assumptions to be made in subsequent
	 * code. In many cases, this means copying more data than
	 * strictly necessary. That's okay, as it is the larger packets
	 * (such as LSO) that really benefit from desballoc().
	 */
	for (i = 1; i < n; i++) {
		const uint32_t to_copy = MIN(min_copy, iov[i].iov_len);

		bcopy(iov[i].iov_base, mp_head->b_wptr, to_copy);
		mp_head->b_wptr += to_copy;
		len += to_copy;
		min_copy -= to_copy;

		/*
		 * We've met the minimum copy requirement. The rest of
		 * the guest data can be referenced.
		 */
		if (min_copy == 0) {
			/*
			 * If we copied all contents of this
			 * descriptor then move onto the next one.
			 * Otherwise, record how far we are into the
			 * current descriptor.
			 */
			if (iov[i].iov_len == to_copy)
				i++;
			else
				base_off = to_copy;

			break;
		}
	}

	ASSERT3P(mp_head, !=, NULL);
	ASSERT3P(mp_tail, !=, NULL);

	for (; i < n; i++) {
		uintptr_t base = (uintptr_t)iov[i].iov_base + base_off;
		uint32_t chunk = iov[i].iov_len - base_off;

		ASSERT3U(base_off, <, iov[i].iov_len);
		ASSERT3U(chunk, >, 0);

		if (dp != NULL) {
			mp = desballoc((uchar_t *)base, chunk, 0, &dp->d_frtn);
			if (mp == NULL) {
				goto drop_fail;
			}
			dp->d_ref++;
		} else {
			mp = allocb(chunk, BPRI_MED);
			if (mp == NULL) {
				goto drop_fail;
			}
			bcopy((uchar_t *)base, mp->b_wptr, chunk);
		}

		base_off = 0;
		len += chunk;
		mp->b_wptr += chunk;
		mp_tail->b_cont = mp;
		mp_tail = mp;
	}

	if (VNETHOOK_INTERESTED_OUT(link->l_neti)) {
		/*
		 * The hook consumer may elect to free the mblk_t and set
		 * our mblk_t ** to NULL.  When using a viona_desb_t
		 * (dp != NULL), we do not want the corresponding cleanup to
		 * occur during the viona_hook() call. We instead want to
		 * reset and recycle dp for future use.  To prevent cleanup
		 * during the viona_hook() call, we take a ref on dp (if being
		 * used), and release it on success.  On failure, the
		 * freemsgchain() call will release all the refs taken earlier
		 * in viona_tx() (aside from the initial ref and the one we
		 * take), and drop_hook will reset dp for reuse.
		 */
		if (dp != NULL)
			dp->d_ref++;

		/*
		 * Pass &mp instead of &mp_head so we don't lose track of
		 * mp_head if the hook consumer (i.e. ipf) elects to free mp
		 * and set mp to NULL.
		 */
		mp = mp_head;
		if (viona_hook(link, ring, &mp, B_TRUE) != 0) {
			if (mp != NULL)
				freemsgchain(mp);
			goto drop_hook;
		}

		if (dp != NULL) {
			dp->d_ref--;

			/*
			 * It is possible that the hook(s) accepted the packet,
			 * but as part of its processing, it issued a pull-up
			 * which released all references to the desb.  In that
			 * case, go back to acting like the packet is entirely
			 * copied (which it is).
			 */
			if (dp->d_ref == 1) {
				dp->d_cookie = 0;
				dp->d_ref = 0;
				dp = NULL;
			}
		}
	}

	/*
	 * Request hardware checksumming, if necessary. If the guest
	 * sent an LSO packet then it must have also negotiated and
	 * requested partial checksum; therefore the LSO logic is
	 * contained within viona_tx_csum().
	 */
	if ((link->l_features & VIRTIO_NET_F_CSUM) != 0 &&
	    (hdr->vrh_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0) {
		if (!viona_tx_csum(ring, hdr, mp_head, len - iov[0].iov_len)) {
			goto drop_fail;
		}
	}

	if (dp != NULL) {
		dp->d_len = len;
		mutex_enter(&ring->vr_lock);
		ring->vr_xfer_outstanding++;
		mutex_exit(&ring->vr_lock);
	} else {
		/*
		 * If the data was cloned out of the ring, the descriptors can
		 * be marked as 'used' now, rather than deferring that action
		 * until after successful packet transmission.
		 */
		viona_tx_done(ring, len, cookie);
	}

	/*
	 * We're potentially going deep into the networking layer; make sure the
	 * guest can't run concurrently.
	 */
	smt_begin_unsafe();
	mac_tx(link_mch, mp_head, 0, MAC_DROP_ON_NO_DESC, NULL);
	smt_end_unsafe();
	return;

drop_fail:
	/*
	 * On the off chance that memory is not available via the desballoc or
	 * allocb calls, there are few options left besides to fail and drop
	 * the frame on the floor.
	 */

	if (dp != NULL) {
		/*
		 * Take an additional reference on the desb handle (if present)
		 * so any desballoc-sourced mblks can release their hold on it
		 * without the handle reaching its final state and executing
		 * its clean-up logic.
		 */
		dp->d_ref++;
	}

	/*
	 * Free any already-allocated blocks and sum up the total length of the
	 * dropped data to be released to the used ring.
	 */
	freemsgchain(mp_head);

drop_hook:
	len = 0;
	for (uint_t i = 0; i < n; i++) {
		len += iov[i].iov_len;
	}

	if (dp != NULL) {
		VERIFY(dp->d_ref == 2);

		/* Clean up the desb handle, releasing the extra hold. */
		dp->d_len = 0;
		dp->d_cookie = 0;
		dp->d_ref = 0;
	}

	VIONA_PROBE3(tx_drop, viona_vring_t *, ring, uint32_t, len,
	    uint16_t, cookie);
	viona_tx_done(ring, len, cookie);
}
