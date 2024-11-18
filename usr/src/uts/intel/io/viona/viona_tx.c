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
 * Copyright 2024 Oxide Computer Company
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
 * Tunable controls tx copy by default on or off
 */
boolean_t viona_default_tx_copy = B_TRUE;

/*
 * Tunable for maximum configured TX header padding.
 */
uint_t viona_max_header_pad = 256;

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
	vmm_page_t		*d_pages;
};

static void viona_tx(viona_link_t *, viona_vring_t *);
static void viona_desb_release(viona_desb_t *);


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
boolean_t
viona_tx_copy_needed(void)
{
	boolean_t result;

	if (viona_default_tx_copy) {
		return (B_TRUE);
	}

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
	const viona_link_params_t *vlp = &ring->vr_link->l_params;

	ring->vr_tx.vrt_header_pad = vlp->vlp_tx_header_pad;
	/* Allocate desb handles for TX ring if packet copying not forced */
	if (!ring->vr_link->l_params.vlp_tx_copy_data) {
		viona_desb_t *dp =
		    kmem_zalloc(sizeof (viona_desb_t) * qsz, KM_SLEEP);
		ring->vr_tx.vrt_desb = dp;

		const size_t header_sz =
		    VIONA_MAX_HDRS_LEN + ring->vr_tx.vrt_header_pad;
		for (uint_t i = 0; i < qsz; i++, dp++) {
			dp->d_frtn.free_func = viona_desb_release;
			dp->d_frtn.free_arg = (void *)dp;
			dp->d_ring = ring;
			dp->d_headers = kmem_zalloc(header_sz, KM_SLEEP);
		}
	}

	/* Allocate ring-sized iovec buffers for TX */
	ring->vr_tx.vrt_iov = kmem_alloc(sizeof (struct iovec) * qsz, KM_SLEEP);
	ring->vr_tx.vrt_iov_cnt = qsz;
}

void
viona_tx_ring_free(viona_vring_t *ring, const uint16_t qsz)
{
	if (ring->vr_tx.vrt_desb != NULL) {
		viona_desb_t *dp = ring->vr_tx.vrt_desb;

		const size_t header_sz =
		    VIONA_MAX_HDRS_LEN + ring->vr_tx.vrt_header_pad;
		for (uint_t i = 0; i < qsz; i++, dp++) {
			kmem_free(dp->d_headers, header_sz);
		}
		kmem_free(ring->vr_tx.vrt_desb, sizeof (viona_desb_t) * qsz);
		ring->vr_tx.vrt_desb = NULL;
	}

	if (ring->vr_tx.vrt_iov != NULL) {
		ASSERT3U(ring->vr_tx.vrt_iov_cnt, !=, 0);

		kmem_free(ring->vr_tx.vrt_iov,
		    sizeof (struct iovec) * ring->vr_tx.vrt_iov_cnt);
		ring->vr_tx.vrt_iov = NULL;
		ring->vr_tx.vrt_iov_cnt = 0;
	}
}

static void
viona_tx_done(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	vq_pushchain(ring, len, cookie);

	membar_enter();
	viona_intr_ring(ring, B_FALSE);
}

#define	TX_BURST_THRESH	32

void
viona_worker_tx(viona_vring_t *ring, viona_link_t *link)
{
	(void) thread_vsetname(curthread, "viona_tx_%p", ring);

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3U(ring->vr_state, ==, VRS_RUN);

	mutex_exit(&ring->vr_lock);

	for (;;) {
		uint_t ntx = 0, burst = 0;

		viona_ring_disable_notify(ring);
		while (viona_ring_num_avail(ring) != 0) {
			viona_tx(link, ring);
			ntx++;
			burst++;

			/*
			 * It is advantageous for throughput to keep this
			 * transmission loop tight, but periodic breaks to
			 * check for other events are of value too.
			 */
			if (burst >= TX_BURST_THRESH) {
				mutex_enter(&ring->vr_lock);
				const bool need_bail = vring_need_bail(ring);
				mutex_exit(&ring->vr_lock);

				if (need_bail) {
					break;
				}
				burst = 0;
			}
		}

		VIONA_PROBE2(tx, viona_link_t *, link, uint_t, ntx);

		/*
		 * Check for available descriptors on the ring once more in
		 * case a late addition raced with the NO_NOTIFY flag toggle.
		 *
		 * The barrier ensures that visibility of the no-notify
		 * store does not cross the viona_ring_num_avail() check below.
		 */
		viona_ring_enable_notify(ring);
		membar_enter();

		if (viona_ring_num_avail(ring) == 0 &&
		    (link->l_features & VIRTIO_F_RING_NOTIFY_ON_EMPTY) != 0) {
			/*
			 * The NOTIFY_ON_EMPTY interrupt should not pay heed to
			 * the presence of AVAIL_NO_INTERRUPT.
			 */
			viona_intr_ring(ring, B_TRUE);
		}

		mutex_enter(&ring->vr_lock);
		for (;;) {
			if (vring_need_bail(ring)) {
				ring->vr_state = VRS_STOP;
				viona_tx_wait_outstanding(ring);
				return;
			}

			if (vmm_drv_lease_expired(ring->vr_lease)) {
				ring->vr_state_flags |= VRSF_RENEW;
				/*
				 * When renewing the lease for the ring, no TX
				 * frames may be outstanding, as they contain
				 * references to guest memory.
				 */
				viona_tx_wait_outstanding(ring);

				const boolean_t renewed =
				    viona_ring_lease_renew(ring);
				ring->vr_state_flags &= ~VRSF_RENEW;

				if (!renewed) {
					/* stop ring on failed renewal */
					ring->vr_state = VRS_STOP;
					return;
				}
			}

			if (viona_ring_num_avail(ring) != 0) {
				break;
			}

			/* Wait for further activity on the ring */
			(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
		}
		mutex_exit(&ring->vr_lock);
	}
	/* UNREACHABLE */
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
	vmm_drv_page_release_chain(dp->d_pages);
	dp->d_pages = NULL;

	/*
	 * Ensure all other changes to the desb are visible prior to zeroing its
	 * refcount, signifying its readiness for reuse.
	 */
	membar_exit();
	dp->d_ref = 0;

	viona_tx_done(ring, len, cookie);

	mutex_enter(&ring->vr_lock);
	if ((--ring->vr_xfer_outstanding) == 0) {
		cv_broadcast(&ring->vr_cv);
	}
	mutex_exit(&ring->vr_lock);
}

/*
 * Confirm that the requested checksum operation acts within the bounds of the
 * provided packet, and that the checksum itself will be stored in the "copied
 * headers" portion of said packet.
 */
static boolean_t
viona_tx_csum_req_valid(const struct virtio_net_mrgrxhdr *hdr,
    const mac_ether_offload_info_t *meoi, uint_t copied_len)
{
	const uint_t csum_off = hdr->vrh_csum_offset + hdr->vrh_csum_start;

	if (hdr->vrh_csum_start >= meoi->meoi_len ||
	    hdr->vrh_csum_start < meoi->meoi_l2hlen ||
	    csum_off >= meoi->meoi_len ||
	    (csum_off + sizeof (uint16_t)) > copied_len) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Configure mblk to request full checksum offloading, given the virtio and meoi
 * details provided.
 */
static void
viona_tx_hcksum_full(mblk_t *mp, const struct virtio_net_mrgrxhdr *hdr,
    const mac_ether_offload_info_t *meoi, uint32_t added_flags)
{
	/*
	 * Out of caution, zero the checksum field in case any driver and/or
	 * device would erroneously use it in the sum calculation.
	 */
	uint16_t *csump = (uint16_t *)
	    (mp->b_rptr + hdr->vrh_csum_start + hdr->vrh_csum_offset);
	*csump = 0;

	mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM | added_flags);
}

/*
 * Configure mblk to request partial checksum offloading, given the virtio and
 * meoi details provided.
 */
static void
viona_tx_hcksum_partial(mblk_t *mp, const struct virtio_net_mrgrxhdr *hdr,
    const mac_ether_offload_info_t *meoi, uint32_t added_flags)
{
	/*
	 * MAC expects these offsets to be relative to the start of the L3
	 * header rather than the L2 frame.
	 */
	mac_hcksum_set(mp,
	    hdr->vrh_csum_start - meoi->meoi_l2hlen,
	    hdr->vrh_csum_start + hdr->vrh_csum_offset - meoi->meoi_l2hlen,
	    meoi->meoi_len - meoi->meoi_l2hlen,
	    0, HCK_PARTIALCKSUM | added_flags);
}

static boolean_t
viona_tx_offloads(viona_vring_t *ring, const struct virtio_net_mrgrxhdr *hdr,
    const mac_ether_offload_info_t *meoi, mblk_t *mp, uint32_t len)
{
	viona_link_t *link = ring->vr_link;
	const uint32_t cap_csum = link->l_cap_csum;

	/*
	 * Since viona is a "legacy device", the data stored by the driver will
	 * be in the guest's native endian format (see sections 2.4.3 and
	 * 5.1.6.1 of the VIRTIO 1.0 spec for more info). At this time the only
	 * guests using viona are x86 and we can assume little-endian.
	 */
	const uint16_t gso_size = LE_16(hdr->vrh_gso_size);

	if (!viona_tx_csum_req_valid(hdr, meoi, MBLKL(mp))) {
		VIONA_PROBE2(fail_hcksum, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum);
		return (B_FALSE);
	}

	const uint16_t ftype = meoi->meoi_l3proto;
	const uint8_t ipproto = meoi->meoi_l4proto;
	if (ftype != ETHERTYPE_IP && ftype != ETHERTYPE_IPV6) {
		/* Ignore checksum offload requests for non-IP protocols. */
		VIONA_PROBE2(fail_hcksum_proto, viona_link_t *, link,
		    mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum_proto);
		return (B_FALSE);
	}

	/* Configure TCPv4 LSO when requested */
	if ((hdr->vrh_gso_type & VIRTIO_NET_HDR_GSO_TCPV4) != 0 &&
	    ftype == ETHERTYPE_IP) {
		if ((link->l_features & VIRTIO_NET_F_HOST_TSO4) == 0) {
			VIONA_PROBE2(tx_gso_fail, viona_link_t *, link,
			    mblk_t *, mp);
			VIONA_RING_STAT_INCR(ring, tx_gso_fail);
			return (B_FALSE);
		}

		lso_info_set(mp, gso_size, HW_LSO);

		/*
		 * We should have already verified that an adequate form of
		 * hardware checksum offload is present for TSOv4
		 */
		ASSERT3U(cap_csum &
		    (HCKSUM_INET_PARTIAL | HCKSUM_INET_FULL_V4), !=, 0);

		if ((cap_csum & HCKSUM_INET_FULL_V4) != 0) {
			viona_tx_hcksum_full(mp, hdr, meoi, HW_LSO);
		} else if ((cap_csum & HCKSUM_INET_PARTIAL) != 0) {
			/*
			 * Our native IP stack doesn't set the L4 length field
			 * of the pseudo header when LSO is in play.  Other IP
			 * stacks, e.g.  Linux, do include the length field.
			 * This is a problem because the hardware expects that
			 * the length field is not set. When it is set, it will
			 * cause an incorrect TCP checksum to be generated.
			 * Linux avoids this issue by correcting the
			 * pseudo-header checksum in the driver code.
			 *
			 * In order to get the correct HW checksum we need to
			 * assume the guest's IP stack gave us a bogus TCP
			 * partial checksum and calculate it ourselves.
			 */
			ipha_t *ipha =
			    (ipha_t *)(mp->b_rptr + meoi->meoi_l2hlen);
			uint16_t *cksump =
			    IPH_TCPH_CHECKSUMP(ipha, IPH_HDR_LENGTH(ipha));

			uint32_t cksum = IP_TCP_CSUM_COMP;
			const ipaddr_t src = ipha->ipha_src;
			const ipaddr_t dst = ipha->ipha_dst;
			cksum += (dst >> 16) + (dst & 0xffff) +
			    (src >> 16) + (src & 0xffff);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			*cksump = (cksum & 0xffff) + (cksum >> 16);

			/*
			 * NICs such as ixgbe require that ipv4 checksum offload
			 * also be enabled when performing LSO.
			 */
			uint32_t v4csum = 0;
			if ((cap_csum & HCKSUM_IPHDRCKSUM) != 0) {
				v4csum = HCK_IPV4_HDRCKSUM;
				ipha->ipha_hdr_checksum = 0;
			}

			viona_tx_hcksum_partial(mp, hdr, meoi, HW_LSO | v4csum);
		} else {
			/*
			 * This should be unreachable: We do not permit LSO
			 * without adequate checksum offload capability.
			 */
			VIONA_PROBE2(tx_gso_fail, viona_link_t *, link,
			    mblk_t *, mp);
			VIONA_RING_STAT_INCR(ring, tx_gso_fail);
			return (B_FALSE);
		}

		return (B_TRUE);
	}

	/*
	 * Partial checksum support from the NIC is ideal, since it most closely
	 * maps to the interface defined by virtio.
	 */
	if ((cap_csum & HCKSUM_INET_PARTIAL) != 0 &&
	    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
		viona_tx_hcksum_partial(mp, hdr, meoi, 0);
		return (B_TRUE);
	}

	/*
	 * Without partial checksum support, look to the L3/L4 protocol
	 * information to see if the NIC can handle it.  If not, the checksum
	 * will need to calculated inline.
	 */
	if (ftype == ETHERTYPE_IP) {
		if ((cap_csum & HCKSUM_INET_FULL_V4) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			viona_tx_hcksum_full(mp, hdr, meoi, 0);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum);
		return (B_FALSE);
	} else if (ftype == ETHERTYPE_IPV6) {
		if ((cap_csum & HCKSUM_INET_FULL_V6) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			viona_tx_hcksum_full(mp, hdr, meoi, 0);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum6, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum6);
		return (B_FALSE);
	}

	/*
	 * Note the failure for unrecognized protocols, but soldier on to make
	 * our best effort at getting the frame out the door.
	 */
	VIONA_PROBE2(fail_hcksum_proto, viona_link_t *, link, mblk_t *, mp);
	VIONA_RING_STAT_INCR(ring, fail_hcksum_proto);
	return (B_FALSE);
}

static mblk_t *
viona_tx_alloc_headers(viona_vring_t *ring, uint16_t cookie, viona_desb_t **dpp,
    uint32_t len)
{
	ASSERT3P(*dpp, ==, NULL);

	mblk_t *mp = NULL;
	const size_t header_pad = ring->vr_tx.vrt_header_pad;

	if (ring->vr_tx.vrt_desb != NULL) {
		viona_desb_t *dp = &ring->vr_tx.vrt_desb[cookie];
		const size_t header_sz = VIONA_MAX_HDRS_LEN + header_pad;

		/*
		 * If the guest driver is operating properly, each desb slot
		 * should be available for use when processing a TX descriptor
		 * from the 'avail' ring.  In the case of drivers that reuse a
		 * descriptor before it has been posted to the 'used' ring, the
		 * data is simply dropped.
		 */
		if (atomic_cas_uint(&dp->d_ref, 0, 1) != 0) {
			return (NULL);
		}

		dp->d_cookie = cookie;
		mp = desballoc(dp->d_headers, header_sz, 0, &dp->d_frtn);

		if (mp != NULL) {
			/*
			 * Account for the successful desballoc, and communicate
			 * out the desb handle for subsequent use
			 */
			dp->d_ref++;
			*dpp = dp;
		} else {
			/* Reset the desb back to its "available" state */
			dp->d_ref = 0;
		}
	} else {
		/*
		 * If we are going to be copying the entire packet, we might as
		 * well allocate for it all in one go.
		 */
		mp = allocb(len + header_pad, 0);
	}

	/* Push pointers forward to account for requested header padding */
	if (mp != NULL && header_pad != 0) {
		mp->b_rptr = mp->b_wptr = (DB_BASE(mp) + header_pad);
	}

	return (mp);
}

static boolean_t
viona_tx_copy_headers(viona_vring_t *ring, iov_bunch_t *iob, mblk_t *mp,
    mac_ether_offload_info_t *meoi)
{
	ASSERT(mp->b_cont == NULL);

	if (ring->vr_tx.vrt_desb == NULL) {
		/*
		 * If not using guest data loaning through the desb, then we
		 * expect viona_tx_alloc_headers() to have allocated space for
		 * the entire packet, which we should copy now.
		 */
		const uint32_t pkt_size = iob->ib_remain;

		VERIFY(MBLKTAIL(mp) >= pkt_size);
		VERIFY(iov_bunch_copy(iob, mp->b_wptr, pkt_size));
		mp->b_wptr += pkt_size;
		(void) mac_ether_offload_info(mp, meoi);
		return (B_TRUE);
	}

	/*
	 * We want to maximize the amount of guest data we loan when performing
	 * packet transmission, with the caveat that we must copy the packet
	 * headers to prevent TOCTOU issues.
	 */
	const uint32_t copy_sz = MIN(iob->ib_remain, MBLKTAIL(mp));

	VERIFY(iov_bunch_copy(iob, mp->b_wptr, copy_sz));
	mp->b_wptr += copy_sz;

	if (iob->ib_remain == 0) {
		(void) mac_ether_offload_info(mp, meoi);
		return (B_TRUE);
	}

	/*
	 * Attempt to confirm that our buffer contains at least the entire
	 * (L2-L4) packet headers.
	 */
	if (mac_ether_offload_info(mp, meoi) == 0) {
		const uint32_t full_hdr_sz =
		    meoi->meoi_l2hlen + meoi->meoi_l3hlen + meoi->meoi_l4hlen;

		if (copy_sz >= full_hdr_sz) {
			return (B_TRUE);
		}
	}

	/*
	 * Despite our best efforts, the full headers do not appear to be along
	 * for the ride yet.  Just allocate a buffer and copy the remainder of
	 * the packet.
	 */
	const uint32_t remain_sz = iob->ib_remain;
	mblk_t *remain_mp = allocb(remain_sz, 0);
	if (remain_mp == NULL) {
		return (B_FALSE);
	}
	VERIFY(iov_bunch_copy(iob, remain_mp->b_wptr, remain_sz));
	remain_mp->b_wptr += remain_sz;
	mp->b_cont = remain_mp;
	/* Refresh header info now that we have copied the rest */
	(void) mac_ether_offload_info(mp, meoi);

	return (B_TRUE);
}

static void
viona_tx(viona_link_t *link, viona_vring_t *ring)
{
	struct iovec		*iov = ring->vr_tx.vrt_iov;
	const uint_t		max_segs = ring->vr_tx.vrt_iov_cnt;
	uint16_t		cookie;
	vmm_page_t		*pages = NULL;
	uint32_t		total_len;
	mblk_t			*mp_head = NULL;
	viona_desb_t		*dp = NULL;
	const boolean_t merge_enabled =
	    ((link->l_features & VIRTIO_NET_F_MRG_RXBUF) != 0);

	ASSERT(iov != NULL);

	const int n = vq_popchain(ring, iov, max_segs, &cookie, &pages,
	    &total_len);
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

	/*
	 * Get setup to copy the VirtIO header from in front of the packet.
	 *
	 * With an eye toward supporting VirtIO 1.0 behavior in the future, we
	 * determine the size of the header based on the device state.  This
	 * goes a bit beyond the expectations of legacy VirtIO, where the first
	 * buffer must cover the header and nothing else.
	 */
	iov_bunch_t iob = {
		.ib_iov = iov,
		.ib_remain = total_len,
	};
	struct virtio_net_mrgrxhdr hdr;
	uint32_t vio_hdr_len = 0;
	if (merge_enabled) {
		/*
		 * Presence of the "num_bufs" member is determined by the
		 * merge-rxbuf feature on the device, despite the fact that we
		 * are in transmission context here.
		 */
		vio_hdr_len = sizeof (struct virtio_net_mrgrxhdr);
	} else {
		vio_hdr_len = sizeof (struct virtio_net_hdr);
		/*
		 * We ignore "num_bufs" from the guest anyways, but zero it out
		 * just in case.
		 */
		hdr.vrh_bufs = 0;
	}
	uint32_t pkt_len = 0;
	if (!iov_bunch_copy(&iob, &hdr, vio_hdr_len)) {
		goto drop_fail;
	}

	pkt_len = total_len - vio_hdr_len;
	if (pkt_len > VIONA_MAX_PACKET_SIZE ||
	    pkt_len < sizeof (struct ether_header)) {
		goto drop_fail;
	}

	mp_head = viona_tx_alloc_headers(ring, cookie, &dp, pkt_len);
	if (mp_head == NULL) {
		goto drop_fail;
	}

	/*
	 * Copy the the packet headers (L2 through L4, if present) to prevent
	 * TOCTOU attacks in any subsequent consumers of that data.
	 */
	mac_ether_offload_info_t meoi = { 0 };
	if (!viona_tx_copy_headers(ring, &iob, mp_head, &meoi)) {
		goto drop_fail;
	}

	if (dp != NULL && iob.ib_remain != 0) {
		/*
		 * If this device is loaning guest memory, rather than copying
		 * the entire body of the packet, we may need to establish mblks
		 * for the remaining data-to-be-loaned after the header copy.
		 */
		uint32_t chunk_sz;
		caddr_t chunk;
		mblk_t *mp_tail = mp_head;

		/*
		 * Ensure that our view of the tail is accurate in the rare case
		 * that the header allocation/copying logic has already resulted
		 * in a chained mblk.
		 */
		while (mp_tail->b_cont != NULL) {
			mp_tail = mp_tail->b_cont;
		}

		while (iov_bunch_next_chunk(&iob, &chunk, &chunk_sz)) {
			mblk_t *mp = desballoc((uchar_t *)chunk, chunk_sz, 0,
			    &dp->d_frtn);
			if (mp == NULL) {
				goto drop_fail;
			}

			mp->b_wptr += chunk_sz;
			dp->d_ref++;
			mp_tail->b_cont = mp;
			mp_tail = mp;
		}
	} else {
		/* The copy-everything strategy should be done by now */
		VERIFY0(iob.ib_remain);
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
		mblk_t *mp = mp_head;
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
	 * Translate request for offloaded checksumming. If the guest sent an
	 * LSO packet then it must have also negotiated and requested partial
	 * checksum; therefore the LSO logic is contained within
	 * viona_tx_offloads().
	 */
	if ((link->l_features & VIRTIO_NET_F_CSUM) != 0 &&
	    (hdr.vrh_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0) {
		if (!viona_tx_offloads(ring, &hdr, &meoi, mp_head, pkt_len)) {
			/*
			 * If processing of any checksum offload request fails,
			 * we can still pass the packet on for transmission.
			 * Even with this best-effort behavior, which may in
			 * fact succeed in the end, we record it as an error.
			 */
			viona_ring_stat_error(ring);
		}
	}

	if (dp != NULL) {
		/*
		 * Record the info required to record this descriptor in the
		 * used ring once its transmission has completed.
		 */
		dp->d_len = total_len;
		dp->d_pages = pages;
		mutex_enter(&ring->vr_lock);
		ring->vr_xfer_outstanding++;
		mutex_exit(&ring->vr_lock);
	} else {
		/*
		 * If the data was cloned out of the ring, the descriptors can
		 * be marked as 'used' now, rather than deferring that action
		 * until after successful packet transmission.
		 */
		vmm_drv_page_release_chain(pages);
		viona_tx_done(ring, total_len, cookie);
	}

	/*
	 * From viona's point of view, this is a successful transmit, even if
	 * something downstream decides to drop the packet.
	 */
	viona_ring_stat_accept(ring, pkt_len);

	/*
	 * We're potentially going deep into the networking layer; make sure the
	 * guest can't run concurrently.
	 */
	smt_begin_unsafe();
	/*
	 * Ignore, for now, any signal from MAC about whether the outgoing
	 * packet was dropped or not.
	 */
	(void) mac_tx(link->l_mch, mp_head, 0, MAC_DROP_ON_NO_DESC, NULL);
	smt_end_unsafe();
	return;

drop_fail:
	/*
	 * On the off chance that memory is not available via the desballoc or
	 * allocb calls, there are few options left besides to fail and drop
	 * the frame on the floor.
	 *
	 * First account for it in the error stats.
	 */
	viona_ring_stat_error(ring);

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
	if (dp != NULL) {
		VERIFY(dp->d_ref == 2);

		/* Clean up the desb handle, releasing the extra hold. */
		dp->d_len = 0;
		dp->d_cookie = 0;
		dp->d_ref = 0;
	}

	/* Count in the stats as a drop, rather than an error */
	viona_ring_stat_drop(ring);

	VIONA_PROBE3(tx_drop, viona_vring_t *, ring, uint32_t, pkt_len,
	    uint16_t, cookie);
	vmm_drv_page_release_chain(pages);
	viona_tx_done(ring, total_len, cookie);
}
