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
 * Copyright 2025 Oxide Computer Company
 * Copyright 2022 Michael Zeller
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/strsubr.h>

#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/vlan.h>

#include "viona_impl.h"



#define	VTNET_MAXSEGS		32

/* Min. octets in an ethernet frame minus FCS */
#define	MIN_BUF_SIZE		60
#define	NEED_VLAN_PAD_SIZE	(MIN_BUF_SIZE - VLAN_TAGSZ)

static mblk_t *viona_vlan_pad_mp;

void
viona_rx_init(void)
{
	mblk_t *mp;

	ASSERT(viona_vlan_pad_mp == NULL);

	/* Create mblk for padding when VLAN tags are stripped */
	mp = allocb_wait(VLAN_TAGSZ, BPRI_HI, STR_NOSIG, NULL);
	bzero(mp->b_rptr, VLAN_TAGSZ);
	mp->b_wptr += VLAN_TAGSZ;
	viona_vlan_pad_mp = mp;
}

void
viona_rx_fini(void)
{
	mblk_t *mp;

	/* Clean up the VLAN padding mblk */
	mp = viona_vlan_pad_mp;
	viona_vlan_pad_mp = NULL;
	VERIFY(mp != NULL && mp->b_cont == NULL);
	freemsg(mp);
}

void
viona_worker_rx(viona_vring_t *ring, viona_link_t *link)
{
	(void) thread_vsetname(curthread, "viona_rx_%p", ring);

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3U(ring->vr_state, ==, VRS_RUN);

	viona_ring_disable_notify(ring);

	do {
		if (vmm_drv_lease_expired(ring->vr_lease)) {
			/*
			 * Set the renewal flag, causing incoming traffic to be
			 * dropped, and issue an RX barrier to ensure any
			 * threads in the RX callbacks will have finished.
			 * The vr_lock cannot be held across the barrier as it
			 * poses a deadlock risk.
			 */
			ring->vr_state_flags |= VRSF_RENEW;
			mutex_exit(&ring->vr_lock);
			mac_rx_barrier(link->l_mch);
			mutex_enter(&ring->vr_lock);

			if (!viona_ring_lease_renew(ring)) {
				break;
			}
			ring->vr_state_flags &= ~VRSF_RENEW;
		}

		/*
		 * For now, there is little to do in the RX worker as inbound
		 * data is delivered by MAC via the RX callbacks.  If tap-like
		 * functionality is added later, this would be a convenient
		 * place to inject frames into the guest.
		 */
		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
	} while (!vring_need_bail(ring));

	ring->vr_state = VRS_STOP;

	/*
	 * The RX ring is stopping, before we start tearing it down it
	 * is imperative that we perform an RX barrier so that
	 * incoming packets are dropped at viona_rx_classified().
	 */
	mutex_exit(&ring->vr_lock);
	mac_rx_barrier(link->l_mch);
	mutex_enter(&ring->vr_lock);

	/*
	 * If we bailed while renewing the ring lease, we cannot reset
	 * USED_NO_NOTIFY, since we lack a valid mapping to do so.
	 */
	if (ring->vr_lease != NULL) {
		viona_ring_enable_notify(ring);
	}
}

static size_t
viona_copy_mblk(const mblk_t *mp, size_t seek, caddr_t buf, size_t len,
    boolean_t *end)
{
	size_t copied = 0;
	size_t off = 0;

	/* Seek past already-consumed data */
	while (seek > 0 && mp != NULL) {
		const size_t chunk = MBLKL(mp);

		if (chunk > seek) {
			off = seek;
			break;
		}
		mp = mp->b_cont;
		seek -= chunk;
	}

	while (mp != NULL) {
		const size_t chunk = MBLKL(mp) - off;
		const size_t to_copy = MIN(chunk, len);

		bcopy(mp->b_rptr + off, buf, to_copy);
		copied += to_copy;
		buf += to_copy;
		len -= to_copy;

		/*
		 * If all the remaining data in the mblk_t was copied, move on
		 * to the next one in the chain.  Any seek offset applied to
		 * the first mblk copy is zeroed out for subsequent operations.
		 */
		if (chunk == to_copy) {
			mp = mp->b_cont;
			off = 0;
		}
#ifdef DEBUG
		else {
			/*
			 * The only valid reason for the copy to consume less
			 * than the entire contents of the mblk_t is because
			 * the output buffer has been filled.
			 */
			ASSERT0(len);
		}
#endif

		/* Go no further if the buffer has been filled */
		if (len == 0) {
			break;
		}

	}
	*end = (mp == NULL);
	return (copied);
}

static int
viona_recv_plain(viona_vring_t *ring, const mblk_t *mp, size_t msz)
{
	struct iovec iov[VTNET_MAXSEGS];
	uint16_t cookie;
	int n;
	const size_t hdr_sz = sizeof (struct virtio_net_hdr);
	struct virtio_net_hdr *hdr;
	size_t len, copied = 0;
	caddr_t buf = NULL;
	boolean_t end = B_FALSE;
	const uint32_t features = ring->vr_link->l_features;
	vmm_page_t *pages = NULL;

	ASSERT(msz >= MIN_BUF_SIZE);

	n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie, &pages, NULL);
	if (n <= 0) {
		/* Without available buffers, the frame must be dropped. */
		return (ENOSPC);
	}
	if (iov[0].iov_len < hdr_sz) {
		/*
		 * There is little to do if there is not even space available
		 * for the sole header.  Zero the buffer and bail out as a last
		 * act of desperation.
		 */
		bzero(iov[0].iov_base, iov[0].iov_len);
		goto bad_frame;
	}

	/* Grab the address of the header before anything else */
	hdr = (struct virtio_net_hdr *)iov[0].iov_base;

	/*
	 * If there is any space remaining in the first buffer after writing
	 * the header, fill it with frame data.
	 */
	if (iov[0].iov_len > hdr_sz) {
		buf = (caddr_t)iov[0].iov_base + hdr_sz;
		len = iov[0].iov_len - hdr_sz;

		copied += viona_copy_mblk(mp, copied, buf, len, &end);
	}

	/* Copy any remaining data into subsequent buffers, if present */
	for (int i = 1; i < n && !end; i++) {
		buf = (caddr_t)iov[i].iov_base;
		len = iov[i].iov_len;

		copied += viona_copy_mblk(mp, copied, buf, len, &end);
	}

	/* Was the expected amount of data copied? */
	if (copied != msz) {
		VIONA_PROBE5(too_short, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp, size_t, copied,
		    size_t, msz);
		VIONA_RING_STAT_INCR(ring, too_short);
		goto bad_frame;
	}

	/* Populate (read: zero) the header and account for it in the size */
	bzero(hdr, hdr_sz);
	copied += hdr_sz;

	/* Add chksum bits, if needed */
	if ((features & VIRTIO_NET_F_GUEST_CSUM) != 0) {
		uint32_t cksum_flags;

		if (((features & VIRTIO_NET_F_GUEST_TSO4) != 0) &&
		    ((DB_CKSUMFLAGS(mp) & HW_LSO) != 0)) {
			hdr->vrh_gso_type |= VIRTIO_NET_HDR_GSO_TCPV4;
			hdr->vrh_gso_size = DB_LSOMSS(mp);
		}

		mac_hcksum_get((mblk_t *)mp, NULL, NULL, NULL, NULL,
		    &cksum_flags);
		if ((cksum_flags & HCK_FULLCKSUM_OK) != 0) {
			hdr->vrh_flags |= VIRTIO_NET_HDR_F_DATA_VALID;
		}
	}

	/* Release this chain */
	vmm_drv_page_release_chain(pages);
	vq_pushchain(ring, copied, cookie);
	return (0);

bad_frame:
	VIONA_PROBE3(bad_rx_frame, viona_vring_t *, ring, uint16_t, cookie,
	    mblk_t *, mp);
	VIONA_RING_STAT_INCR(ring, bad_rx_frame);

	vmm_drv_page_release_chain(pages);
	vq_pushchain(ring, MAX(copied, MIN_BUF_SIZE + hdr_sz), cookie);
	return (EINVAL);
}

static int
viona_recv_merged(viona_vring_t *ring, const mblk_t *mp, size_t msz)
{
	struct iovec iov[VTNET_MAXSEGS];
	used_elem_t uelem[VTNET_MAXSEGS];
	vmm_page_t *pages = NULL, *hdr_pages = NULL;
	int n, i = 0, buf_idx = 0, err = 0;
	uint16_t cookie;
	caddr_t buf;
	size_t len, copied = 0, chunk = 0;
	struct virtio_net_mrgrxhdr *hdr = NULL;
	const size_t hdr_sz = sizeof (struct virtio_net_mrgrxhdr);
	boolean_t end = B_FALSE;
	const uint32_t features = ring->vr_link->l_features;

	ASSERT(msz >= MIN_BUF_SIZE);

	n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie, &hdr_pages, NULL);
	if (n <= 0) {
		/* Without available buffers, the frame must be dropped. */
		VIONA_PROBE2(no_space, viona_vring_t *, ring, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, no_space);
		return (ENOSPC);
	}
	if (iov[0].iov_len < hdr_sz) {
		/*
		 * There is little to do if there is not even space available
		 * for the sole header.  Zero the buffer and bail out as a last
		 * act of desperation.
		 */
		bzero(iov[0].iov_base, iov[0].iov_len);
		uelem[0].id = cookie;
		uelem[0].len = iov[0].iov_len;
		err = EINVAL;
		goto done;
	}

	/* Grab the address of the header and do initial population */
	hdr = (struct virtio_net_mrgrxhdr *)iov[0].iov_base;
	bzero(hdr, hdr_sz);
	hdr->vrh_bufs = 1;

	/*
	 * If there is any space remaining in the first buffer after writing
	 * the header, fill it with frame data.  The size of the header itself
	 * is accounted for later.
	 */
	if (iov[0].iov_len > hdr_sz) {
		buf = iov[0].iov_base + hdr_sz;
		len = iov[0].iov_len - hdr_sz;

		size_t copy_len;
		copy_len = viona_copy_mblk(mp, copied, buf, len, &end);
		chunk += copy_len;
		copied += copy_len;
	}
	i = 1;

	do {
		while (i < n && !end) {
			buf = iov[i].iov_base;
			len = iov[i].iov_len;

			size_t copy_len;
			copy_len = viona_copy_mblk(mp, copied, buf, len, &end);
			chunk += copy_len;
			copied += copy_len;
			i++;
		}

		uelem[buf_idx].id = cookie;
		uelem[buf_idx].len = chunk;

		/*
		 * Try to grab another buffer from the ring if the mblk has not
		 * yet been entirely copied out.
		 */
		if (!end) {
			if (buf_idx == (VTNET_MAXSEGS - 1)) {
				/*
				 * Our arbitrary limit on the number of buffers
				 * to offer for merge has already been reached.
				 */
				err = EOVERFLOW;
				break;
			}
			if (pages != NULL) {
				vmm_drv_page_release_chain(pages);
				pages = NULL;
			}
			n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie,
			    &pages, NULL);
			if (n <= 0) {
				/*
				 * Without more immediate space to perform the
				 * copying, there is little choice left but to
				 * drop the packet.
				 */
				err = EMSGSIZE;
				break;
			}
			chunk = 0;
			i = 0;
			buf_idx++;
			/*
			 * Keep the header up-to-date with the number of
			 * buffers, but never reference its value since the
			 * guest could meddle with it.
			 */
			hdr->vrh_bufs++;
		}
	} while (!end && copied < msz);

	/* Account for the header size in the first buffer */
	uelem[0].len += hdr_sz;

	/*
	 * If no other errors were encounted during the copy, was the expected
	 * amount of data transferred?
	 */
	if (err == 0 && copied != msz) {
		VIONA_PROBE5(too_short, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp, size_t, copied,
		    size_t, msz);
		VIONA_RING_STAT_INCR(ring, too_short);
		err = EINVAL;
	}

	/* Add chksum bits, if needed */
	if ((features & VIRTIO_NET_F_GUEST_CSUM) != 0) {
		uint32_t cksum_flags;

		if (((features & VIRTIO_NET_F_GUEST_TSO4) != 0) &&
		    ((DB_CKSUMFLAGS(mp) & HW_LSO) != 0)) {
			hdr->vrh_gso_type |= VIRTIO_NET_HDR_GSO_TCPV4;
			hdr->vrh_gso_size = DB_LSOMSS(mp);
		}

		mac_hcksum_get((mblk_t *)mp, NULL, NULL, NULL, NULL,
		    &cksum_flags);
		if ((cksum_flags & HCK_FULLCKSUM_OK) != 0) {
			hdr->vrh_flags |= VIRTIO_NET_HDR_F_DATA_VALID;
		}
	}

done:
	switch (err) {
	case 0:
		/* Success can fall right through to ring delivery */
		break;

	case EMSGSIZE:
		VIONA_PROBE3(rx_merge_underrun, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, rx_merge_underrun);
		break;

	case EOVERFLOW:
		VIONA_PROBE3(rx_merge_overrun, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, rx_merge_overrun);
		break;

	default:
		VIONA_PROBE3(bad_rx_frame, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, bad_rx_frame);
	}

	if (hdr_pages != NULL) {
		vmm_drv_page_release_chain(hdr_pages);
	}
	if (pages != NULL) {
		vmm_drv_page_release_chain(pages);
	}
	vq_pushchain_many(ring, buf_idx + 1, uelem);
	return (err);
}

static void
viona_rx_common(viona_vring_t *ring, mblk_t *mp, boolean_t is_loopback)
{
	viona_link_t *link = ring->vr_link;
	mblk_t *mprx = NULL, **mprx_prevp = &mprx;
	mblk_t *mpdrop = NULL, **mpdrop_prevp = &mpdrop;
	const boolean_t do_merge =
	    (link->l_features & VIRTIO_NET_F_MRG_RXBUF) != 0;
	const boolean_t allow_gro =
	    (link->l_features & VIRTIO_NET_F_GUEST_TSO4) != 0;

	size_t cnt_accept = 0, size_accept = 0, cnt_drop = 0;

	while (mp != NULL) {
		mblk_t *next = mp->b_next;
		mblk_t *pad = NULL;
		size_t size = msgsize(mp);
		int err = 0;

		mp->b_next = NULL;

		/*
		 * We treat both a 'drop' response and errors the same here
		 * and put the packet on the drop chain.  As packets may be
		 * subject to different actions in ipf (which do not all
		 * return the same set of error values), an error processing
		 * one packet doesn't mean the next packet will also generate
		 * an error.
		 */
		if (VNETHOOK_INTERESTED_IN(link->l_neti) &&
		    viona_hook(link, ring, &mp, B_FALSE) != 0) {
			if (mp != NULL) {
				*mpdrop_prevp = mp;
				mpdrop_prevp = &mp->b_next;
			} else {
				/*
				 * If the hook consumer (e.g. ipf) already
				 * freed the mblk_t, update the drop count now.
				 */
				cnt_drop++;
			}
			mp = next;
			continue;
		}

		/*
		 * Virtio devices are prohibited from passing on packets larger
		 * than the MTU + Eth if the guest has not negotiated GRO flags
		 * (e.g., GUEST_TSO*). This occurs irrespective of `do_merge`.
		 */
		if (size > sizeof (struct ether_header) + link->l_mtu) {
			const boolean_t can_emu_lso = DB_LSOMSS(mp) != 0;
			const boolean_t attempt_emu =
			    !allow_gro || size > VIONA_GRO_MAX_PACKET_SIZE;

			if ((DB_CKSUMFLAGS(mp) & HW_LSO) == 0 ||
			    (attempt_emu && !can_emu_lso)) {
				VIONA_PROBE3(rx_drop_over_mtu, viona_vring_t *,
				    ring, mblk_t *, mp, size_t, size);
				VIONA_RING_STAT_INCR(ring, rx_drop_over_mtu);
				err = E2BIG;
				goto pad_drop;
			}

			/*
			 * If the packet has come from another device or viona
			 * which expected to make use of LSO, we can split the
			 * packet on its behalf.
			 */
			if (attempt_emu) {
				mblk_t *tail = NULL;
				uint_t n_pkts = 0;

				/*
				 * Emulation of LSO requires that cksum offload
				 * be enabled on the mblk.
				 */
				if ((DB_CKSUMFLAGS(mp) &
				    (HCK_FULLCKSUM | HCK_PARTIALCKSUM)) == 0) {
					DB_CKSUMFLAGS(mp) |= HCK_FULLCKSUM;
				}

				/*
				 * IPv4 packets should have the offload enabled
				 * for the IPv4 header checksum.
				 */
				mac_ether_offload_info_t meoi;
				mac_ether_offload_info(mp, &meoi);
				if ((meoi.meoi_flags & MEOI_L2INFO_SET) != 0 &&
				    meoi.meoi_l3proto == ETHERTYPE_IP) {
					DB_CKSUMFLAGS(mp) |= HCK_IPV4_HDRCKSUM;
				}

				mac_hw_emul(&mp, &tail, &n_pkts, MAC_ALL_EMULS);
				if (mp == NULL) {
					VIONA_RING_STAT_INCR(ring,
					    rx_gro_fallback_fail);
					viona_ring_stat_error(ring);
					mp = next;
					continue;
				}
				VIONA_PROBE4(rx_gro_fallback, viona_vring_t *,
				    ring, mblk_t *, mp, size_t, size,
				    uint_t, n_pkts);
				VIONA_RING_STAT_INCR(ring, rx_gro_fallback);
				ASSERT3P(tail, !=, NULL);
				if (tail != mp) {
					tail->b_next = next;
					next = mp->b_next;
					mp->b_next = NULL;
				}
				size = msgsize(mp);
			}
		}

		/*
		 * Ethernet frames are expected to be padded out in order to
		 * meet the minimum size.
		 *
		 * A special case is made for frames which are short by
		 * VLAN_TAGSZ, having been stripped of their VLAN tag while
		 * traversing MAC.  A preallocated (and recycled) mblk is used
		 * for that specific condition.
		 *
		 * All other frames that fall short on length will have custom
		 * zero-padding allocated appended to them.
		 */
		if (size == NEED_VLAN_PAD_SIZE) {
			ASSERT(MBLKL(viona_vlan_pad_mp) == VLAN_TAGSZ);
			ASSERT(viona_vlan_pad_mp->b_cont == NULL);

			for (pad = mp; pad->b_cont != NULL; pad = pad->b_cont)
				;

			pad->b_cont = viona_vlan_pad_mp;
			size += VLAN_TAGSZ;
		} else if (size < MIN_BUF_SIZE) {
			const size_t pad_size = MIN_BUF_SIZE - size;
			mblk_t *zero_mp;

			zero_mp = allocb(pad_size, BPRI_MED);
			if (zero_mp == NULL) {
				err = ENOMEM;
				goto pad_drop;
			}

			VIONA_PROBE3(rx_pad_short, viona_vring_t *, ring,
			    mblk_t *, mp, size_t, pad_size);
			VIONA_RING_STAT_INCR(ring, rx_pad_short);
			zero_mp->b_wptr += pad_size;
			bzero(zero_mp->b_rptr, pad_size);
			linkb(mp, zero_mp);
			size += pad_size;
		}

		if (do_merge) {
			err = viona_recv_merged(ring, mp, size);
		} else {
			err = viona_recv_plain(ring, mp, size);
		}

		/*
		 * The VLAN padding mblk is meant for continual reuse, so
		 * remove it from the chain to prevent it from being freed.
		 *
		 * Custom allocated padding does not require this treatment and
		 * is freed normally.
		 */
		if (pad != NULL) {
			pad->b_cont = NULL;
		}

pad_drop:
		/*
		 * While an error during rx processing
		 * (viona_recv_{merged,plain}) does not free mp on error,
		 * hook processing might or might not free mp.  Handle either
		 * scenario -- if mp is not yet free, it is queued up and
		 * freed after the guest has been notified.  If mp is
		 * already NULL, just proceed on.
		 */
		if (err != 0) {
			*mpdrop_prevp = mp;
			mpdrop_prevp = &mp->b_next;

			/*
			 * If the available ring is empty, do not bother
			 * attempting to deliver any more frames.  Count the
			 * rest as dropped too.
			 */
			if (err == ENOSPC) {
				mp->b_next = next;
				break;
			} else {
				/*
				 * Cases other than the ring being empty of
				 * available descriptors count as errors for the
				 * ring/link stats.
				 */
				viona_ring_stat_error(ring);
			}
		} else {
			/* Chain successful mblks to be freed later */
			*mprx_prevp = mp;
			mprx_prevp = &mp->b_next;
			cnt_accept++;
			size_accept += size;

			VIONA_PROBE3(pkt__rx, viona_vring_t *, ring, mblk_t, mp,
			    size_t, size)
		}
		mp = next;
	}

	membar_enter();
	viona_intr_ring(ring, B_FALSE);

	/* Free successfully received frames */
	if (mprx != NULL) {
		freemsgchain(mprx);
	}

	/* Free dropped frames, also tallying them */
	mp = mpdrop;
	while (mp != NULL) {
		mblk_t *next = mp->b_next;

		mp->b_next = NULL;
		freemsg(mp);
		mp = next;
		cnt_drop++;
	}

	if (cnt_accept != 0) {
		viona_ring_stat_accept(ring, cnt_accept, size_accept);
	}
	if (cnt_drop != 0) {
		viona_ring_stat_drop(ring, cnt_drop);
	}
	VIONA_PROBE3(rx, viona_link_t *, link, size_t, cnt_accept,
	    size_t, cnt_drop);
}

static void
viona_rx_classified(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t is_loopback)
{
	viona_vring_t *ring = (viona_vring_t *)arg;

	/* Drop traffic if ring is inactive or renewing its lease */
	if (ring->vr_state != VRS_RUN ||
	    (ring->vr_state_flags & VRSF_RENEW) != 0) {
		freemsgchain(mp);
		return;
	}

	viona_rx_common(ring, mp, is_loopback);
}

static void
viona_rx_mcast(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t is_loopback)
{
	viona_vring_t *ring = (viona_vring_t *)arg;
	mac_handle_t mh = ring->vr_link->l_mh;
	mblk_t *mp_mcast_only = NULL;
	mblk_t **mpp = &mp_mcast_only;

	/* Drop traffic if ring is inactive or renewing its lease */
	if (ring->vr_state != VRS_RUN ||
	    (ring->vr_state_flags & VRSF_RENEW) != 0) {
		freemsgchain(mp);
		return;
	}

	/*
	 * In addition to multicast traffic, broadcast packets will also arrive
	 * via the MAC_CLIENT_PROMISC_MULTI handler. The mac_rx_set() callback
	 * for fully-classified traffic has already delivered that broadcast
	 * traffic, so it should be suppressed here, rather than duplicating it
	 * to the guest.
	 */
	while (mp != NULL) {
		mblk_t *mp_next;
		mac_header_info_t mhi;
		int err;

		mp_next = mp->b_next;
		mp->b_next = NULL;

		/* Determine the packet type */
		err = mac_vlan_header_info(mh, mp, &mhi);
		if (err != 0) {
			mblk_t *pull;

			/*
			 * It is possible that gathering of the header
			 * information was impeded by a leading mblk_t which
			 * was of inadequate length to reference the needed
			 * fields.  Try again, in case that could be solved
			 * with a pull-up.
			 */
			pull = msgpullup(mp, sizeof (struct ether_vlan_header));
			if (pull == NULL) {
				err = ENOMEM;
			} else {
				err = mac_vlan_header_info(mh, pull, &mhi);
				freemsg(pull);
			}

			if (err != 0) {
				VIONA_RING_STAT_INCR(ring, rx_mcast_check);
			}
		}

		/* Chain up matching packets while discarding others */
		if (err == 0 && mhi.mhi_dsttype == MAC_ADDRTYPE_MULTICAST) {
			*mpp = mp;
			mpp = &mp->b_next;
		} else {
			freemsg(mp);
		}

		mp = mp_next;
	}

	if (mp_mcast_only != NULL) {
		viona_rx_common(ring, mp_mcast_only, is_loopback);
	}
}

int
viona_rx_set(viona_link_t *link, viona_promisc_t mode)
{
	viona_vring_t *ring = &link->l_vrings[VIONA_VQ_RX];
	int err = 0;

	if (link->l_mph != NULL) {
		mac_promisc_remove(link->l_mph);
		link->l_mph = NULL;
	}

	switch (mode) {
	case VIONA_PROMISC_MULTI:
		mac_rx_set(link->l_mch, viona_rx_classified, ring);
		err = mac_promisc_add(link->l_mch, MAC_CLIENT_PROMISC_MULTI,
		    viona_rx_mcast, ring, &link->l_mph,
		    MAC_PROMISC_FLAGS_NO_TX_LOOP |
		    MAC_PROMISC_FLAGS_VLAN_TAG_STRIP);
		break;
	case VIONA_PROMISC_ALL:
		mac_rx_clear(link->l_mch);
		err = mac_promisc_add(link->l_mch, MAC_CLIENT_PROMISC_ALL,
		    viona_rx_classified, ring, &link->l_mph,
		    MAC_PROMISC_FLAGS_NO_TX_LOOP |
		    MAC_PROMISC_FLAGS_VLAN_TAG_STRIP);
		/*
		 * In case adding the promisc handler failed, restore the
		 * generic classified callback so that packets continue to
		 * flow to the guest.
		 */
		if (err != 0) {
			mac_rx_set(link->l_mch, viona_rx_classified, ring);
		}
		break;
	case VIONA_PROMISC_NONE:
	default:
		mac_rx_set(link->l_mch, viona_rx_classified, ring);
		break;
	}

	return (err);
}

void
viona_rx_clear(viona_link_t *link)
{
	if (link->l_mph != NULL) {
		mac_promisc_remove(link->l_mph);
		link->l_mph = NULL;
	}
	mac_rx_clear(link->l_mch);
}
