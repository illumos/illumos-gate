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
 */


#include <sys/disp.h>

#include "viona_impl.h"

#define	VRING_MAX_LEN		32768

/* Layout and sizing as defined in the spec for a legacy-style virtqueue */

/*
 * Because viona is not built with MACHDEP defined, PAGESIZE and friends are not
 * constants but rather variable references.  While viona remains x86-only, we
 * are free to hard-code this to 4k.
 */
#define	VQ_PGSZ			4096UL
#define	VQ_PGOFF		(VQ_PGSZ - 1)
#define	VQ_PGMASK		~VQ_PGOFF

#define	LEGACY_VQ_ALIGN		VQ_PGSZ

#define	LEGACY_DESC_SZ(qsz)	((qsz) * sizeof (struct virtio_desc))
/*
 * Available ring consists of avail_idx (uint16_t), flags (uint16_t), qsz avail
 * descriptors (uint16_t each), and (optional) used_event (uint16_t).
 */
#define	LEGACY_AVAIL_SZ(qsz)	(((qsz) + 3) * sizeof (uint16_t))
/*
 * Used ring consists of used_idx (uint16_t), flags (uint16_t), qsz used
 * descriptors (two uint32_t each), and (optional) avail_event (uint16_t).
 */
#define	LEGACY_USED_SZ(qsz)	\
	((qsz) * sizeof (struct virtio_used) + 3 * sizeof (uint16_t))

#define	LEGACY_AVAIL_FLAGS_OFF(qsz)	LEGACY_DESC_SZ(qsz)
#define	LEGACY_AVAIL_IDX_OFF(qsz)	\
	(LEGACY_DESC_SZ(qsz) + sizeof (uint16_t))
#define	LEGACY_AVAIL_ENT_OFF(qsz, idx)	\
	(LEGACY_DESC_SZ(qsz) + (2 + (idx)) * sizeof (uint16_t))

#define	LEGACY_USED_FLAGS_OFF(qsz)	\
	P2ROUNDUP(LEGACY_DESC_SZ(qsz) + LEGACY_AVAIL_SZ(qsz), LEGACY_VQ_ALIGN)
#define	LEGACY_USED_IDX_OFF(qsz)	\
	(LEGACY_USED_FLAGS_OFF(qsz) + sizeof (uint16_t))
#define	LEGACY_USED_ENT_OFF(qsz, idx)	\
	(LEGACY_USED_FLAGS_OFF(qsz) + 2 * sizeof (uint16_t) + \
	(idx) * sizeof (struct virtio_used))

#define	LEGACY_VQ_SIZE(qsz)	\
	(LEGACY_USED_FLAGS_OFF(qsz) + \
	P2ROUNDUP(LEGACY_USED_SZ(qsz), LEGACY_VQ_ALIGN))
#define	LEGACY_VQ_PAGES(qsz)	(LEGACY_VQ_SIZE(qsz) / VQ_PGSZ)

struct vq_held_region {
	struct iovec	*vhr_iov;
	vmm_page_t	*vhr_head;
	vmm_page_t	*vhr_tail;
	/* Length of iovec array supplied in `vhr_iov` */
	uint_t		vhr_niov;
	/*
	 * Index into vhr_iov, indicating the next "free" entry (following the
	 * last entry which has valid contents).
	 */
	uint_t		vhr_idx;

	/* Total length of populated entries in `vhr_iov` */
	uint32_t	vhr_len;
};
typedef struct vq_held_region vq_held_region_t;

static bool viona_ring_map(viona_vring_t *, bool);
static void viona_ring_unmap(viona_vring_t *);
static kthread_t *viona_create_worker(viona_vring_t *);
static void viona_ring_consolidate_stats(viona_vring_t *);

static vmm_page_t *
vq_page_hold(viona_vring_t *ring, uint64_t gpa, bool writable)
{
	ASSERT3P(ring->vr_lease, !=, NULL);

	int prot = PROT_READ;
	if (writable) {
		prot |= PROT_WRITE;
	}

	return (vmm_drv_page_hold(ring->vr_lease, gpa, prot));
}

/*
 * Establish a hold on the page(s) which back the region of guest memory covered
 * by [gpa, gpa + len).  The host-kernel-virtual pointers to those pages are
 * stored in the iovec array supplied in `region`, along with the chain of
 * vmm_page_t entries representing the held pages.  Since guest memory
 * carries no guarantees of being physically contiguous (on the host), it is
 * assumed that an iovec entry will be required for each page sized section
 * covered by the specified `gpa` and `len` range.  For each iovec entry
 * successfully populated by holding a page, `vhr_idx` will be incremented so it
 * references the next available iovec entry (or `vhr_niov`, if the iovec array
 * is full).  The responsibility for releasing the `vmm_page_t` chain (stored in
 * `vhr_head` and `vhr_tail`) resides with the caller, regardless of the result.
 */
static int
vq_region_hold(viona_vring_t *ring, uint64_t gpa, uint32_t len,
    bool writable, vq_held_region_t *region)
{
	const uint32_t front_offset = gpa & VQ_PGOFF;
	const uint32_t front_len = MIN(len, VQ_PGSZ - front_offset);
	uint_t pages = 1;
	vmm_page_t *vmp;
	caddr_t buf;

	ASSERT3U(region->vhr_idx, <, region->vhr_niov);

	if (front_len < len) {
		pages += P2ROUNDUP((uint64_t)(len - front_len),
		    VQ_PGSZ) / VQ_PGSZ;
	}
	if (pages > (region->vhr_niov - region->vhr_idx)) {
		return (E2BIG);
	}

	vmp = vq_page_hold(ring, gpa & VQ_PGMASK, writable);
	if (vmp == NULL) {
		return (EFAULT);
	}
	buf = (caddr_t)vmm_drv_page_readable(vmp);

	region->vhr_iov[region->vhr_idx].iov_base = buf + front_offset;
	region->vhr_iov[region->vhr_idx].iov_len = front_len;
	region->vhr_idx++;
	gpa += front_len;
	len -= front_len;
	if (region->vhr_head == NULL) {
		region->vhr_head = vmp;
		region->vhr_tail = vmp;
	} else {
		vmm_drv_page_chain(region->vhr_tail, vmp);
		region->vhr_tail = vmp;
	}

	for (uint_t i = 1; i < pages; i++) {
		ASSERT3U(gpa & VQ_PGOFF, ==, 0);

		vmp = vq_page_hold(ring, gpa, writable);
		if (vmp == NULL) {
			return (EFAULT);
		}
		buf = (caddr_t)vmm_drv_page_readable(vmp);

		const uint32_t chunk_len = MIN(len, VQ_PGSZ);
		region->vhr_iov[region->vhr_idx].iov_base = buf;
		region->vhr_iov[region->vhr_idx].iov_len = chunk_len;
		region->vhr_idx++;
		gpa += chunk_len;
		len -= chunk_len;
		vmm_drv_page_chain(region->vhr_tail, vmp);
		region->vhr_tail = vmp;
	}

	return (0);
}

static boolean_t
viona_ring_lease_expire_cb(void *arg)
{
	viona_vring_t *ring = arg;

	mutex_enter(&ring->vr_lock);
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);

	/* The lease will be broken asynchronously. */
	return (B_FALSE);
}

static void
viona_ring_lease_drop(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	if (ring->vr_lease != NULL) {
		vmm_hold_t *hold = ring->vr_link->l_vm_hold;

		ASSERT(hold != NULL);

		/*
		 * Without an active lease, the ring mappings cannot be
		 * considered valid.
		 */
		viona_ring_unmap(ring);

		vmm_drv_lease_break(hold, ring->vr_lease);
		ring->vr_lease = NULL;
	}
}

boolean_t
viona_ring_lease_renew(viona_vring_t *ring)
{
	vmm_hold_t *hold = ring->vr_link->l_vm_hold;

	ASSERT(hold != NULL);
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	viona_ring_lease_drop(ring);

	/*
	 * Lease renewal will fail if the VM has requested that all holds be
	 * cleaned up.
	 */
	ring->vr_lease = vmm_drv_lease_sign(hold, viona_ring_lease_expire_cb,
	    ring);
	if (ring->vr_lease != NULL) {
		/* A ring undergoing renewal will need valid guest mappings */
		if (ring->vr_pa != 0 && ring->vr_size != 0) {
			/*
			 * If new mappings cannot be established, consider the
			 * lease renewal a failure.
			 */
			if (!viona_ring_map(ring, ring->vr_state == VRS_INIT)) {
				viona_ring_lease_drop(ring);
				return (B_FALSE);
			}
		}
	}
	return (ring->vr_lease != NULL);
}

void
viona_ring_alloc(viona_link_t *link, viona_vring_t *ring)
{
	ring->vr_link = link;
	mutex_init(&ring->vr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ring->vr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&ring->vr_a_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ring->vr_u_mutex, NULL, MUTEX_DRIVER, NULL);
}

static void
viona_ring_misc_free(viona_vring_t *ring)
{
	const uint_t qsz = ring->vr_size;

	viona_tx_ring_free(ring, qsz);
}

void
viona_ring_free(viona_vring_t *ring)
{
	mutex_destroy(&ring->vr_lock);
	cv_destroy(&ring->vr_cv);
	mutex_destroy(&ring->vr_a_mutex);
	mutex_destroy(&ring->vr_u_mutex);
	ring->vr_link = NULL;
}

int
viona_ring_init(viona_link_t *link, uint16_t idx,
    const struct viona_ring_params *params)
{
	viona_vring_t *ring;
	kthread_t *t;
	int err = 0;
	const uint16_t qsz = params->vrp_size;
	const uint64_t pa = params->vrp_pa;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}

	if (qsz == 0 || qsz > VRING_MAX_LEN || (1 << (ffs(qsz) - 1)) != qsz) {
		return (EINVAL);
	}
	if ((pa & (LEGACY_VQ_ALIGN - 1)) != 0) {
		return (EINVAL);
	}

	ring = &link->l_vrings[idx];
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state != VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (EBUSY);
	}
	VERIFY(ring->vr_state_flags == 0);

	ring->vr_lease = NULL;
	if (!viona_ring_lease_renew(ring)) {
		err = EBUSY;
		goto fail;
	}

	ring->vr_size = qsz;
	ring->vr_mask = (ring->vr_size - 1);
	ring->vr_pa = pa;
	if (!viona_ring_map(ring, true)) {
		err = EINVAL;
		goto fail;
	}

	/* Initialize queue indexes */
	ring->vr_cur_aidx = params->vrp_avail_idx;
	ring->vr_cur_uidx = params->vrp_used_idx;

	if (idx == VIONA_VQ_TX) {
		viona_tx_ring_alloc(ring, qsz);
	}

	/* Zero out MSI-X configuration */
	ring->vr_msi_addr = 0;
	ring->vr_msi_msg = 0;

	/* Clear the stats */
	bzero(&ring->vr_stats, sizeof (ring->vr_stats));
	bzero(&ring->vr_err_stats, sizeof (ring->vr_err_stats));

	t = viona_create_worker(ring);
	if (t == NULL) {
		err = ENOMEM;
		goto fail;
	}
	ring->vr_worker_thread = t;
	ring->vr_state = VRS_SETUP;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);
	return (0);

fail:
	viona_ring_lease_drop(ring);
	viona_ring_misc_free(ring);
	ring->vr_size = 0;
	ring->vr_mask = 0;
	ring->vr_pa = 0;
	ring->vr_cur_aidx = 0;
	ring->vr_cur_uidx = 0;
	mutex_exit(&ring->vr_lock);
	return (err);
}

int
viona_ring_get_state(viona_link_t *link, uint16_t idx,
    struct viona_ring_params *params)
{
	viona_vring_t *ring;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}

	ring = &link->l_vrings[idx];
	mutex_enter(&ring->vr_lock);

	params->vrp_size = ring->vr_size;
	params->vrp_pa = ring->vr_pa;

	if (ring->vr_state == VRS_RUN) {
		/* On a running ring, we must heed the avail/used locks */
		mutex_enter(&ring->vr_a_mutex);
		params->vrp_avail_idx = ring->vr_cur_aidx;
		mutex_exit(&ring->vr_a_mutex);
		mutex_enter(&ring->vr_u_mutex);
		params->vrp_used_idx = ring->vr_cur_uidx;
		mutex_exit(&ring->vr_u_mutex);
	} else {
		/* Otherwise vr_lock is adequate protection */
		params->vrp_avail_idx = ring->vr_cur_aidx;
		params->vrp_used_idx = ring->vr_cur_uidx;
	}

	mutex_exit(&ring->vr_lock);

	return (0);
}

int
viona_ring_reset(viona_vring_t *ring, boolean_t heed_signals)
{
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state == VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (0);
	}

	if ((ring->vr_state_flags & VRSF_REQ_STOP) == 0) {
		ring->vr_state_flags |= VRSF_REQ_STOP;
		cv_broadcast(&ring->vr_cv);
	}
	while (ring->vr_state != VRS_RESET) {
		if (!heed_signals) {
			cv_wait(&ring->vr_cv, &ring->vr_lock);
		} else {
			int rs;

			rs = cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
			if (rs <= 0 && ring->vr_state != VRS_RESET) {
				mutex_exit(&ring->vr_lock);
				return (EINTR);
			}
		}
	}
	mutex_exit(&ring->vr_lock);
	return (0);
}

static bool
viona_ring_map(viona_vring_t *ring, bool defer_dirty)
{
	const uint16_t qsz = ring->vr_size;
	uintptr_t pa = ring->vr_pa;

	ASSERT3U(qsz, !=, 0);
	ASSERT3U(qsz, <=, VRING_MAX_LEN);
	ASSERT3U(pa, !=, 0);
	ASSERT3U(pa & (LEGACY_VQ_ALIGN - 1), ==, 0);
	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3P(ring->vr_map_pages, ==, NULL);

	const uint_t npages = LEGACY_VQ_PAGES(qsz);
	ring->vr_map_pages = kmem_zalloc(npages * sizeof (void *), KM_SLEEP);

	int page_flags = 0;
	if (defer_dirty) {
		/*
		 * During initialization, and when entering the paused state,
		 * the page holds for a virtqueue are established with the
		 * DEFER_DIRTY flag set.
		 *
		 * This prevents those page holds from immediately marking the
		 * underlying pages as dirty, since the viona emulation is not
		 * yet performing any accesses.  Once the ring transitions to
		 * the VRS_RUN state, the held pages will be marked as dirty.
		 *
		 * Any ring mappings performed outside those state conditions,
		 * such as those part of vmm_lease renewal during steady-state
		 * operation, will map the ring pages normally (as considered
		 * immediately dirty).
		 */
		page_flags |= VMPF_DEFER_DIRTY;
	}

	vmm_page_t *prev = NULL;
	for (uint_t i = 0; i < npages; i++, pa += VQ_PGSZ) {
		vmm_page_t *vmp;

		vmp = vmm_drv_page_hold_ext(ring->vr_lease, pa,
		    PROT_READ | PROT_WRITE, page_flags);
		if (vmp == NULL) {
			viona_ring_unmap(ring);
			return (false);
		}

		/*
		 * Keep the first page has the head of the chain, appending all
		 * subsequent pages to the tail.
		 */
		if (prev == NULL) {
			ring->vr_map_hold = vmp;
		} else {
			vmm_drv_page_chain(prev, vmp);
		}
		prev = vmp;
		ring->vr_map_pages[i] = vmm_drv_page_writable(vmp);
	}

	return (true);
}

static void
viona_ring_mark_dirty(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT(ring->vr_map_hold != NULL);

	for (vmm_page_t *vp = ring->vr_map_hold; vp != NULL;
	    vp = vmm_drv_page_next(vp)) {
		vmm_drv_page_mark_dirty(vp);
	}
}

static void
viona_ring_unmap(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	void **map = ring->vr_map_pages;
	if (map != NULL) {
		const uint_t npages = LEGACY_VQ_PAGES(ring->vr_size);
		kmem_free(map, npages * sizeof (void *));
		ring->vr_map_pages = NULL;

		vmm_drv_page_release_chain(ring->vr_map_hold);
		ring->vr_map_hold = NULL;
	} else {
		ASSERT3P(ring->vr_map_hold, ==, NULL);
	}
}

static inline void *
viona_ring_addr(viona_vring_t *ring, uint_t off)
{
	ASSERT3P(ring->vr_map_pages, !=, NULL);
	ASSERT3U(LEGACY_VQ_SIZE(ring->vr_size), >, off);

	const uint_t page_num = off / VQ_PGSZ;
	const uint_t page_off = off % VQ_PGSZ;
	return ((caddr_t)ring->vr_map_pages[page_num] + page_off);
}

void
viona_intr_ring(viona_vring_t *ring, boolean_t skip_flags_check)
{
	if (!skip_flags_check) {
		volatile uint16_t *avail_flags = viona_ring_addr(ring,
		    LEGACY_AVAIL_FLAGS_OFF(ring->vr_size));

		if ((*avail_flags & VRING_AVAIL_F_NO_INTERRUPT) != 0) {
			return;
		}
	}

	mutex_enter(&ring->vr_lock);
	uint64_t addr = ring->vr_msi_addr;
	uint64_t msg = ring->vr_msi_msg;
	mutex_exit(&ring->vr_lock);
	if (addr != 0) {
		/* Deliver the interrupt directly, if so configured... */
		(void) vmm_drv_msi(ring->vr_lease, addr, msg);
	} else {
		/* ... otherwise, leave it to userspace */
		if (atomic_cas_uint(&ring->vr_intr_enabled, 0, 1) == 0) {
			pollwakeup(&ring->vr_link->l_pollhead, POLLRDBAND);
		}
	}
}

static inline bool
vring_stop_req(const viona_vring_t *ring)
{
	return ((ring->vr_state_flags & VRSF_REQ_STOP) != 0);
}

static inline bool
vring_pause_req(const viona_vring_t *ring)
{
	return ((ring->vr_state_flags & VRSF_REQ_PAUSE) != 0);
}

static inline bool
vring_start_req(const viona_vring_t *ring)
{
	return ((ring->vr_state_flags & VRSF_REQ_START) != 0);
}

/*
 * Check if vring worker thread should bail out.  This will heed indications
 * that the containing process is exiting, as well as requests to stop or pause
 * the ring.  The `stop_only` parameter controls if pause requests are ignored
 * (true) or checked (false).
 *
 * Caller should hold vr_lock.
 */
static bool
vring_need_bail_ext(const viona_vring_t *ring, bool stop_only)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	if (vring_stop_req(ring) ||
	    (!stop_only && vring_pause_req(ring))) {
		return (true);
	}

	kthread_t *t = ring->vr_worker_thread;
	if (t != NULL) {
		proc_t *p = ttoproc(t);

		ASSERT(p != NULL);
		if ((p->p_flag & SEXITING) != 0) {
			return (true);
		}
	}
	return (false);
}

bool
vring_need_bail(const viona_vring_t *ring)
{
	return (vring_need_bail_ext(ring, false));
}

int
viona_ring_pause(viona_vring_t *ring)
{
	mutex_enter(&ring->vr_lock);
	switch (ring->vr_state) {
	case VRS_RESET:
	case VRS_SETUP:
	case VRS_INIT:
		/*
		 * For rings which have not yet started (even those in the
		 * VRS_SETUP and VRS_INIT phases, where there a running worker
		 * thread (waiting to be released to do its intended task), it
		 * is adequate to simply clear any start request, to keep them
		 * from proceeding into the actual work processing function.
		 */
		ring->vr_state_flags &= ~VRSF_REQ_START;
		mutex_exit(&ring->vr_lock);
		return (0);

	case VRS_STOP:
		if ((ring->vr_state_flags & VRSF_REQ_STOP) != 0) {
			/* A ring on its way to RESET cannot be paused. */
			mutex_exit(&ring->vr_lock);
			return (EBUSY);
		}
		/* FALLTHROUGH */
	case VRS_RUN:
		ring->vr_state_flags |= VRSF_REQ_PAUSE;
		cv_broadcast(&ring->vr_cv);
		break;

	default:
		panic("invalid ring state %d", ring->vr_state);
		break;
	}

	for (;;) {
		int res = cv_wait_sig(&ring->vr_cv, &ring->vr_lock);

		if (ring->vr_state == VRS_INIT ||
		    (ring->vr_state_flags & VRSF_REQ_PAUSE) == 0) {
			/* Ring made it to (or through) paused state */
			mutex_exit(&ring->vr_lock);
			return (0);
		}
		if (res == 0) {
			/* interrupted by signal */
			mutex_exit(&ring->vr_lock);
			return (EINTR);
		}
	}
	/* NOTREACHED */
}

static void
viona_worker(void *arg)
{
	viona_vring_t *ring = (viona_vring_t *)arg;
	viona_link_t *link = ring->vr_link;

	mutex_enter(&ring->vr_lock);
	VERIFY3U(ring->vr_state, ==, VRS_SETUP);

	/* Bail immediately if ring shutdown or process exit was requested */
	if (vring_need_bail_ext(ring, true)) {
		goto ring_reset;
	}

	/* Report worker thread as alive and notify creator */
ring_init:
	ring->vr_state = VRS_INIT;
	cv_broadcast(&ring->vr_cv);

	while (!vring_start_req(ring)) {
		/*
		 * Keeping lease renewals timely while waiting for the ring to
		 * be started is important for avoiding deadlocks.
		 */
		if (vmm_drv_lease_expired(ring->vr_lease)) {
			if (!viona_ring_lease_renew(ring)) {
				goto ring_reset;
			}
		}

		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);

		if (vring_pause_req(ring)) {
			/* We are already paused in the INIT state. */
			ring->vr_state_flags &= ~VRSF_REQ_PAUSE;
		}
		if (vring_need_bail_ext(ring, true)) {
			goto ring_reset;
		}
	}

	ASSERT((ring->vr_state_flags & VRSF_REQ_START) != 0);
	ring->vr_state = VRS_RUN;
	ring->vr_state_flags &= ~VRSF_REQ_START;
	viona_ring_mark_dirty(ring);

	/* Ensure ring lease is valid first */
	if (vmm_drv_lease_expired(ring->vr_lease)) {
		if (!viona_ring_lease_renew(ring)) {
			goto ring_reset;
		}
	}

	/* Process actual work */
	if (ring == &link->l_vrings[VIONA_VQ_RX]) {
		viona_worker_rx(ring, link);
	} else if (ring == &link->l_vrings[VIONA_VQ_TX]) {
		viona_worker_tx(ring, link);
	} else {
		panic("unexpected ring: %p", (void *)ring);
	}

	VERIFY3U(ring->vr_state, ==, VRS_STOP);
	VERIFY3U(ring->vr_xfer_outstanding, ==, 0);

	/*
	 * Consolidate stats data so that it is not lost if/when this ring is
	 * being stopped.
	 */
	viona_ring_consolidate_stats(ring);

	/* Respond to a pause request if the ring is not required to stop */
	if (vring_pause_req(ring)) {
		ring->vr_state_flags &= ~VRSF_REQ_PAUSE;

		if (vring_need_bail_ext(ring, true)) {
			goto ring_reset;
		}

		/*
		 * To complete pausing of the ring, unmap and re-map the pages
		 * underpinning the virtqueue.  This is to synchronize their
		 * dirty state in the backing page tables and restore the
		 * defer-dirty state on the held pages.
		 */
		viona_ring_unmap(ring);
		if (viona_ring_map(ring, true)) {
			goto ring_init;
		}

		/*
		 * If the ring pages failed to be mapped, fallthrough to
		 * ring-reset like any other failure.
		 */
	}

ring_reset:
	viona_ring_misc_free(ring);

	viona_ring_lease_drop(ring);
	ring->vr_cur_aidx = 0;
	ring->vr_size = 0;
	ring->vr_mask = 0;
	ring->vr_pa = 0;
	ring->vr_state = VRS_RESET;
	ring->vr_state_flags = 0;
	ring->vr_worker_thread = NULL;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);

	mutex_enter(&ttoproc(curthread)->p_lock);
	lwp_exit();
}

static kthread_t *
viona_create_worker(viona_vring_t *ring)
{
	k_sigset_t hold_set;
	proc_t *p = curproc;
	kthread_t *t;
	klwp_t *lwp;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT(ring->vr_state == VRS_RESET);

	sigfillset(&hold_set);
	lwp = lwp_create(viona_worker, (void *)ring, 0, p, TS_STOPPED,
	    minclsyspri - 1, &hold_set, curthread->t_cid, 0);
	if (lwp == NULL) {
		return (NULL);
	}

	t = lwptot(lwp);
	mutex_enter(&p->p_lock);
	t->t_proc_flag = (t->t_proc_flag & ~TP_HOLDLWP) | TP_KTHREAD;
	lwp_create_done(t);
	mutex_exit(&p->p_lock);

	return (t);
}

static inline void
vq_read_desc(viona_vring_t *ring, uint16_t idx, struct virtio_desc *descp)
{
	const uint_t entry_off = idx * sizeof (struct virtio_desc);

	ASSERT3U(idx, <, ring->vr_size);

	/*
	 * On both legacy and 1.x VirtIO, the virtqueue descriptors are required
	 * to be aligned to at least 16 bytes (4k for legacy).
	 */
	*descp = *(const struct virtio_desc *)viona_ring_addr(ring, entry_off);
}

static uint16_t
vq_read_avail(viona_vring_t *ring, uint16_t idx)
{
	ASSERT3U(idx, <, ring->vr_size);

	volatile uint16_t *avail_ent =
	    viona_ring_addr(ring, LEGACY_AVAIL_ENT_OFF(ring->vr_size, idx));
	return (*avail_ent);
}

/*
 * Given a buffer descriptor `desc`, attempt to map the pages backing that
 * region of guest physical memory, taking into account that there are no
 * guarantees about guest-contiguous pages being host-contiguous.
 */
static int
vq_map_desc_bufs(viona_vring_t *ring, const struct virtio_desc *desc,
    vq_held_region_t *region)
{
	if (desc->vd_len == 0) {
		VIONA_PROBE2(desc_bad_len, viona_vring_t *, ring,
		    uint32_t, desc->vd_len);
		VIONA_RING_STAT_INCR(ring, desc_bad_len);
		return (EINVAL);
	} else if ((region->vhr_len + desc->vd_len) < region->vhr_len) {
		VIONA_PROBE1(len_overflow, viona_vring_t *, ring);
		VIONA_RING_STAT_INCR(ring, len_overflow);
		return (EOVERFLOW);
	}

	int err = vq_region_hold(ring, desc->vd_addr, desc->vd_len,
	    (desc->vd_flags & VRING_DESC_F_WRITE) != 0, region);
	if (err == 0) {
		region->vhr_len += desc->vd_len;
	} else if (err == E2BIG) {
		VIONA_PROBE1(too_many_desc, viona_vring_t *, ring);
		VIONA_RING_STAT_INCR(ring, too_many_desc);
	} else if (err == EFAULT) {
		VIONA_PROBE_BAD_RING_ADDR(ring, desc->vd_addr);
		VIONA_RING_STAT_INCR(ring, bad_ring_addr);
	}

	return (err);
}

/*
 * Walk an indirect buffer descriptor `desc`, attempting to map the pages
 * backing the regions of guest memory covered by its constituent descriptors.
 */
static int
vq_map_indir_desc_bufs(viona_vring_t *ring, const struct virtio_desc *desc,
    vq_held_region_t *region)
{
	const uint16_t indir_count = desc->vd_len / sizeof (struct virtio_desc);

	if ((desc->vd_len & 0xf) != 0 || indir_count == 0 ||
	    indir_count > ring->vr_size ||
	    desc->vd_addr > (desc->vd_addr + desc->vd_len)) {
		VIONA_PROBE2(indir_bad_len, viona_vring_t *, ring,
		    uint32_t, desc->vd_len);
		VIONA_RING_STAT_INCR(ring, indir_bad_len);
		return (EINVAL);
	}

	uint16_t indir_next = 0;
	const uint8_t *buf = NULL;
	uint64_t buf_gpa = UINT64_MAX;
	vmm_page_t *vmp = NULL;
	int err = 0;

	for (;;) {
		const uint64_t indir_gpa =
		    desc->vd_addr + (indir_next * sizeof (struct virtio_desc));
		const uint64_t indir_page = indir_gpa & VQ_PGMASK;

		/*
		 * Get a mapping for the page that the next indirect descriptor
		 * resides in, if has not already been done.
		 */
		if (indir_page != buf_gpa) {
			if (vmp != NULL) {
				vmm_drv_page_release(vmp);
			}
			vmp = vq_page_hold(ring, indir_page, false);
			if (vmp == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, indir_page);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				err = EFAULT;
				break;
			}
			buf_gpa = indir_page;
			buf = vmm_drv_page_readable(vmp);
		}

		/*
		 * A copy of the indirect descriptor is made here, rather than
		 * simply using a reference pointer.  This prevents malicious or
		 * erroneous guest writes to the descriptor from fooling the
		 * flags/bounds verification through a race.
		 *
		 * While indirect descriptors do not have the same alignment
		 * requirements as those residing in the virtqueue itself, we
		 * are not concerned about unaligned access while viona remains
		 * x86-only.
		 */
		struct virtio_desc vp = *(const struct virtio_desc *)
		    (buf + (indir_gpa - indir_page));

		if (vp.vd_flags & VRING_DESC_F_INDIRECT) {
			VIONA_PROBE1(indir_bad_nest, viona_vring_t *, ring);
			VIONA_RING_STAT_INCR(ring, indir_bad_nest);
			err = EINVAL;
			break;
		} else if (vp.vd_len == 0) {
			VIONA_PROBE2(desc_bad_len, viona_vring_t *, ring,
			    uint32_t, vp.vd_len);
			VIONA_RING_STAT_INCR(ring, desc_bad_len);
			err = EINVAL;
			break;
		}

		err = vq_map_desc_bufs(ring, &vp, region);
		if (err != 0) {
			break;
		}

		/* Successfully reach the end of the indir chain */
		if ((vp.vd_flags & VRING_DESC_F_NEXT) == 0) {
			break;
		}
		if (region->vhr_idx >= region->vhr_niov) {
			VIONA_PROBE1(too_many_desc, viona_vring_t *, ring);
			VIONA_RING_STAT_INCR(ring, too_many_desc);
			err = E2BIG;
			break;
		}

		indir_next = vp.vd_next;
		if (indir_next >= indir_count) {
			VIONA_PROBE3(indir_bad_next, viona_vring_t *, ring,
			    uint16_t, indir_next, uint16_t, indir_count);
			VIONA_RING_STAT_INCR(ring, indir_bad_next);
			err = EINVAL;
			break;
		}
	}

	if (vmp != NULL) {
		vmm_drv_page_release(vmp);
	}
	return (err);
}

int
vq_popchain(viona_vring_t *ring, struct iovec *iov, uint_t niov,
    uint16_t *cookie, vmm_page_t **chain, uint32_t *len)
{
	uint16_t ndesc, idx, head, next;
	struct virtio_desc vdir;
	vq_held_region_t region = {
		.vhr_niov = niov,
		.vhr_iov = iov,
	};

	ASSERT(iov != NULL);
	ASSERT(niov > 0 && niov < INT_MAX);
	ASSERT(*chain == NULL);

	mutex_enter(&ring->vr_a_mutex);
	idx = ring->vr_cur_aidx;
	ndesc = viona_ring_num_avail(ring);

	if (ndesc == 0) {
		mutex_exit(&ring->vr_a_mutex);
		return (0);
	}
	if (ndesc > ring->vr_size) {
		/*
		 * Despite the fact that the guest has provided an 'avail_idx'
		 * which indicates that an impossible number of descriptors are
		 * available, continue on and attempt to process the next one.
		 *
		 * The transgression will not escape the probe or stats though.
		 */
		VIONA_PROBE2(ndesc_too_high, viona_vring_t *, ring,
		    uint16_t, ndesc);
		VIONA_RING_STAT_INCR(ring, ndesc_too_high);
	}

	head = vq_read_avail(ring, idx & ring->vr_mask);
	next = head;

	for (region.vhr_idx = 0; region.vhr_idx < niov; next = vdir.vd_next) {
		if (next >= ring->vr_size) {
			VIONA_PROBE2(bad_idx, viona_vring_t *, ring,
			    uint16_t, next);
			VIONA_RING_STAT_INCR(ring, bad_idx);
			break;
		}

		vq_read_desc(ring, next, &vdir);
		if ((vdir.vd_flags & VRING_DESC_F_INDIRECT) == 0) {
			if (vq_map_desc_bufs(ring, &vdir, &region) != 0) {
				break;
			}
		} else {
			/*
			 * Per the specification (Virtio 1.1 S2.6.5.3.1):
			 *   A driver MUST NOT set both VIRTQ_DESC_F_INDIRECT
			 *   and VIRTQ_DESC_F_NEXT in `flags`.
			 */
			if ((vdir.vd_flags & VRING_DESC_F_NEXT) != 0) {
				VIONA_PROBE3(indir_bad_next,
				    viona_vring_t *, ring,
				    uint16_t, next, uint16_t, 0);
				VIONA_RING_STAT_INCR(ring, indir_bad_next);
				break;
			}

			if (vq_map_indir_desc_bufs(ring, &vdir, &region) != 0) {
				break;
			}
		}

		if ((vdir.vd_flags & VRING_DESC_F_NEXT) == 0) {
			ring->vr_cur_aidx++;
			mutex_exit(&ring->vr_a_mutex);

			*cookie = head;
			*chain = region.vhr_head;
			if (len != NULL) {
				*len = region.vhr_len;
			}
			return (region.vhr_idx);
		}
	}

	mutex_exit(&ring->vr_a_mutex);
	if (region.vhr_head != NULL) {
		/*
		 * If any pages were held prior to encountering an error, we
		 * must release them now.
		 */
		vmm_drv_page_release_chain(region.vhr_head);
	}
	return (-1);
}


static void
vq_write_used_ent(viona_vring_t *ring, uint16_t idx, uint16_t cookie,
    uint32_t len)
{
	/*
	 * In a larger ring, entry could be split across pages, so be sure to
	 * account for that when configuring the transfer by looking up the ID
	 * and length addresses separately, rather than an address for a
	 * combined `struct virtio_used`.
	 */
	const uint_t used_id_off = LEGACY_USED_ENT_OFF(ring->vr_size, idx);
	const uint_t used_len_off = used_id_off + sizeof (uint32_t);
	volatile uint32_t *idp = viona_ring_addr(ring, used_id_off);
	volatile uint32_t *lenp = viona_ring_addr(ring, used_len_off);

	ASSERT(MUTEX_HELD(&ring->vr_u_mutex));

	*idp = cookie;
	*lenp = len;
}

static void
vq_write_used_idx(viona_vring_t *ring, uint16_t idx)
{
	ASSERT(MUTEX_HELD(&ring->vr_u_mutex));

	volatile uint16_t *used_idx =
	    viona_ring_addr(ring, LEGACY_USED_IDX_OFF(ring->vr_size));
	*used_idx = idx;
}

void
vq_pushchain(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	uint16_t uidx;

	mutex_enter(&ring->vr_u_mutex);

	uidx = ring->vr_cur_uidx;
	vq_write_used_ent(ring, uidx & ring->vr_mask, cookie, len);
	uidx++;
	membar_producer();

	vq_write_used_idx(ring, uidx);
	ring->vr_cur_uidx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

void
vq_pushchain_many(viona_vring_t *ring, uint_t num_bufs, used_elem_t *elem)
{
	uint16_t uidx;

	mutex_enter(&ring->vr_u_mutex);

	uidx = ring->vr_cur_uidx;

	for (uint_t i = 0; i < num_bufs; i++, uidx++) {
		vq_write_used_ent(ring, uidx & ring->vr_mask, elem[i].id,
		    elem[i].len);
	}

	membar_producer();
	vq_write_used_idx(ring, uidx);
	ring->vr_cur_uidx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

/*
 * Set USED_NO_NOTIFY on VQ so guest elides doorbell calls for new entries.
 */
void
viona_ring_disable_notify(viona_vring_t *ring)
{
	volatile uint16_t *used_flags =
	    viona_ring_addr(ring, LEGACY_USED_FLAGS_OFF(ring->vr_size));

	*used_flags |= VRING_USED_F_NO_NOTIFY;
}

/*
 * Clear USED_NO_NOTIFY on VQ so guest resumes doorbell calls for new entries.
 */
void
viona_ring_enable_notify(viona_vring_t *ring)
{
	volatile uint16_t *used_flags =
	    viona_ring_addr(ring, LEGACY_USED_FLAGS_OFF(ring->vr_size));

	*used_flags &= ~VRING_USED_F_NO_NOTIFY;
}

/*
 * Return the number of available descriptors in the vring taking care of the
 * 16-bit index wraparound.
 *
 * Note: If the number of apparently available descriptors is larger than the
 * ring size (due to guest misbehavior), this check will still report the
 * positive count of descriptors.
 */
uint16_t
viona_ring_num_avail(viona_vring_t *ring)
{
	volatile uint16_t *avail_idx =
	    viona_ring_addr(ring, LEGACY_AVAIL_IDX_OFF(ring->vr_size));

	return (*avail_idx - ring->vr_cur_aidx);
}

/* Record successfully transferred packet(s) for the ring stats */
void
viona_ring_stat_accept(viona_vring_t *ring, size_t count, size_t len)
{
	atomic_add_64(&ring->vr_stats.vts_packets, count);
	atomic_add_64(&ring->vr_stats.vts_bytes, len);
}

/*
 * Record dropped packet(s) in the ring stats
 */
void
viona_ring_stat_drop(viona_vring_t *ring, size_t count)
{
	atomic_add_64(&ring->vr_stats.vts_drops, count);
}

/*
 * Record a packet transfer error in the ring stats
 */
void
viona_ring_stat_error(viona_vring_t *ring)
{
	atomic_inc_64(&ring->vr_stats.vts_errors);
}

/*
 * Consolidate statistic data for this ring into the totals for the link
 */
static void
viona_ring_consolidate_stats(viona_vring_t *ring)
{
	viona_link_t *link = ring->vr_link;
	struct viona_transfer_stats *lstat =
	    (ring == &link->l_vrings[VIONA_VQ_RX]) ?
	    &link->l_stats.vls_rx : &link->l_stats.vls_tx;

	mutex_enter(&link->l_stats_lock);
	lstat->vts_packets += ring->vr_stats.vts_packets;
	lstat->vts_bytes += ring->vr_stats.vts_bytes;
	lstat->vts_drops += ring->vr_stats.vts_drops;
	lstat->vts_errors += ring->vr_stats.vts_errors;
	bzero(&ring->vr_stats, sizeof (ring->vr_stats));
	mutex_exit(&link->l_stats_lock);
}

/*
 * Copy `sz` bytes from iovecs contained in `iob` to `dst.
 *
 * Returns `true` if copy was successful (implying adequate data was remaining
 * in the iov_bunch_t).
 */
bool
iov_bunch_copy(iov_bunch_t *iob, void *dst, uint32_t sz)
{
	if (sz > iob->ib_remain) {
		return (false);
	}
	if (sz == 0) {
		return (true);
	}

	caddr_t dest = dst;
	do {
		struct iovec *iov = iob->ib_iov;

		ASSERT3U(iov->iov_len, <, UINT32_MAX);
		ASSERT3U(iov->iov_len, !=, 0);

		const uint32_t iov_avail = (iov->iov_len - iob->ib_offset);
		const uint32_t to_copy = MIN(sz, iov_avail);

		if (to_copy != 0) {
			bcopy((caddr_t)iov->iov_base + iob->ib_offset, dest,
			    to_copy);
		}

		sz -= to_copy;
		iob->ib_remain -= to_copy;
		dest += to_copy;
		iob->ib_offset += to_copy;

		ASSERT3U(iob->ib_offset, <=, iov->iov_len);

		if (iob->ib_offset == iov->iov_len) {
			iob->ib_iov++;
			iob->ib_offset = 0;
		}
	} while (sz > 0);

	return (true);
}

/*
 * Get the data pointer and length of the current head iovec, less any
 * offsetting from prior copy operations.  This will advanced the iov_bunch_t as
 * if the caller had performed a copy of that chunk length.
 *
 * Returns `true` if the iov_bunch_t had at least one iovec (unconsumed bytes)
 * remaining, setting `chunk` and `chunk_sz` to the chunk pointer and size,
 * respectively.
 */
bool
iov_bunch_next_chunk(iov_bunch_t *iob, caddr_t *chunk, uint32_t *chunk_sz)
{
	if (iob->ib_remain == 0) {
		*chunk = NULL;
		*chunk_sz = 0;
		return (false);
	}

	*chunk_sz = iob->ib_iov->iov_len - iob->ib_offset;
	*chunk = (caddr_t)iob->ib_iov->iov_base + iob->ib_offset;
	iob->ib_remain -= *chunk_sz;
	iob->ib_iov++;
	iob->ib_offset = 0;
	return (true);
}
