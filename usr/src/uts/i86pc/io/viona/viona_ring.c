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


#include <sys/disp.h>

#include "viona_impl.h"

#define	VRING_ALIGN		4096
#define	VRING_MAX_LEN		32768

static boolean_t viona_ring_map(viona_vring_t *);
static void viona_ring_unmap(viona_vring_t *);
static kthread_t *viona_create_worker(viona_vring_t *);

static void *
viona_gpa2kva(viona_vring_t *ring, uint64_t gpa, size_t len)
{
	ASSERT3P(ring->vr_lease, !=, NULL);

	return (vmm_drv_gpa2kva(ring->vr_lease, gpa, len));
}

static boolean_t
viona_ring_lease_expire_cb(void *arg)
{
	viona_vring_t *ring = arg;

	cv_broadcast(&ring->vr_cv);

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
			if (!viona_ring_map(ring)) {
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
viona_ring_init(viona_link_t *link, uint16_t idx, uint16_t qsz, uint64_t pa)
{
	viona_vring_t *ring;
	kthread_t *t;
	int err = 0;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}
	if (qsz == 0 || qsz > VRING_MAX_LEN || (1 << (ffs(qsz) - 1)) != qsz) {
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
	if (!viona_ring_map(ring)) {
		err = EINVAL;
		goto fail;
	}

	/* Initialize queue indexes */
	ring->vr_cur_aidx = 0;

	if (idx == VIONA_VQ_TX) {
		viona_tx_ring_alloc(ring, qsz);
	}

	/* Zero out MSI-X configuration */
	ring->vr_msi_addr = 0;
	ring->vr_msi_msg = 0;

	/* Clear the stats */
	bzero(&ring->vr_stats, sizeof (ring->vr_stats));

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
	mutex_exit(&ring->vr_lock);
	return (err);
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
	viona_ring_lease_drop(ring);
	mutex_exit(&ring->vr_lock);
	return (0);
}

static boolean_t
viona_ring_map(viona_vring_t *ring)
{
	uint64_t pos = ring->vr_pa;
	const uint16_t qsz = ring->vr_size;

	ASSERT3U(qsz, !=, 0);
	ASSERT3U(pos, !=, 0);
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	const size_t desc_sz = qsz * sizeof (struct virtio_desc);
	ring->vr_descr = viona_gpa2kva(ring, pos, desc_sz);
	if (ring->vr_descr == NULL) {
		goto fail;
	}
	pos += desc_sz;

	const size_t avail_sz = (qsz + 3) * sizeof (uint16_t);
	ring->vr_avail_flags = viona_gpa2kva(ring, pos, avail_sz);
	if (ring->vr_avail_flags == NULL) {
		goto fail;
	}
	ring->vr_avail_idx = ring->vr_avail_flags + 1;
	ring->vr_avail_ring = ring->vr_avail_flags + 2;
	ring->vr_avail_used_event = ring->vr_avail_ring + qsz;
	pos += avail_sz;

	const size_t used_sz = (qsz * sizeof (struct virtio_used)) +
	    (sizeof (uint16_t) * 3);
	pos = P2ROUNDUP(pos, VRING_ALIGN);
	ring->vr_used_flags = viona_gpa2kva(ring, pos, used_sz);
	if (ring->vr_used_flags == NULL) {
		goto fail;
	}
	ring->vr_used_idx = ring->vr_used_flags + 1;
	ring->vr_used_ring = (struct virtio_used *)(ring->vr_used_flags + 2);
	ring->vr_used_avail_event = (uint16_t *)(ring->vr_used_ring + qsz);

	return (B_TRUE);

fail:
	viona_ring_unmap(ring);
	return (B_FALSE);
}

static void
viona_ring_unmap(viona_vring_t *ring)
{
	ASSERT(MUTEX_HELD(&ring->vr_lock));

	ring->vr_descr = NULL;
	ring->vr_avail_flags = NULL;
	ring->vr_avail_idx = NULL;
	ring->vr_avail_ring = NULL;
	ring->vr_avail_used_event = NULL;
	ring->vr_used_flags = NULL;
	ring->vr_used_idx = NULL;
	ring->vr_used_ring = NULL;
	ring->vr_used_avail_event = NULL;
}

void
viona_intr_ring(viona_vring_t *ring)
{
	uint64_t addr;

	mutex_enter(&ring->vr_lock);
	/* Deliver the interrupt directly, if so configured. */
	if ((addr = ring->vr_msi_addr) != 0) {
		uint64_t msg = ring->vr_msi_msg;

		mutex_exit(&ring->vr_lock);
		(void) vmm_drv_msi(ring->vr_lease, addr, msg);
		return;
	}
	mutex_exit(&ring->vr_lock);

	if (atomic_cas_uint(&ring->vr_intr_enabled, 0, 1) == 0) {
		pollwakeup(&ring->vr_link->l_pollhead, POLLRDBAND);
	}
}

static void
viona_worker(void *arg)
{
	viona_vring_t *ring = (viona_vring_t *)arg;
	viona_link_t *link = ring->vr_link;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&ring->vr_lock);
	VERIFY3U(ring->vr_state, ==, VRS_SETUP);

	/* Bail immediately if ring shutdown or process exit was requested */
	if (VRING_NEED_BAIL(ring, p)) {
		goto cleanup;
	}

	/* Report worker thread as alive and notify creator */
	ring->vr_state = VRS_INIT;
	cv_broadcast(&ring->vr_cv);

	while (ring->vr_state_flags == 0) {
		/*
		 * Keeping lease renewals timely while waiting for the ring to
		 * be started is important for avoiding deadlocks.
		 */
		if (vmm_drv_lease_expired(ring->vr_lease)) {
			if (!viona_ring_lease_renew(ring)) {
				goto cleanup;
			}
		}

		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);

		if (VRING_NEED_BAIL(ring, p)) {
			goto cleanup;
		}
	}

	ASSERT((ring->vr_state_flags & VRSF_REQ_START) != 0);
	ring->vr_state = VRS_RUN;
	ring->vr_state_flags &= ~VRSF_REQ_START;

	/* Ensure ring lease is valid first */
	if (vmm_drv_lease_expired(ring->vr_lease)) {
		if (!viona_ring_lease_renew(ring)) {
			goto cleanup;
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

cleanup:
	if (ring->vr_txdesb != NULL) {
		/*
		 * Transmit activity must be entirely concluded before the
		 * associated descriptors can be cleaned up.
		 */
		VERIFY(ring->vr_xfer_outstanding == 0);
	}
	viona_ring_misc_free(ring);

	viona_ring_lease_drop(ring);
	ring->vr_cur_aidx = 0;
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

int
vq_popchain(viona_vring_t *ring, struct iovec *iov, uint_t niov,
    uint16_t *cookie)
{
	uint_t i, ndesc, idx, head, next;
	struct virtio_desc vdir;
	void *buf;

	ASSERT(iov != NULL);
	ASSERT(niov > 0 && niov < INT_MAX);

	mutex_enter(&ring->vr_a_mutex);
	idx = ring->vr_cur_aidx;
	ndesc = (uint16_t)((unsigned)*ring->vr_avail_idx - (unsigned)idx);

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

	head = ring->vr_avail_ring[idx & ring->vr_mask];
	next = head;

	for (i = 0; i < niov; next = vdir.vd_next) {
		if (next >= ring->vr_size) {
			VIONA_PROBE2(bad_idx, viona_vring_t *, ring,
			    uint16_t, next);
			VIONA_RING_STAT_INCR(ring, bad_idx);
			goto bail;
		}

		vdir = ring->vr_descr[next];
		if ((vdir.vd_flags & VRING_DESC_F_INDIRECT) == 0) {
			if (vdir.vd_len == 0) {
				VIONA_PROBE2(desc_bad_len,
				    viona_vring_t *, ring,
				    uint32_t, vdir.vd_len);
				VIONA_RING_STAT_INCR(ring, desc_bad_len);
				goto bail;
			}
			buf = viona_gpa2kva(ring, vdir.vd_addr, vdir.vd_len);
			if (buf == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				goto bail;
			}
			iov[i].iov_base = buf;
			iov[i].iov_len = vdir.vd_len;
			i++;
		} else {
			const uint_t nindir = vdir.vd_len / 16;
			volatile struct virtio_desc *vindir;

			if ((vdir.vd_len & 0xf) || nindir == 0) {
				VIONA_PROBE2(indir_bad_len,
				    viona_vring_t *, ring,
				    uint32_t, vdir.vd_len);
				VIONA_RING_STAT_INCR(ring, indir_bad_len);
				goto bail;
			}
			vindir = viona_gpa2kva(ring, vdir.vd_addr, vdir.vd_len);
			if (vindir == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				goto bail;
			}
			next = 0;
			for (;;) {
				struct virtio_desc vp;

				/*
				 * A copy of the indirect descriptor is made
				 * here, rather than simply using a reference
				 * pointer.  This prevents malicious or
				 * erroneous guest writes to the descriptor
				 * from fooling the flags/bounds verification
				 * through a race.
				 */
				vp = vindir[next];
				if (vp.vd_flags & VRING_DESC_F_INDIRECT) {
					VIONA_PROBE1(indir_bad_nest,
					    viona_vring_t *, ring);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_nest);
					goto bail;
				} else if (vp.vd_len == 0) {
					VIONA_PROBE2(desc_bad_len,
					    viona_vring_t *, ring,
					    uint32_t, vp.vd_len);
					VIONA_RING_STAT_INCR(ring,
					    desc_bad_len);
					goto bail;
				}
				buf = viona_gpa2kva(ring, vp.vd_addr,
				    vp.vd_len);
				if (buf == NULL) {
					VIONA_PROBE_BAD_RING_ADDR(ring,
					    vp.vd_addr);
					VIONA_RING_STAT_INCR(ring,
					    bad_ring_addr);
					goto bail;
				}
				iov[i].iov_base = buf;
				iov[i].iov_len = vp.vd_len;
				i++;

				if ((vp.vd_flags & VRING_DESC_F_NEXT) == 0)
					break;
				if (i >= niov) {
					goto loopy;
				}

				next = vp.vd_next;
				if (next >= nindir) {
					VIONA_PROBE3(indir_bad_next,
					    viona_vring_t *, ring,
					    uint16_t, next,
					    uint_t, nindir);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_next);
					goto bail;
				}
			}
		}
		if ((vdir.vd_flags & VRING_DESC_F_NEXT) == 0) {
			*cookie = head;
			ring->vr_cur_aidx++;
			mutex_exit(&ring->vr_a_mutex);
			return (i);
		}
	}

loopy:
	VIONA_PROBE1(too_many_desc, viona_vring_t *, ring);
	VIONA_RING_STAT_INCR(ring, too_many_desc);
bail:
	mutex_exit(&ring->vr_a_mutex);
	return (-1);
}

void
vq_pushchain(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	volatile struct virtio_used *vu;
	uint_t uidx;

	mutex_enter(&ring->vr_u_mutex);

	uidx = *ring->vr_used_idx;
	vu = &ring->vr_used_ring[uidx++ & ring->vr_mask];
	vu->vu_idx = cookie;
	vu->vu_tlen = len;
	membar_producer();
	*ring->vr_used_idx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

void
vq_pushchain_many(viona_vring_t *ring, uint_t num_bufs, used_elem_t *elem)
{
	volatile struct virtio_used *vu;
	uint_t uidx, i;

	mutex_enter(&ring->vr_u_mutex);

	uidx = *ring->vr_used_idx;
	if (num_bufs == 1) {
		vu = &ring->vr_used_ring[uidx++ & ring->vr_mask];
		vu->vu_idx = elem[0].id;
		vu->vu_tlen = elem[0].len;
	} else {
		for (i = 0; i < num_bufs; i++) {
			vu = &ring->vr_used_ring[(uidx + i) & ring->vr_mask];
			vu->vu_idx = elem[i].id;
			vu->vu_tlen = elem[i].len;
		}
		uidx = uidx + num_bufs;
	}
	membar_producer();
	*ring->vr_used_idx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}
