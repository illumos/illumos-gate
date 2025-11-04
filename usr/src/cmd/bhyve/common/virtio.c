/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 * Copyright (c) 2019 Joyent, Inc.
 * Copyright (c) 2021 The FreeBSD Foundation
 *
 * Portions of this software were developed by Ka Ho Ng
 * under sponsorship of the FreeBSD Foundation.
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
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/stdbool.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include <machine/atomic.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <pthread_np.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"

/*
 * Functions for dealing with generalized "virtual devices" as
 * defined by <https://www.google.com/#output=search&q=virtio+spec>
 *
 * The reference for the implementation of virtio modern is on
 * <https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/>
 */

#define DPRINTF(vs, fmt, arg...) \
	do { \
		if ((((vs)->vs_flags) & VIRTIO_DEBUG) != 0) { \
			FPRINTLN(stdout, fmt, ##arg); \
			fflush(stdout); \
		} \
	} while (0)

#define VQ_NOTIFY_OFF_MULTIPLIER sizeof (uint32_t)

/*
 * In case we decide to relax the "virtio softc comes at the
 * front of virtio-based device softc" constraint, let's use
 * this to convert.
 */
#define	DEV_SOFTC(vs) ((void *)(vs))

#define VI_MASK(nbytes) \
        (((nbytes) >= 4) ? 0xFFFFFFFFu : (~0u >> (32 - 8 * (nbytes))))

static uint64_t vi_modern_pci_read(struct virtio_softc *, int, uint64_t, int);
static void vi_modern_pci_write(struct virtio_softc *, int, uint64_t, int,
    uint64_t);

/*
 * Link a virtio_softc to its constants, the device softc, and
 * the PCI emulation.
 */
void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *dev_softc, struct pci_devinst *pi, struct vqueue_info *queues)
{
	int i;

	/* vs and dev_softc addresses must match */
	assert((void *)vs == dev_softc);
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	pi->pi_arg = vs;

	vs->vs_queues = queues;
	for (i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

/*
 * Reset device (device-wide).  This erases all queues, i.e.,
 * all the queues become invalid (though we don't wipe out the
 * internal pointers, we just clear the VQ_ALLOC flag).
 *
 * It resets negotiated features to "none".
 *
 * If MSI-X is enabled, this also resets all the vectors to NO_VECTOR.
 */
void
vi_reset_dev(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	int i, nvq;

	if (vs->vs_mtx)
		assert(pthread_mutex_isowned_np(vs->vs_mtx));

	nvq = vs->vs_vc->vc_nvq;
	for (vq = vs->vs_queues, i = 0; i < nvq; vq++, i++) {
		vq->vq_flags = 0;
		vq->vq_last_avail = 0;
		vq->vq_next_used = 0;
		vq->vq_save_used = 0;
		vq->vq_pfn = 0;
		vq->vq_desc_gpa = vq->vq_avail_gpa = vq->vq_used_gpa = 0;
		vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	}
	vs->vs_negotiated_caps = 0;
	vs->vs_curq = 0;
	if (vs->vs_isr != 0)
		pci_lintr_deassert(vs->vs_pi);
	vs->vs_isr = 0;
	vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
}

/*
 * These are the capability bits common to all virtio devices.
 */
static const virtio_capstr_t virtio_caps[] = {
	{ VIRTIO_F_NOTIFY_ON_EMPTY,	"VIRTIO_F_NOTIFY_ON_EMPTY" },
	{ VIRTIO_F_ANY_LAYOUT,		"VIRTIO_F_ANY_LAYOUT" },
	{ VIRTIO_RING_F_INDIRECT_DESC,	"VIRTIO_RING_F_INDIRECT_DESC" },
	{ VIRTIO_RING_F_EVENT_IDX,	"VIRTIO_RING_F_EVENT_IDX" },
	{ VIRTIO_F_BAD_FEATURE,		"VIRTIO_F_BAD_FEATURE" },
	{ VIRTIO_F_VERSION_1,		"VIRTIO_F_VERSION_1" },
};

static void
vi_print_caps(struct virtio_softc *vs, uint64_t caps)
{
	struct virtio_consts *vc = vs->vs_vc;

	if ((vs->vs_flags & VIRTIO_DEBUG) == 0)
		return;

	for (size_t i = 0; i < vc->vc_ncapstr; i++) {
		if ((caps & vc->vc_capstr[i].vp_flag) != 0)
			FPRINTLN(stdout, "    -> %s", vc->vc_capstr[i].vp_name);
	}
	for (size_t i = 0; i < ARRAY_SIZE(virtio_caps); i++) {
		if ((caps & virtio_caps[i].vp_flag) != 0)
			FPRINTLN(stdout, "    -> %s", virtio_caps[i].vp_name);
	}
	fflush(stdout);
}

void
vi_set_debug(struct virtio_softc *vs, bool debug)
{
	if (debug)
		vs->vs_flags |= VIRTIO_DEBUG;
	else
		vs->vs_flags &= ~VIRTIO_DEBUG;
}

bool
vi_is_modern(struct virtio_softc *vs)
{
	return (vs->vs_negotiated_caps & VIRTIO_F_VERSION_1) != 0;
}

void __PRINTFLIKE(2)
vi_error(struct virtio_softc *vs, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "%s", raw_stdio ? "\r\n" : "\n");
	va_end(ap);

	if (vi_is_modern(vs)) {
		vs->vs_status |= VTCFG_STATUS_NEEDS_RST;
		vq_devcfg_changed(vs);
	}

	vs->vs_flags |= VIRTIO_BROKEN;
}

/*
 * Set I/O BAR (usually 0) to map legacy PCI config registers.
 */
static bool
vi_legacy_iobar_setup(struct virtio_softc *vs, int barnum)
{
	size_t size;

	/*
	 * We set the size to that which will accommodate the configuration
	 * space with MSI-X enabled, plus the configuration size.
	 */
	size = VIRTIO_PCI_CONFIG_OFF(1) + vs->vs_vc->vc_cfgsize;
	if (pci_emul_alloc_bar(vs->vs_pi, barnum, PCIBAR_IO, size) != 0)
		return (false);

	return (true);
}

virtio_pci_capcfg_t *
vi_pci_cfg_bytype(struct virtio_softc *vs, uint8_t cfgtype)
{
	for (uint_t i = 0; i < vs->vs_ncaps; i++) {
		if (vs->vs_caps[i].c_captype == cfgtype)
			return (&vs->vs_caps[i]);
	}
	return (NULL);
}

virtio_pci_capcfg_t *
vi_pci_cfg_bycapaddr(struct virtio_softc *vs, uint32_t start, uint32_t size)
{
	if (size == 0 || start > UINT32_MAX - size)
		return (NULL);

	const uint32_t end = start + size;

	for (uint_t i = 0; i < vs->vs_ncaps; i++) {
		virtio_pci_capcfg_t *cfg = &vs->vs_caps[i];
		const uint32_t cap_start = cfg->c_capoff;
		const uint32_t cap_end = cap_start + cfg->c_caplen;

		if (cap_start <= start && end <= cap_end)
			return (cfg);
	}

	return (NULL);
}

virtio_pci_capcfg_t *
vi_pci_cfg_bybaraddr(struct virtio_softc *vs, uint8_t bar, uint64_t offset,
    uint32_t size)
{
	/*
	 * We currently don't use the larger capabilities introduced in VirtIO
	 * 1.2 that allow for 64-bit offsets and sizes.
	 */
	if (size == 0 || offset > UINT32_MAX - size)
		return (NULL);

	const uint32_t end = offset + size;

	for (uint_t i = 0; i < vs->vs_ncaps; i++) {
		virtio_pci_capcfg_t *cfg = &vs->vs_caps[i];

		if (cfg->c_baridx != bar)
			continue;

		const uint32_t bar_start = cfg->c_baroff;
		const uint32_t bar_end = bar_start + cfg->c_barlen;

		if (bar_start <= offset && end <= bar_end)
			return (cfg);
	}

	return (NULL);
}

/*
 * Add a modern configuration structure capability.
 */
static bool
vi_modern_add_cfg(struct virtio_softc *vs, struct virtio_pci_cap *cap,
    int barnum, uint32_t baroff, uint32_t barlen, uint8_t caplen,
    uint8_t cfgtype)
{
	int capoff;

	cap->cap_vndr = PCIY_VENDOR;
	cap->cap_len = caplen;
	cap->cfg_type = cfgtype;
	cap->bar = barnum;
	cap->id = 0;
	cap->offset = baroff;
	cap->length = barlen;
	if (pci_emul_add_capability(vs->vs_pi, (u_char *)cap, caplen,
	    &capoff) != 0) {
		return (false);
	}

	vs->vs_caps[vs->vs_ncaps].c_captype = cfgtype;
	vs->vs_caps[vs->vs_ncaps].c_baridx = cap->bar;
	vs->vs_caps[vs->vs_ncaps].c_baroff = cap->offset;
	vs->vs_caps[vs->vs_ncaps].c_barlen = cap->length;
	vs->vs_caps[vs->vs_ncaps].c_capoff = capoff;
	vs->vs_caps[vs->vs_ncaps].c_caplen = caplen;
	vs->vs_ncaps++;
	VERIFY3U(vs->vs_ncaps, <=, sizeof (vs->vs_caps));

	return (true);
}

/*
 * Add COMMON_CFG configuration structure capability.
 */
static bool
vi_modern_add_common_cfg(struct virtio_softc *vs, int barnum, uint32_t *offp)
{
	struct virtio_pci_cap cap;
	uint32_t bardatalen;

	*offp = roundup2(*offp, VIRTIO_PCI_CAP_COMMON_CFG_ALIGN);
	/*
	 * We choose to round this BAR area up to a page size in common with
	 * other hypervisors.
	 */
	bardatalen = roundup2(sizeof (struct virtio_pci_common_cfg), PAGE_SIZE);

	memset(&cap, 0, sizeof (cap));
	if (vi_modern_add_cfg(vs, &cap, barnum, *offp, bardatalen, sizeof (cap),
	    VIRTIO_PCI_CAP_COMMON_CFG)) {
		*offp += bardatalen;
		return (true);
	}
	return (false);
}

/*
 * Add NOTIFY_CFG configuration structure capability.
 */
static bool
vi_modern_add_notify_cfg(struct virtio_softc *vs, int barnum, uint32_t *offp)
{
	struct virtio_pci_notify_cap cap;
	uint32_t bardatalen;

	*offp = roundup2(*offp, VIRTIO_PCI_CAP_NOTIFY_CFG_ALIGN);
	/*
	 * We choose to round this BAR area up to a page size in common with
	 * other hypervisors.
	 */
	bardatalen = roundup2(VQ_NOTIFY_OFF_MULTIPLIER * vs->vs_vc->vc_nvq,
	    PAGE_SIZE);

	memset(&cap, 0, sizeof (cap));
	cap.notify_off_multiplier = VQ_NOTIFY_OFF_MULTIPLIER;
	if (vi_modern_add_cfg(vs, &cap.cap, barnum, *offp, bardatalen,
	    sizeof (cap), VIRTIO_PCI_CAP_NOTIFY_CFG)) {
		*offp += bardatalen;
		return (true);
	}
	return (false);
}

/*
 * Add ISR_CFG configuration structure capability.
 */
static bool
vi_modern_add_isr_cfg(struct virtio_softc *vs, int barnum, uint32_t *offp)
{
	struct virtio_pci_cap cap;
	uint32_t bardatalen;

	*offp = roundup2(*offp, VIRTIO_PCI_CAP_ISR_CFG_ALIGN);
	/*
	 * While this capability could point to a single byte in the BAR, we
	 * choose to round up to a page in common with other hypervisors.
	 */
	bardatalen = PAGE_SIZE;

	memset(&cap, 0, sizeof (cap));
	if (vi_modern_add_cfg(vs, &cap, barnum, *offp, bardatalen, sizeof (cap),
	    VIRTIO_PCI_CAP_ISR_CFG)) {
		*offp += bardatalen;
		return (true);
	}
	return (false);
}

/*
 * Add DEV_CFG configuration structure capability.
 */
static bool
vi_modern_add_dev_cfg(struct virtio_softc *vs, int barnum, uint32_t *offp)
{
	struct virtio_pci_cap cap;
	uint32_t bardatalen;

	*offp = roundup2(*offp, VIRTIO_PCI_CAP_DEVICE_CFG_ALIGN);
	/*
	 * We choose to round this BAR area up to a page size in common with
	 * other hypervisors.
	 */
	bardatalen = PAGE_SIZE;

	memset(&cap, 0, sizeof (cap));
	if (vi_modern_add_cfg(vs, &cap, barnum, *offp, bardatalen, sizeof (cap),
	    VIRTIO_PCI_CAP_DEVICE_CFG)) {
		*offp += bardatalen;
		return (true);
	}
	return (false);
}

/*
 * Add PCI_CFG configuration structure capability.
 */
static bool
vi_modern_add_pci_cfg(struct virtio_softc *vs)
{
	struct virtio_pci_cfg_cap cap;

	memset(&cap, 0, sizeof (cap));
	memset(cap.pci_cfg_data, 0xff, sizeof (cap.pci_cfg_data));
	if (vi_modern_add_cfg(vs, &cap.cap, 0, 0, 0, sizeof (cap),
	    VIRTIO_PCI_CAP_PCI_CFG)) {
		vs->vs_pcicap = &vs->vs_caps[vs->vs_ncaps - 1];
		return (true);
	}
	return (false);
}

/*
 * Set up Virtio modern device pci configuration space
 */
static bool
vi_modern_membar_setup(struct virtio_softc *vs, int barnum)
{
	uint32_t baroff = 0;
	bool ret = false;

	ret |= vi_modern_add_common_cfg(vs, barnum, &baroff);
	ret |= vi_modern_add_notify_cfg(vs, barnum, &baroff);
	ret |= vi_modern_add_dev_cfg(vs, barnum, &baroff);
	ret |= vi_modern_add_isr_cfg(vs, barnum, &baroff);
	ret |= vi_modern_add_pci_cfg(vs);
	if (!ret)
		return (false);
	if (pci_emul_alloc_bar(vs->vs_pi, barnum, PCIBAR_MEM64, baroff) != 0)
		return (false);
	return (true);
}

void
vi_pci_init(struct pci_devinst *pi, virtio_mode_t mode,
    uint16_t legacy, uint16_t device_id, uint8_t class)
{
	struct virtio_softc *vs = pi->pi_arg;

	DPRINTF(vs, "VIRTIO %s PCI init mode=%x, legacy=0x%x devid=0x%x",
	    vs->vs_vc->vc_name, mode, legacy, device_id);

	/*
	 * We provide global options to force transitional devices to present
	 * as pure legacy or modern. This is mostly to support testing guest
	 * drivers or bhyve itself.
         *
         *   TRANSITIONAL mode usually exposes both interfaces
         *   - virtio.legacy=false forces a modern-only device
         *   - virtio.modern=false forces a legacy-only device
	 */
	if (mode == VIRTIO_MODE_TRANSITIONAL) {
		if (!get_config_bool_default("virtio.legacy", true))
			mode = VIRTIO_MODE_MODERN;
		else if (!get_config_bool_default("virtio.modern", true))
			mode = VIRTIO_MODE_LEGACY;
	}

	vs->vs_mode = mode;

	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, class);

	if (mode == VIRTIO_MODE_MODERN) {
		/*
		 * Pure modern / non-transitional device.
		 *
		 * Virtio 1.2, 4.1.2.1:
		 *   - PCI Device ID		= 0x1040 + virtio device ID
		 *   - PCI Revision ID>		>= 1
		 *   - PCI Subsystem Device ID	>= 0x40
		 *
		 * `device_id` here is the virtio Device ID from section 5
		 * [0x0-0x3f].
		 */
		VERIFY3U(device_id, <=, 0x3f);
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_DEVICEID_MODERN_MIN + device_id);
		/*
		 * For modern devices the spec only recommends that the
		 * Subsystem Device ID be >= 0x40 to avoid legacy binding.
		 * We choose to mirror the main device ID here so that the
		 * (vendor,device) and (subvendor,subdevice) pairs line up.
		 */
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0,
		    VIRTIO_PCI_DEVICEID_MODERN_MIN + device_id);
		pci_set_cfgdata16(pi, PCIR_REVID, 1);
	} else {
		/*
		 * Legacy-only or transitional device.
		 *
		 * For *transitional* devices, virtio 1.2, 4.1.2.3 requires:
		 *   - PCI Device ID in [0x1000, 0x103f]
		 *   - PCI Revision ID == 0
		 *   - PCI Subsystem Device ID == virtio Device ID
		 *
		 * We rely on the caller to pass:
		 *   - `legacy`		the 0x1000-0x103f PCI Device ID
		 *   - `device_id`	the virtio Device ID from section 5
		 *
		 * For a true legacy-only device this layout is also compatible
		 * with old drivers.
		 */
		VERIFY(legacy >= 0x1000 && legacy <= 0x103f);
		pci_set_cfgdata16(pi, PCIR_DEVICE, legacy);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, device_id);
		pci_set_cfgdata16(pi, PCIR_REVID, 0);
	}
}

/*
 * Set up Virtio device pci configuration space.
 */
bool
vi_pcibar_setup(struct virtio_softc *vs)
{
	DPRINTF(vs, "VIRTIO %s set up PCI BARs", vs->vs_vc->vc_name);

	assert(vs->vs_mode != VIRTIO_MODE_UNSET);

	if (vs->vs_mode == VIRTIO_MODE_LEGACY ||
	    vs->vs_mode == VIRTIO_MODE_TRANSITIONAL) {
		if (!vi_legacy_iobar_setup(vs, VIRTIO_LEGACY_BAR))
			return (false);
	}
	if (vs->vs_mode == VIRTIO_MODE_MODERN ||
	    vs->vs_mode == VIRTIO_MODE_TRANSITIONAL) {
		if (!vi_modern_membar_setup(vs, VIRTIO_MODERN_BAR))
			return (false);
	}

	return (true);
}

/*
 * Initialize MSI-X vector capabilities if we're to use MSI-X,
 * or MSI capabilities if not.
 *
 * We assume we want one MSI-X vector per queue, here, plus one
 * for the config vec.
 */
bool
vi_intr_init(struct virtio_softc *vs, bool use_msi, bool use_msix)
{
	int nvec;

	if (use_msix) {
		vs->vs_flags |= VIRTIO_USE_MSIX;
		VS_LOCK(vs);
		vi_reset_dev(vs); /* set all vectors to NO_VECTOR */
		VS_UNLOCK(vs);
		nvec = vs->vs_vc->vc_nvq + 1;
		if (pci_emul_add_msixcap(vs->vs_pi, nvec, VIRTIO_MSIX_BAR) != 0)
			return (false);
	} else {
		vs->vs_flags &= ~VIRTIO_USE_MSIX;
	}

	/* Only 1 MSI vector for bhyve */
	if (use_msi)
		pci_emul_add_msicap(vs->vs_pi, 1);

	/* Legacy interrupts are mandatory for virtio devices */
	pci_lintr_request(vs->vs_pi);

	return (true);
}

/*
 * Initialize the currently-selected virtio queue (vs->vs_curq)
 */
void
vi_vq_init(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	uint64_t phys;
	size_t size;
	char *base;

	vq = &vs->vs_queues[vs->vs_curq];

	phys = vq->vq_desc_gpa;
	size = vq->vq_qsize * sizeof (struct vring_desc);
	base = paddr_guest2host(vs->vs_pi->pi_vmctx, phys, size);
	if (base == NULL) {
		vi_error(vs, "Could not map queue 0x%x phys 0x%" PRIx64,
		    vq->vq_num, phys);
		return;
	}
	vq->vq_desc = (struct vring_desc *)base;

	phys = vq->vq_avail_gpa;
	size = sizeof (struct vring_avail) + sizeof (uint16_t) +
	    vq->vq_qsize * sizeof (uint16_t);
	base = paddr_guest2host(vs->vs_pi->pi_vmctx, phys, size);
	if (base == NULL) {
		vi_error(vs, "Could not map queue 0x%x phys 0x%" PRIx64,
		    vq->vq_num, phys);
		return;
	}
	vq->vq_avail = (struct vring_avail *)base;

	phys = vq->vq_used_gpa;
	size = sizeof (struct vring_used) + sizeof (uint16_t) +
	    vq->vq_qsize * sizeof (struct vring_used_elem);
	base = paddr_guest2host(vs->vs_pi->pi_vmctx, phys, size);
	if (base == NULL) {
		vi_error(vs, "Could not map queue 0x%x phys 0x%" PRIx64,
		    vq->vq_num, phys);
		return;
	}
	vq->vq_used = (struct vring_used *)base;

	/* Mark queue as allocated, and start at 0 when we use it. */
	vq->vq_flags = VQ_ALLOC;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
}

/*
 * Initialize the currently-selected virtio queue (vs->vs_curq).
 * The guest just gave us a page frame number, from which we can
 * calculate the addresses of the queue components.
 */
void
vi_legacy_vq_init(struct virtio_softc *vs, uint32_t pfn)
{
	struct vqueue_info *vq;
	uint64_t phys;

	vq = &vs->vs_queues[vs->vs_curq];
	vq->vq_pfn = pfn;
	phys = (uint64_t)pfn << LEGACY_VRING_PFN;

	/* First page(s) are descriptors... */
	vq->vq_desc_gpa = phys;
	phys += vq->vq_qsize * sizeof (struct vring_desc);
	/* ... immediately followed by "avail" ring (entirely uint16_t's) */
	vq->vq_avail_gpa = phys;
	phys += sizeof (struct vring_avail) + sizeof (uint16_t) +
	    vq->vq_qsize * sizeof (uint16_t);
	/* Then it's rounded up to the next page... */
	phys = roundup2(phys, LEGACY_VRING_ALIGN);
	/* ... and the last page(s) are the used ring. */
	vq->vq_used_gpa = phys;

	vi_vq_init(vs);
}

/*
 * Helper inline for vq_getchain(): record the i'th "real"
 * descriptor.
 */
static inline void
_vq_record(struct virtio_softc *vs, int i, struct vring_desc *vd,
    struct iovec *iov, int n_iov, struct vi_req *reqp)
{
	struct vmctx *ctx;
	uint32_t len;
	uint64_t addr;

	ctx = vs->vs_pi->pi_vmctx;

	if (i >= n_iov)
		return;
	len = atomic_load_32(&vd->len);
	addr = atomic_load_64(&vd->addr);
	iov[i].iov_len = len;
	iov[i].iov_base = paddr_guest2host(ctx, addr, len);
	if ((vd->flags & VRING_DESC_F_WRITE) == 0)
		reqp->readable++;
	else
		reqp->writable++;
}
#define	VQ_MAX_DESCRIPTORS	512	/* see below */

/*
 * Examine the chain of descriptors starting at the "next one" to
 * make sure that they describe a sensible request.  If so, return
 * the number of "real" descriptors that would be needed/used in
 * acting on this request.  This may be smaller than the number of
 * available descriptors, e.g., if there are two available but
 * they are two separate requests, this just returns 1.  Or, it
 * may be larger: if there are indirect descriptors involved,
 * there may only be one descriptor available but it may be an
 * indirect pointing to eight more.  We return 8 in this case,
 * i.e., we do not count the indirect descriptors, only the "real"
 * ones.
 *
 * Basically, this vets the "flags" and "next" field of each
 * descriptor and tells you how many are involved.  Since some may
 * be indirect, this also needs the vmctx (in the pci_devinst
 * at vs->vs_pi) so that it can find indirect descriptors.
 *
 * As we process each descriptor, we copy and adjust it (guest to
 * host address wise, also using the vmtctx) into the given iov[]
 * array (of the given size).  If the array overflows, we stop
 * placing values into the array but keep processing descriptors,
 * up to VQ_MAX_DESCRIPTORS, before giving up and returning -1.
 * So you, the caller, must not assume that iov[] is as big as the
 * return value (you can process the same thing twice to allocate
 * a larger iov array if needed, or supply a zero length to find
 * out how much space is needed).
 *
 * If some descriptor(s) are invalid, this prints a diagnostic message
 * and returns -1.  If no descriptors are ready now it simply returns 0.
 *
 * You are assumed to have done a vq_ring_ready() if needed (note
 * that vq_has_descs() does one).
 */
int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *reqp)
{
	int i;
	u_int ndesc, n_indir;
	u_int idx, next;
	struct vi_req req;
	struct vring_desc *vdir, *vindir, *vp;
	struct vmctx *ctx;
	struct virtio_softc *vs;
	const char *name;

	vs = vq->vq_vs;
	name = vs->vs_vc->vc_name;
	memset(&req, 0, sizeof (req));

	/*
	 * Note: it's the responsibility of the guest not to
	 * update vq->vq_avail->idx until all of the descriptors
         * the guest has written are valid (including all their
         * "next" fields and "flags").
	 *
	 * Compute (vq_avail->idx - last_avail) in integers mod 2**16.  This is
	 * the number of descriptors the device has made available
	 * since the last time we updated vq->vq_last_avail.
	 *
	 * We just need to do the subtraction as an unsigned int,
	 * then trim off excess bits.
	 */
	idx = vq->vq_last_avail;
	ndesc = (uint16_t)((u_int)vq->vq_avail->idx - idx);
	if (ndesc == 0)
		return (0);
	if (ndesc > vq->vq_qsize) {
		vi_error(vs,
		    "%s: ndesc (%u) out of range, driver confused?",
		    name, (u_int)ndesc);
		return (-1);
	}

	/*
	 * Now count/parse "involved" descriptors starting from
	 * the head of the chain.
	 *
	 * To prevent loops, we could be more complicated and
	 * check whether we're re-visiting a previously visited
	 * index, but we just abort if the count gets excessive.
	 */
	ctx = vs->vs_pi->pi_vmctx;
	req.idx = next = vq->vq_avail->ring[idx & (vq->vq_qsize - 1)];
	vq->vq_last_avail++;
	for (i = 0; i < VQ_MAX_DESCRIPTORS; next = vdir->next) {
		if (next >= vq->vq_qsize) {
			vi_error(vs,
			    "%s: descriptor index %u out of range, "
			    "driver confused?",
			    name, next);
			return (-1);
		}
		vdir = &vq->vq_desc[next];
		if ((vdir->flags & VRING_DESC_F_INDIRECT) == 0) {
			_vq_record(vs, i, vdir, iov, niov, &req);
			i++;
		} else if ((vs->vs_negotiated_caps &
		    VIRTIO_RING_F_INDIRECT_DESC) == 0) {
			vi_error(vs,
			    "%s: descriptor has forbidden INDIRECT flag, "
			    "driver confused?",
			    name);
			return (-1);
		} else {
			n_indir = vdir->len / 16;
			if ((vdir->len & 0xf) || n_indir == 0) {
				vi_error(vs,
				    "%s: invalid indir len 0x%x, "
				    "driver confused?",
				    name, (u_int)vdir->len);
				return (-1);
			}
			vindir = paddr_guest2host(ctx,
			    vdir->addr, vdir->len);
			/*
			 * Indirects start at the 0th, then follow
			 * their own embedded "next"s until those run
			 * out.  Each one's indirect flag must be off
			 * (we don't really have to check, could just
			 * ignore errors...).
			 */
			next = 0;
			for (;;) {
				vp = &vindir[next];
				if (vp->flags & VRING_DESC_F_INDIRECT) {
					vi_error(vs,
					    "%s: indirect desc has INDIR flag,"
					    " driver confused?",
					    name);
					return (-1);
				}
				_vq_record(vs, i, vp, iov, niov, &req);
				if (++i > VQ_MAX_DESCRIPTORS)
					goto loopy;
				if ((vp->flags & VRING_DESC_F_NEXT) == 0)
					break;
				next = vp->next;
				if (next >= n_indir) {
					vi_error(vs,
					    "%s: invalid next %u > %u, "
					    "driver confused?",
					    name, (u_int)next, n_indir);
					return (-1);
				}
			}
		}
		if ((vdir->flags & VRING_DESC_F_NEXT) == 0)
			goto done;
	}

loopy:
	vi_error(vs, "%s: descriptor loop? count > %d - driver confused?",
	    name, i);
	return (-1);

done:
	*reqp = req;
	return (i);
}

/*
 * Return the first n_chain request chains back to the available queue.
 *
 * (These chains are the ones you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_retchains(struct vqueue_info *vq, uint16_t n_chains)
{

	vq->vq_last_avail -= n_chains;
}

void
vq_relchain_prepare(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	struct vring_used *vuh;
	struct vring_used_elem *vue;
	uint16_t mask;

	/*
	 * Notes:
	 *  - mask is N-1 where N is a power of 2 so computes x % N
	 *  - vuh points to the "used" data shared with guest
	 *  - vue points to the "used" ring entry we want to update
	 */
	mask = vq->vq_qsize - 1;
	vuh = vq->vq_used;

	vue = &vuh->ring[vq->vq_next_used++ & mask];
	vue->id = idx;
	vue->len = iolen;
}

void
vq_relchain_publish(struct vqueue_info *vq)
{
	/*
	 * Ensure the used descriptor is visible before updating the index.
	 * This is necessary on ISAs with memory ordering less strict than x86
	 * (and even on x86 to act as a compiler barrier).
	 */
	atomic_thread_fence_rel();
	vq->vq_used->idx = vq->vq_next_used;
}

/*
 * Return specified request chain to the guest, setting its I/O length
 * to the provided value.
 *
 * (This chain is the one you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	vq_relchain_prepare(vq, idx, iolen);
	vq_relchain_publish(vq);
}

/*
 * Driver has finished processing "available" chains and calling
 * vq_relchain on each one.  If driver used all the available
 * chains, used_all should be set.
 *
 * If the "used" index moved we may need to inform the guest, i.e.,
 * deliver an interrupt.  Even if the used index did NOT move we
 * may need to deliver an interrupt, if the avail ring is empty and
 * we are supposed to interrupt on empty.
 *
 * Note that used_all_avail is provided by the caller because it's
 * a snapshot of the ring state when he decided to finish interrupt
 * processing -- it's possible that descriptors became available after
 * that point.  (It's also typically a constant 1/True as well.)
 */
void
vq_endchains(struct vqueue_info *vq, int used_all_avail)
{
	struct virtio_softc *vs;
	uint16_t event_idx, new_idx, old_idx;
	int intr;

	/*
	 * Interrupt generation: if we're using EVENT_IDX,
	 * interrupt if we've crossed the event threshold.
	 * Otherwise interrupt is generated if we added "used" entries,
	 * but suppressed by VRING_AVAIL_F_NO_INTERRUPT.
	 *
	 * In any case, though, if NOTIFY_ON_EMPTY is set and the
	 * entire avail was processed, we need to interrupt always.
	 */
	vs = vq->vq_vs;
	old_idx = vq->vq_save_used;
	vq->vq_save_used = new_idx = vq->vq_used->idx;

	/*
	 * Use full memory barrier between "idx" store from preceding
	 * vq_relchain() call and the loads from VQ_USED_EVENT_IDX() or
	 * "flags" field below.
	 */
	atomic_thread_fence_seq_cst();
	if (used_all_avail &&
	    (vs->vs_negotiated_caps & VIRTIO_F_NOTIFY_ON_EMPTY)) {
		intr = 1;
	} else if (vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) {
		event_idx = VQ_USED_EVENT_IDX(vq);
		/*
		 * This calculation is per docs and the kernel
		 * (see src/sys/dev/virtio/virtio_ring.h).
		 */
		intr = (uint16_t)(new_idx - event_idx - 1) <
			(uint16_t)(new_idx - old_idx);
	} else {
		intr = new_idx != old_idx &&
		    !(vq->vq_avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
	}
	if (intr)
		vq_interrupt(vs, vq);
}

/* Note: these are in sorted order to make for a fast search */
static struct config_reg {
	uint16_t	cr_offset;	/* register offset */
	uint8_t		cr_size;	/* size (bytes) */
	uint8_t		cr_ro;		/* true => reg is read only */
	const char	*cr_name;	/* name of reg */
} legacy_cfg_regs[] = {
	{ VIRTIO_PCI_HOST_FEATURES,		4, 1, "HOST_FEATURES" },
	{ VIRTIO_PCI_GUEST_FEATURES,		4, 0, "GUEST_FEATURES" },
	{ VIRTIO_PCI_QUEUE_PFN,			4, 0, "QUEUE_PFN" },
	{ VIRTIO_PCI_QUEUE_NUM,			2, 1, "QUEUE_NUM" },
	{ VIRTIO_PCI_QUEUE_SEL,			2, 0, "QUEUE_SEL" },
	{ VIRTIO_PCI_QUEUE_NOTIFY,		2, 0, "QUEUE_NOTIFY" },
	{ VIRTIO_PCI_STATUS,			1, 0, "STATUS" },
	{ VIRTIO_PCI_ISR,			1, 0, "ISR" },
	{ VIRTIO_MSI_CONFIG_VECTOR,		2, 0, "CONFIG_VECTOR" },
	{ VIRTIO_MSI_QUEUE_VECTOR,		2, 0, "QUEUE_VECTOR" },
}, common_cfg_regs[] = {
	{ VIRTIO_PCI_COMMON_DFSELECT,		4, 0, "DFSELECT" },
	{ VIRTIO_PCI_COMMON_DF,			4, 1, "DF" },
	{ VIRTIO_PCI_COMMON_GFSELECT,		4, 0, "GFSELECT" },
	{ VIRTIO_PCI_COMMON_GF,			4, 0, "GF" },
	{ VIRTIO_PCI_COMMON_MSIX,		2, 0, "MSIX" },
	{ VIRTIO_PCI_COMMON_NUMQ,		2, 1, "NUMQ" },
	{ VIRTIO_PCI_COMMON_STATUS,		1, 0, "STATUS" },
	{ VIRTIO_PCI_COMMON_CFGGENERATION,	1, 1, "CFGGENERATION" },
	{ VIRTIO_PCI_COMMON_Q_SELECT,		2, 0, "Q_SELECT" },
	{ VIRTIO_PCI_COMMON_Q_SIZE,		2, 0, "Q_SIZE" },
	{ VIRTIO_PCI_COMMON_Q_MSIX,		2, 0, "Q_MSIX" },
	{ VIRTIO_PCI_COMMON_Q_ENABLE,		2, 0, "Q_ENABLE" },
	{ VIRTIO_PCI_COMMON_Q_NOFF,		2, 1, "Q_NOFF" },
	{ VIRTIO_PCI_COMMON_Q_DESCLO,		4, 0, "Q_DESCLO" },
	{ VIRTIO_PCI_COMMON_Q_DESCHI,		4, 0, "Q_DESCHI" },
	{ VIRTIO_PCI_COMMON_Q_AVAILLO,		4, 0, "Q_AVAILLO" },
	{ VIRTIO_PCI_COMMON_Q_AVAILHI,		4, 0, "Q_AVAILHI" },
	{ VIRTIO_PCI_COMMON_Q_USEDLO,		4, 0, "Q_USEDLO" },
	{ VIRTIO_PCI_COMMON_Q_USEDHI,		4, 0, "Q_USEDHI" },
};

static inline struct config_reg *
vi_find_cr(struct config_reg *regstbl, size_t n, int offset) {
	u_int hi, lo, mid;
	struct config_reg *cr;

	lo = 0;
	hi = n - 1;
	while (hi >= lo) {
		mid = (hi + lo) >> 1;
		cr = &regstbl[mid];
		if (cr->cr_offset == offset)
			return (cr);
		if (cr->cr_offset < offset)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return (NULL);
}

static uint64_t
vi_hv_features(struct virtio_softc *vs, bool modern)
{
	return (modern ? vs->vs_vc->vc_hv_caps_modern | VIRTIO_F_VERSION_1 :
	    vs->vs_vc->vc_hv_caps_legacy);
}

/*
 * Handle legacy pci config space reads.
 *
 * If it's part of the legacy virtio config structure, do that.
 * Otherwise dispatch to the actual device backend's config read
 * callback.
 */
static uint64_t
vi_legacy_pci_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	struct virtio_consts *vc;
	struct config_reg *cr;
	uint64_t virtio_config_size;
	const char *name;
	uint32_t newoff;
	uint32_t value;
	int error;

	/* Checked by caller */
	assert(size == 1 || size == 2 || size == 4);

	vc = vs->vs_vc;
	name = vc->vc_name;
	value = VI_MASK(size);
	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(vs->vs_pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to underlying driver.
		 * If that fails, fall into general code.
		 */
		newoff = offset - virtio_config_size;
		if (newoff + size > vc->vc_cfgsize)
			goto bad;
		if (vc->vc_cfgread != NULL) {
			error = (*vc->vc_cfgread)(DEV_SOFTC(vs),
			    newoff, size, &value);
		} else {
			error = 0;
		}
		if (error == 0) {
			DPRINTF(vs, "VIRTIO %s LEGACY PCI devcfg read[0x%"
			    PRIx64 "] = 0x%x", name, newoff, value);
			goto done;
		}
	}

bad:
	cr = vi_find_cr(legacy_cfg_regs, nitems(legacy_cfg_regs), offset);
	if (cr == NULL || cr->cr_size != size) {
		if (cr != NULL) {
			/* offset must be OK, so size must be bad */
			EPRINTLN(
			    "%s: read from %s: bad size %d",
			    name, cr->cr_name, size);
		} else {
			EPRINTLN(
			    "%s: read from bad offset/size %jd/%d",
			    name, (uintmax_t)offset, size);
		}
		goto done;
	}

	switch (offset) {
	case VIRTIO_PCI_HOST_FEATURES:
		/* Caps for legacy PCI configuration layout is only 32bit */
		if (vc->vc_hv_features != NULL)
			value = vc->vc_hv_features(DEV_SOFTC(vs), false);
		else
			value = vi_hv_features(vs, false);
		break;
	case VIRTIO_PCI_GUEST_FEATURES:
		value = vs->vs_negotiated_caps;
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		if (!vi_is_modern(vs) && vs->vs_curq < vc->vc_nvq)
			value = vs->vs_queues[vs->vs_curq].vq_pfn;
		break;
	case VIRTIO_PCI_QUEUE_NUM:
		value = vs->vs_curq < vc->vc_nvq ?
		    vs->vs_queues[vs->vs_curq].vq_qsize : 0;
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		value = vs->vs_curq;
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		value = 0;	/* XXX */
		break;
	case VIRTIO_PCI_STATUS:
		value = vs->vs_status;
		break;
	case VIRTIO_PCI_ISR:
		value = vs->vs_isr;
		vs->vs_isr = 0;		/* a read clears this flag */
		if (value != 0)
			pci_lintr_deassert(vs->vs_pi);
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		value = vs->vs_msix_cfg_idx;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		value = vs->vs_curq < vc->vc_nvq ?
		    vs->vs_queues[vs->vs_curq].vq_msix_idx :
		    VIRTIO_MSI_NO_VECTOR;
		break;
	}

	DPRINTF(vs, "VIRTIO %s LEGACY READ %s = 0x%x",
	    name, cr->cr_name, value);

	switch (offset) {
	case VIRTIO_PCI_GUEST_FEATURES:
	case VIRTIO_PCI_HOST_FEATURES:
		vi_print_caps(vs, value);
		break;
	}

done:
	return (value);
}

/*
 * Handle legacy pci config space writes.
 *
 * If it's part of the legacy virtio config structure, do that.
 * Otherwise dispatch to the actual device backend's config write
 * callback.
 */
static void
vi_legacy_pci_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	struct vqueue_info *vq;
	struct virtio_consts *vc;
	struct config_reg *cr;
	uint64_t virtio_config_size;
	const char *name;
	uint32_t newoff;
	int error;

	/* Checked by caller */
	assert(size == 1 || size == 2 || size == 4);

	vc = vs->vs_vc;
	name = vc->vc_name;
	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(vs->vs_pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to underlying driver.
		 */
		newoff = offset - virtio_config_size;
		if (newoff + size > vc->vc_cfgsize)
			goto bad;
		if (vc->vc_cfgwrite != NULL) {
			error = (*vc->vc_cfgwrite)(DEV_SOFTC(vs),
			    newoff, size, value);
		} else {
			error = 0;
		}
		if (error == 0) {
			DPRINTF(vs,
			    "VIRTIO %s LEGACY PCI devcfg write[0x%"
			    PRIx64 "] = 0x%x", name, newoff, value);
			return;
		}
	}

bad:
	cr = vi_find_cr(legacy_cfg_regs, nitems(legacy_cfg_regs), offset);
	if (cr == NULL || cr->cr_size != size || cr->cr_ro) {
		if (cr != NULL) {
			/* offset must be OK, wrong size and/or reg is R/O */
			if (cr->cr_size != size)
				EPRINTLN(
				    "%s: write to %s: bad size %d",
				    name, cr->cr_name, size);
			if (cr->cr_ro)
				EPRINTLN(
				    "%s: write to read-only reg %s",
				    name, cr->cr_name);
		} else {
			EPRINTLN(
			    "%s: write to bad offset/size %jd/%d",
			    name, (uintmax_t)offset, size);
		}
		return;
	}

	DPRINTF(vs, "VIRTIO %s LEGACY WRITE %s = 0x%x",
	    name, cr->cr_name, value);

	switch (offset) {
	case VIRTIO_PCI_GUEST_FEATURES:
		if (vc->vc_hv_features != NULL)
			value &= vc->vc_hv_features(DEV_SOFTC(vs), false);
		else
			value &= vi_hv_features(vs, false);
		vs->vs_negotiated_caps = value;
		if (vc->vc_apply_features != NULL) {
			(*vc->vc_apply_features)(DEV_SOFTC(vs),
			    &vs->vs_negotiated_caps);
		}
		DPRINTF(vs, "NEGOTIATED FEATURES 0x%" PRIx64 " (%s)",
		    vs->vs_negotiated_caps,
		    vi_is_modern(vs) ? "modern" : "legacy");
		vi_print_caps(vs, vs->vs_negotiated_caps);
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		if (vc->vc_qinit != NULL)
			vc->vc_qinit(DEV_SOFTC(vs), value, false);
		else
			vi_legacy_vq_init(vs, value);
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		/*
		 * Note that the guest is allowed to select an
		 * invalid queue; we just need to return a QNUM
		 * of 0 while the bad queue is selected.
		 */
		vs->vs_curq = value;
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		if (value >= (unsigned int)vc->vc_nvq) {
			EPRINTLN("%s: queue %d notify out of range",
			    name, (int)value);
			break;
		}
		if ((vs->vs_flags & VIRTIO_BROKEN) != 0)
			break;
		vq = &vs->vs_queues[value];
		if (vq->vq_notify != NULL) {
			(*vq->vq_notify)(DEV_SOFTC(vs), vq);
		} else if (vc->vc_qnotify != NULL) {
			(*vc->vc_qnotify)(DEV_SOFTC(vs), vq);
		} else {
			EPRINTLN("%s: qnotify queue %d: missing vq/vc notify",
			    name, (int)value);
		}
		break;
	case VIRTIO_PCI_STATUS:
		vs->vs_status = value;
		if (value == 0) {
			DPRINTF(vs, "VIRTIO %s RESET", name);
			DPRINTF(vs, "**************************************");
			vc->vc_reset(DEV_SOFTC(vs));
		}
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		vs->vs_msix_cfg_idx = value;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		vq = &vs->vs_queues[vs->vs_curq];
		vq->vq_msix_idx = value;
		if (vc->vc_set_msix != NULL)
			vc->vc_set_msix(DEV_SOFTC(vs), vs->vs_curq);
		break;
	}
	return;

bad_qindex:
	EPRINTLN(
	    "%s: write config reg %s: curq %d >= max %d",
	    name, cr->cr_name, vs->vs_curq, vc->vc_nvq);
}

#define VI_HIGH(x) (((x) >> 32) & 0xffffffff)
#define VI_LOW(x) ((x) & 0xffffffff)

/*
 * Virtio modern:
 * Handle pci config space reads to common config structure.
 */
static uint64_t
vi_pci_common_cfg_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	uint64_t value = -1;
	struct virtio_consts *vc;
	struct vqueue_info *vq;
	struct config_reg *cr;
	const char *name;
	uint64_t capval = 0;

	/* Checked by caller */
	assert(size == 1 || size == 2 || size == 4);

	vc = vs->vs_vc;
	name = vc->vc_name;
	cr = vi_find_cr(common_cfg_regs, nitems(common_cfg_regs), offset);
	if (cr == NULL) {
		EPRINTLN("%s: read from bad offset/size 0x%jx/0x%x",
		    name, (uintmax_t)offset, size);
		goto done;
	}
	/*
	 * We check that the requested size matches the register at this
	 * offset, and refuse to process it if there is a mismatch.
	 */
	if (cr->cr_size != size) {
		EPRINTLN("%s: read from %s: bad size 0x%x",
		    name, cr->cr_name, size);
		goto done;
	}

	vq = (vs->vs_curq < vc->vc_nvq ? &vs->vs_queues[vs->vs_curq] : NULL);

	switch (offset) {
	case VIRTIO_PCI_COMMON_DFSELECT:
		value = vs->vs_dfselect;
		break;
	case VIRTIO_PCI_COMMON_DF:
		if (vc->vc_hv_features != NULL)
			value = vc->vc_hv_features(DEV_SOFTC(vs), true);
		else
			value = vi_hv_features(vs, true);
		switch (vs->vs_dfselect) {
		case 0:
			capval = value = VI_LOW(value);
			break;
		case 1:
			value = VI_HIGH(value);
			capval = value << 32;
			break;
		default:
			value = capval = 0;
			break;
		}
		/* capval is debug printed below */
		break;
	case VIRTIO_PCI_COMMON_GFSELECT:
		value = vs->vs_gfselect;
		break;
	case VIRTIO_PCI_COMMON_GF:
		value = vs->vs_negotiated_caps;
		switch (vs->vs_gfselect) {
		case 0:
			capval = value = VI_LOW(value);
			break;
		case 1:
			value = VI_HIGH(value);
			capval = value << 32;
			break;
		default:
			value = capval = 0;
			break;
		}
		/* capval is debug printed below */
		break;
	case VIRTIO_PCI_COMMON_MSIX:
		value = vs->vs_msix_cfg_idx;
		break;
	case VIRTIO_PCI_COMMON_NUMQ:
		value = vc->vc_nvq;
		break;
	case VIRTIO_PCI_COMMON_STATUS:
		value = vs->vs_status;
		break;
	case VIRTIO_PCI_COMMON_CFGGENERATION:
		if ((vs->vs_flags & VIRTIO_DEVCFG_CHG) != 0) {
			vs->vs_devcfg_gen++;
			vs->vs_flags &= ~VIRTIO_DEVCFG_CHG;
		}
		value = vs->vs_devcfg_gen;
		break;
	case VIRTIO_PCI_COMMON_Q_SELECT:
		value = vs->vs_curq;
		break;
	case VIRTIO_PCI_COMMON_Q_SIZE:
		value = vq != NULL ? vq->vq_qsize : 0;
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		if (vq != NULL)
			value = vq->vq_msix_idx;
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		value = vq != NULL ? !!(vq->vq_flags & VQ_ENABLED) : 0;
		break;
	case VIRTIO_PCI_COMMON_Q_NOFF:
		/* queue_notify_off is equal to qid for now */
		value = vs->vs_curq;
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
		if (vq != NULL)
			value = VI_LOW(vq->vq_desc_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_DESCHI:
		if (vq != NULL)
			value = VI_HIGH(vq->vq_desc_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
		if (vq != NULL)
			value = VI_LOW(vq->vq_avail_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
		if (vq != NULL)
			value = VI_HIGH(vq->vq_avail_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDLO:
		if (vq != NULL)
			value = VI_LOW(vq->vq_used_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		if (vq != NULL)
			value = VI_HIGH(vq->vq_used_gpa);
		break;
	}

done:
	value &= VI_MASK(size);
	DPRINTF(vs, "VIRTIO %s COMMON %s read = 0x%x",
	    name, cr->cr_name, value);

	switch (offset) {
	case VIRTIO_PCI_COMMON_DF:
	case VIRTIO_PCI_COMMON_GF:
		vi_print_caps(vs, capval);
		break;
	}
	return (value);
}

/*
 * Virtio modern:
 * Handle pci config space writes to common config structure.
 */
static void
vi_pci_common_cfg_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	uint64_t capval = 0;
	struct virtio_consts *vc;
	struct vqueue_info *vq;
	struct config_reg *cr;
	const char *name;

	/* Checked by caller */
	assert(size == 1 || size == 2 || size == 4);

	vc = vs->vs_vc;
	name = vc->vc_name;
	value &= VI_MASK(size);

	cr = vi_find_cr(common_cfg_regs, nitems(common_cfg_regs), offset);
	if (cr == NULL) {
		EPRINTLN( "%s: write to %s: bad size 0x%x",
		    name, cr->cr_name, size);
		return;
	}
	/*
	 * We check that the requested size matches the register at this
	 * offset, and refuse to process it if there is a mismatch.
	 */
	if (cr->cr_size != size) {
		EPRINTLN("%s: write to bad offset/size 0x%jx/0x%x",
		    name, (uintmax_t)offset, size);
		return;
	}

	DPRINTF(vs, "VIRTIO %s COMMON %s write 0x%x", name, cr->cr_name, value);

	vq = NULL;
	switch (offset) {
	case VIRTIO_PCI_COMMON_Q_SIZE:
	case VIRTIO_PCI_COMMON_Q_MSIX:
	case VIRTIO_PCI_COMMON_Q_ENABLE:
	case VIRTIO_PCI_COMMON_Q_DESCLO:
	case VIRTIO_PCI_COMMON_Q_DESCHI:
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
	case VIRTIO_PCI_COMMON_Q_USEDLO:
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		if (vs->vs_curq >= vc->vc_nvq) {
			EPRINTLN("%s: write queue %d out of range",
			    name, vs->vs_curq);
			goto bad_write;
		}
		vq = &vs->vs_queues[vs->vs_curq];
		break;
	default:
		break;
	}

	switch (offset) {
	case VIRTIO_PCI_COMMON_DFSELECT:
		vs->vs_dfselect = value;
		break;
	case VIRTIO_PCI_COMMON_GFSELECT:
		vs->vs_gfselect = value;
		break;
	case VIRTIO_PCI_COMMON_GF:
		switch (vs->vs_gfselect) {
		case 0:
			capval = value;
			vs->vs_negotiated_caps =
			    (VI_HIGH(vs->vs_negotiated_caps) << 32) | value;
			break;
		case 1:
			capval = value << 32;
			vs->vs_negotiated_caps =
			    capval | VI_LOW(vs->vs_negotiated_caps);
			break;
		default:
			capval = 0;
			break;
		}
		vi_print_caps(vs, capval);

		uint64_t hvfeat;
		if (vc->vc_hv_features != NULL)
			hvfeat = vc->vc_hv_features(DEV_SOFTC(vs), true);
		else
			hvfeat = vi_hv_features(vs, true);
		vs->vs_negotiated_caps &= hvfeat;
		break;
	case VIRTIO_PCI_COMMON_MSIX:
		vs->vs_msix_cfg_idx = value;
		break;
	case VIRTIO_PCI_COMMON_STATUS:
		if (value == 0) {
			DPRINTF(vs, "VIRTIO %s RESET", name);
			(*vc->vc_reset)(DEV_SOFTC(vs));
			vs->vs_status = value;
			break;
		}
		if ((vs->vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0 &&
		    (value & VIRTIO_CONFIG_S_FEATURES_OK) != 0) {
			if (vc->vc_apply_features != NULL) {
				(*vc->vc_apply_features)(DEV_SOFTC(vs),
				    &vs->vs_negotiated_caps);
			}
			DPRINTF(vs, "NEGOTIATED FEATURES 0x%" PRIx64 " (%s)",
			    vs->vs_negotiated_caps,
			    vi_is_modern(vs) ? "modern" : "legacy");
			vi_print_caps(vs, vs->vs_negotiated_caps);
		}
		vs->vs_status = value;
		break;
	case VIRTIO_PCI_COMMON_Q_SELECT:
		if (value >= vc->vc_nvq) {
			EPRINTLN("%s: queue select %d out of range",
			    name, (int)value);
			goto bad_write;
		}
		vs->vs_curq = value;
		break;
	case VIRTIO_PCI_COMMON_Q_SIZE:
		/*
		 * If the guest has passed us a queue size that is not a power
		 * of two, something is very wrong.
		 */
		if (!ISP2(value)) {
			vi_error(vs, "Bad queue size 0x%" PRIx64
			    " for qid 0x%x, not power of 2",
			    value, vq->vq_num);
		} else {
			vq->vq_qsize = value;
		}
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		vq->vq_msix_idx = value;
		if (vc->vc_set_msix != NULL)
			vc->vc_set_msix(DEV_SOFTC(vs), vs->vs_curq);
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		if ((vq->vq_flags & VQ_ENABLED) == 0 && value == 1) {
			if (vc->vc_qinit != NULL)
				vc->vc_qinit(DEV_SOFTC(vs), 0, true);
			else
				vi_vq_init(vs);
			vq->vq_flags |= VQ_ENABLED;
		} else if (value == 0) {
			/*
			 * The driver is not permitted to write a 0 to this
			 * register. We choose to ignore it rather than fault
			 * the device.
			 */
		}
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
		vq->vq_desc_gpa = (VI_HIGH(vq->vq_desc_gpa) << 32) | value;
		break;
	case VIRTIO_PCI_COMMON_Q_DESCHI:
		vq->vq_desc_gpa = (value << 32) | VI_LOW(vq->vq_desc_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
		vq->vq_avail_gpa = (VI_HIGH(vq->vq_avail_gpa) << 32) | value;
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
		vq->vq_avail_gpa = (value << 32) | VI_LOW(vq->vq_avail_gpa);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDLO:
		vq->vq_used_gpa = (VI_HIGH(vq->vq_used_gpa) << 32) | value;
		break;
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		vq->vq_used_gpa = (value << 32) | VI_LOW(vq->vq_used_gpa);
		break;
	default:
		EPRINTLN("%s: write to bad offset/size %jd/%d", name,
		    (uintmax_t)offset, size);
		goto bad_write;
	}

	return;

bad_write:
	return;
}

/*
 * Virtio modern:
 * Handle pci MMIO reads to the notification structure.
 *
 * Reading the structure always returns zero.
 */
static uint64_t
vi_pci_notify_cfg_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	return (0);
}

/*
 * Virtio modern:
 * Handle pci MMIO writes to the notification structure.
 *
 * VIRTIO_F_NOTIFICATION_DATA is not a feature that this device advertises
 * so we only need to consider the simple case where the vq index is written
 * into the registers.
 */
static void
vi_pci_notify_cfg_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	struct virtio_consts *vc = vs->vs_vc;
	const char *name = vc->vc_name;
	unsigned int qid = value;
	struct vqueue_info *vq;

	DPRINTF(vs, "VIRTIO %s notify queue 0x%x write 0x%x",
	    name, offset, value);

	if (size != 2) {
		EPRINTLN("%s: bad size 0x%x access at offset 0x%" PRIx64,
		    name, size, offset);
		return;
	}

	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0)
		return;

	if ((vs->vs_flags & VIRTIO_BROKEN) != 0)
		return;

	if (offset != qid * VQ_NOTIFY_OFF_MULTIPLIER) {
		EPRINTLN(
		    "%s: queue %u notify does not have matching offset at 0x%"
		    PRIx64, name, qid, offset);
		return;
	}

	if (qid >= vc->vc_nvq) {
		EPRINTLN("%s: queue %u notify out of range", name, qid);
		return;
	}

	vq = &vs->vs_queues[qid];
	if ((vq->vq_flags & VQ_ENABLED) == 0)
		return;
	if (vq->vq_notify != NULL)
		(*vq->vq_notify)(DEV_SOFTC(vs), vq);
	else if (vc->vc_qnotify != NULL)
		(*vc->vc_qnotify)(DEV_SOFTC(vs), vq);
	else
		EPRINTLN("%s: qnotify queue %u: no vq/vc notify", name, qid);
}

/*
 * Virtio modern:
 * Handle pci MMIO reads to ISR structure.
 *
 * The ISR structure has a relaxed requirement on alignment.
 */
static uint64_t
vi_pci_isr_cfg_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	uint64_t value;

	if (offset != 0)
		return (0);

	value = vs->vs_isr;
	vs->vs_isr = 0;
	DPRINTF(vs, "VIRTIO ISR read[0x%" PRIx64 "] = 0x%x", offset, value);
	if (value != 0)
		pci_lintr_deassert(vs->vs_pi);
	return (value);
}

/*
 * Virtio modern:
 * pci MMIO writes to ISR structure are disallowed.
 */
static void
vi_pci_isr_cfg_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	const char *name = vs->vs_vc->vc_name;

	EPRINTLN("%s: invalid write into isr cfg", name);
}

/*
 * Virtio modern:
 * Handle pci MMIO reads to device-specific config structure.
 */
static uint64_t
vi_pci_dev_cfg_read(struct virtio_softc *vs, uint64_t offset, int size)
{
	struct virtio_consts *vc = vs->vs_vc;
	uint32_t value = VI_MASK(size);

	if (offset + size > vc->vc_cfgsize)
		return (value);

	vc->vc_cfgread(DEV_SOFTC(vs), offset, size, &value);
	DPRINTF(vs, "VIRTIO %s PCI devcfg read[0x%" PRIx64 "] = 0x%x",
	    vs->vs_vc->vc_name, offset, value);
	return (value);
}

/*
 * Virtio modern:
 * Handle pci MMIO writes to device-specific config structure.
 */
static void
vi_pci_dev_cfg_write(struct virtio_softc *vs, uint64_t offset, int size,
    uint64_t value)
{
	struct virtio_consts *vc = vs->vs_vc;

	value &= VI_MASK(size);

	if (offset + size > vc->vc_cfgsize)
		return;
	if (vc->vc_cfgwrite != NULL)
		vc->vc_cfgwrite(DEV_SOFTC(vs), offset, size, value);
	DPRINTF(vs, "VIRTIO %s PCI devcfg write[0x%" PRIx64 "] = 0x%x",
	    vs->vs_vc->vc_name, offset, value);
}

/*
 * Handle configuration space reads.
 */
int
vi_pci_cfgread(struct pci_devinst *pi, int offset, int bytes, uint32_t *retval)
{
	struct virtio_softc *vs = pi->pi_arg;
	virtio_pci_capcfg_t *cfg;
	uint32_t baroff, barlen;
	int baridx;

	cfg = vi_pci_cfg_bycapaddr(vs, offset, bytes);

	/* If this is not a VirtIO cap, use the default cfgspace handler */
	if (cfg == NULL)
		return (PE_CFGRW_DEFAULT);

	/* Only the PCI cap has special handling */
	if (cfg->c_captype != VIRTIO_PCI_CAP_PCI_CFG)
		return (PE_CFGRW_DEFAULT);

	/* and then only the data field */
	if (offset != vs->vs_pcicap->c_capoff +
	    offsetof(struct virtio_pci_cfg_cap, pci_cfg_data)) {
		return (PE_CFGRW_DEFAULT);
	}

	if (bytes != 1 && bytes != 2 && bytes != 4)
		return (PE_CFGRW_DROP);

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	baridx = pci_get_cfgdata8(pi,
	    offset + offsetof(struct virtio_pci_cap, bar));
	baroff = pci_get_cfgdata32(pi,
	    offset + offsetof(struct virtio_pci_cap, offset));
	barlen = pci_get_cfgdata32(pi,
	    offset + offsetof(struct virtio_pci_cap, length));
	if (baridx > PCIR_MAX_BAR_0) {
		*retval = VI_MASK(bytes);
		goto done;
	}
	*retval = vi_modern_pci_read(vs, baridx, baroff, barlen);

done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);

	DPRINTF(vs, "VIRTIO PCI READ BAR%u[0x%x+%x] = 0x%x",
	    baridx, baroff, barlen, *retval);

	return (PE_CFGRW_DROP);
}

/*
 * Handle configuration space writes.
 */
int
vi_pci_cfgwrite(struct pci_devinst *pi, int offset, int bytes, uint32_t val)
{
	struct virtio_softc *vs = pi->pi_arg;
	virtio_pci_capcfg_t *cfg;
	uint32_t baroff, barlen;
	int baridx;

	cfg = vi_pci_cfg_bycapaddr(vs, offset, bytes);

	/* If this is not a VirtIO cap, use the default cfgspace handler */
	if (cfg == NULL)
		return (PE_CFGRW_DEFAULT);

	/* Only the PCI VirtIO cap can be written to */
	if (cfg->c_captype != VIRTIO_PCI_CAP_PCI_CFG)
		return (PE_CFGRW_DROP);

	/* and then only the data field needs special handling */
	if (offset != vs->vs_pcicap->c_capoff +
	    offsetof(struct virtio_pci_cfg_cap, pci_cfg_data)) {
		return (PE_CFGRW_DEFAULT);
	}

	if (bytes != 1 && bytes != 2 && bytes != 4)
		return (PE_CFGRW_DROP);

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	baridx = pci_get_cfgdata8(pi,
	    offset + offsetof(struct virtio_pci_cap, bar));
	baroff = pci_get_cfgdata32(pi,
	    offset + offsetof(struct virtio_pci_cap, offset));
	barlen = pci_get_cfgdata32(pi,
	    offset + offsetof(struct virtio_pci_cap, length));
	if (baridx > PCIR_MAX_BAR_0)
		goto done;
	vi_modern_pci_write(vs, baridx, baroff, barlen, val);

done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);

	DPRINTF(vs, "VIRTIO PCI WRITE BAR%x[0x%x+%x] = 0x%x",
	    baridx, baroff, barlen, val);

	return (PE_CFGRW_DROP);
}

/*
 * Handle pci config space reads to virtio-related structures
 */
static uint64_t
vi_modern_pci_read(struct virtio_softc *vs, int baridx, uint64_t offset,
    int size)
{
	virtio_pci_capcfg_t *cfg;
	uint64_t value = VI_MASK(size);

	cfg = vi_pci_cfg_bybaraddr(vs, baridx, offset, size);
	if (cfg == NULL)
		return (value);

	offset -= cfg->c_baroff;

	switch (cfg->c_captype) {
	case VIRTIO_PCI_CAP_COMMON_CFG:
		value = vi_pci_common_cfg_read(vs, offset, size);
		break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
		value = vi_pci_notify_cfg_read(vs, offset, size);
		break;
	case VIRTIO_PCI_CAP_ISR_CFG:
		value = vi_pci_isr_cfg_read(vs, offset, size);
		break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
		value = vi_pci_dev_cfg_read(vs, offset, size);
		break;
	default:
		break;
	}

	return (value);
}

/*
 * Handle pci config space reads to virtio-related structures
 */
static void
vi_modern_pci_write(struct virtio_softc *vs, int baridx, uint64_t offset,
    int size, uint64_t value)
{
	virtio_pci_capcfg_t *cfg;

	cfg = vi_pci_cfg_bybaraddr(vs, baridx, offset, size);
	if (cfg == NULL)
		return;

	offset -= cfg->c_baroff;

	switch (cfg->c_captype) {
	case VIRTIO_PCI_CAP_COMMON_CFG:
		vi_pci_common_cfg_write(vs, offset, size, value);
		break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
		vi_pci_notify_cfg_write(vs, offset, size, value);
		break;
	case VIRTIO_PCI_CAP_ISR_CFG:
		vi_pci_isr_cfg_write(vs, offset, size, value);
		break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
		vi_pci_dev_cfg_write(vs, offset, size, value);
		break;
	}
}

/*
 * Handle virtio bar reads.
 *
 * If it's to the MSI-X info, dispatch the reads to the msix handling code.
 * Otherwise, dispatch the reads to virtio device code.
 */
uint64_t
vi_pci_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct virtio_softc *vs = pi->pi_arg;
	uint64_t value;

	if ((vs->vs_flags & VIRTIO_USE_MSIX) != 0 &&
	    (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi))) {
		return (pci_emul_msix_tread(pi, offset, size));
	}

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	value = VI_MASK(size);

	if (size != 1 && size != 2 && size != 4)
		goto done;

	switch (baridx) {
	case VIRTIO_LEGACY_BAR:
		value = vi_legacy_pci_read(vs, offset, size);
		break;
	case VIRTIO_MODERN_BAR:
		value = vi_modern_pci_read(vs, baridx, offset, size);
		break;
	default:
		break;
	}

done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);
	return (value);
}

/*
 * Handle virtio bar writes.
 *
 * If it's to the MSI-X info, dispatch the writes to the msix handling code.
 * Otherwise, dispatch the writes to virtio device code.
 */
void
vi_pci_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct virtio_softc *vs = pi->pi_arg;
	struct virtio_consts *vc = vs->vs_vc;

	if ((vs->vs_flags & VIRTIO_USE_MSIX) != 0 &&
	    (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi))) {
		if (pci_emul_msix_twrite(pi, offset, size, value) == 0 &&
		    vc->vc_update_msix != NULL) {
			vc->vc_update_msix(DEV_SOFTC(vs), offset);
		}
		return;
	}

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	if (size != 1 && size != 2 && size != 4)
		goto done;

	switch (baridx) {
	case VIRTIO_LEGACY_BAR:
		vi_legacy_pci_write(vs, offset, size, value);
		break;
	case VIRTIO_MODERN_BAR:
		vi_modern_pci_write(vs, baridx, offset, size, value);
		break;
	default:
		break;
	}

done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);
}
