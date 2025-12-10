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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 */

/*
 * VIRTIO FRAMEWORK: Operations via the legacy interface.
 *
 * For design and usage documentation, see the comments in "virtio.h".
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include "virtio.h"
#include "virtio_impl.h"

/*
 * Reads and writes to the legacy BAR.
 */

static inline uint8_t
virtio_get_leg8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_barh, (uint8_t *)(vio->vio_bar + offset)));
}

static inline uint16_t
virtio_get_leg16(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get16(vio->vio_barh, (uint16_t *)(vio->vio_bar + offset)));
}

static inline uint32_t
virtio_get_leg32(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get32(vio->vio_barh, (uint32_t *)(vio->vio_bar + offset)));
}

static inline void
virtio_put_leg8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	ddi_put8(vio->vio_barh, (uint8_t *)(vio->vio_bar + offset), value);
}

static inline void
virtio_put_leg16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_barh, (uint16_t *)(vio->vio_bar + offset), value);
}

static inline void
virtio_put_leg32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_barh, (uint32_t *)(vio->vio_bar + offset), value);
}

/*
 * Reads and writes to the device configuration area.
 * Note that these functions take vio_mutex to avoid racing with interrupt
 * enable/disable, when the device-specific offset can potentially change.
 */

uint8_t
virtio_legacy_devcfg_get8(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint8_t r = virtio_get_leg8(vio, vio->vio_legacy_cfg_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint16_t
virtio_legacy_devcfg_get16(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint16_t r = virtio_get_leg16(vio, vio->vio_legacy_cfg_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint32_t
virtio_legacy_devcfg_get32(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	uint32_t r = virtio_get_leg32(vio, vio->vio_legacy_cfg_offset + offset);
	mutex_exit(&vio->vio_mutex);

	return (r);
}

uint64_t
virtio_legacy_devcfg_get64(virtio_t *vio, uintptr_t offset)
{
	mutex_enter(&vio->vio_mutex);
	/*
	 * On at least some systems, a 64-bit read or write to this BAR is not
	 * possible.  For legacy devices, there is no generation number to use
	 * to determine if configuration may have changed half-way through a
	 * read.  We need to continue to read both halves of the value until we
	 * read the same value at least twice.
	 */
	uintptr_t o_lo = vio->vio_legacy_cfg_offset + offset;
	uintptr_t o_hi = o_lo + 4;

	uint64_t val = virtio_get_leg32(vio, o_lo) |
	    ((uint64_t)virtio_get_leg32(vio, o_hi) << 32);

	for (;;) {
		uint64_t tval = virtio_get_leg32(vio, o_lo) |
		    ((uint64_t)virtio_get_leg32(vio, o_hi) << 32);

		if (tval == val) {
			break;
		}

		val = tval;
	}

	mutex_exit(&vio->vio_mutex);
	return (val);
}

void
virtio_legacy_devcfg_put8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put_leg8(vio, vio->vio_legacy_cfg_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

void
virtio_legacy_devcfg_put16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put_leg16(vio, vio->vio_legacy_cfg_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

void
virtio_legacy_devcfg_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	mutex_enter(&vio->vio_mutex);
	virtio_put_leg32(vio, vio->vio_legacy_cfg_offset + offset, value);
	mutex_exit(&vio->vio_mutex);
}

/* Legacy devices have no configuration generation number */
uint8_t
virtio_legacy_devcfg_getgen(virtio_t *vio)
{
	return (0);
}

uint64_t
virtio_legacy_device_get_features(virtio_t *vio)
{
	return (virtio_get_leg32(vio, VIRTIO_LEGACY_FEATURES_DEVICE));
}

static bool
virtio_legacy_device_set_features(virtio_t *vio, uint64_t features)
{
	/* The legacy interface only supports 32 feature bits */
	VERIFY0(features >> 32);
	virtio_put_leg32(vio, VIRTIO_LEGACY_FEATURES_DRIVER, features);
	return (true);
}

static void
virtio_legacy_set_status_locked(virtio_t *vio, uint8_t status)
{
	VERIFY3U(status, !=, 0);
	VERIFY(MUTEX_HELD(&vio->vio_mutex));

	uint8_t old = virtio_get_leg8(vio, VIRTIO_LEGACY_DEVICE_STATUS);
	virtio_put_leg8(vio, VIRTIO_LEGACY_DEVICE_STATUS, status | old);
}

static uint8_t
virtio_legacy_get_status(virtio_t *vio)
{
	return (virtio_get_leg8(vio, VIRTIO_LEGACY_DEVICE_STATUS));
}

static void
virtio_legacy_device_reset_locked(virtio_t *vio)
{
	VERIFY(MUTEX_HELD(&vio->vio_mutex));
	virtio_put_leg8(vio, VIRTIO_LEGACY_DEVICE_STATUS, VIRTIO_STATUS_RESET);
}

static uint8_t
virtio_legacy_isr_status(virtio_t *vio)
{
	uint8_t val;

	val = virtio_get_leg8(vio, VIRTIO_LEGACY_ISR_STATUS);

	return (val);
}

static uint16_t
virtio_legacy_msix_config_get(virtio_t *vio)
{
	return (virtio_get_leg16(vio, VIRTIO_LEGACY_MSIX_CONFIG));
}

static void
virtio_legacy_msix_config_set(virtio_t *vio, uint16_t msi)
{
	virtio_put_leg16(vio, VIRTIO_LEGACY_MSIX_CONFIG, msi);
}

static void
virtio_legacy_queue_notify(virtio_queue_t *viq)
{
	virtio_put_leg16(viq->viq_virtio, VIRTIO_LEGACY_QUEUE_NOTIFY,
	    viq->viq_index);
}

static void
virtio_legacy_queue_select(virtio_t *vio, uint16_t qidx)
{
	virtio_put_leg16(vio, VIRTIO_LEGACY_QUEUE_SELECT, qidx);
}

static uint16_t
virtio_legacy_queue_size_get(virtio_t *vio, uint16_t qidx)
{
	uint16_t val;

	virtio_acquireq(vio, qidx);
	val = virtio_get_leg16(vio, VIRTIO_LEGACY_QUEUE_SIZE);
	virtio_releaseq(vio);

	return (val);
}

static bool
virtio_legacy_queue_enable_get(virtio_t *vio, uint16_t qidx)
{
	/* Legacy queues are always enabled */
	return (true);
}

static void
virtio_legacy_queue_enable_set(virtio_t *vio, uint16_t qidx, bool enable)
{
	/* Legacy queues are always enabled */
}

static void
virtio_legacy_queue_addr_set(virtio_t *vio, uint16_t qidx, uint64_t descaddr,
    uint64_t availaddr __unused, uint64_t usedaddr __unused)
{
	virtio_acquireq(vio, qidx);
	virtio_put_leg32(vio, VIRTIO_LEGACY_QUEUE_ADDRESS,
	    descaddr >> VIRTIO_PAGE_SHIFT);
	virtio_releaseq(vio);
}

static uint16_t
virtio_legacy_msix_queue_get(virtio_t *vio, uint16_t qidx)
{
	uint16_t val;

	virtio_acquireq(vio, qidx);
	val = virtio_get_leg16(vio, VIRTIO_LEGACY_MSIX_QUEUE);
	virtio_releaseq(vio);

	return (val);
}

static void
virtio_legacy_msix_queue_set(virtio_t *vio, uint16_t qidx, uint16_t msi)
{
	virtio_acquireq(vio, qidx);
	virtio_put_leg16(vio, VIRTIO_LEGACY_MSIX_QUEUE, msi);
	virtio_releaseq(vio);
}

virtio_ops_t virtio_legacy_ops = {
	.vop_device_get_features = virtio_legacy_device_get_features,
	.vop_device_set_features = virtio_legacy_device_set_features,
	.vop_set_status_locked = virtio_legacy_set_status_locked,
	.vop_get_status = virtio_legacy_get_status,
	.vop_device_reset_locked = virtio_legacy_device_reset_locked,
	.vop_isr_status = virtio_legacy_isr_status,
	.vop_msix_config_get = virtio_legacy_msix_config_get,
	.vop_msix_config_set = virtio_legacy_msix_config_set,
	.vop_queue_notify = virtio_legacy_queue_notify,

	.vop_queue_select = virtio_legacy_queue_select,
	.vop_queue_size_get = virtio_legacy_queue_size_get,
	/* There is no way to set the queue size in the legacy interface */
	.vop_queue_size_set = NULL,
	/* The legacy interface doesn't use notification offsets */
	.vop_queue_noff_get = NULL,
	.vop_queue_enable_get = virtio_legacy_queue_enable_get,
	.vop_queue_enable_set = virtio_legacy_queue_enable_set,
	.vop_queue_addr_set = virtio_legacy_queue_addr_set,
	.vop_msix_queue_get = virtio_legacy_msix_queue_get,
	.vop_msix_queue_set = virtio_legacy_msix_queue_set,

	.vop_device_cfg_gen = virtio_legacy_devcfg_getgen,
	.vop_device_cfg_get8 = virtio_legacy_devcfg_get8,
	.vop_device_cfg_get16 = virtio_legacy_devcfg_get16,
	.vop_device_cfg_get32 = virtio_legacy_devcfg_get32,
	.vop_device_cfg_get64 = virtio_legacy_devcfg_get64,
	.vop_device_cfg_put8 = virtio_legacy_devcfg_put8,
	.vop_device_cfg_put16 = virtio_legacy_devcfg_put16,
	.vop_device_cfg_put32 = virtio_legacy_devcfg_put32,
};
