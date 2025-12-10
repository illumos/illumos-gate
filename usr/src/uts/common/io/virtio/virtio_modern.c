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
 * VIRTIO FRAMEWORK: Operations via the modern interface.
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
#include "virtio_endian.h"

static void virtio_modern_set_status_locked(virtio_t *, uint8_t);
static uint8_t virtio_modern_get_status(virtio_t *);

/*
 * Reads and writes to the modern common configuration area.
 */

static inline uint8_t
virtio_get_cmn8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_cap_common.vpc_barh,
	    (uint8_t *)(vio->vio_cap_common.vpc_bar + offset)));
}

static inline uint16_t
virtio_get_cmn16(virtio_t *vio, uintptr_t offset)
{
	return virtio_le16toh((ddi_get16(vio->vio_cap_common.vpc_barh,
	    (uint16_t *)(vio->vio_cap_common.vpc_bar + offset))));
}

static inline uint32_t
virtio_get_cmn32(virtio_t *vio, uintptr_t offset)
{
	return virtio_le32toh((ddi_get32(vio->vio_cap_common.vpc_barh,
	    (uint32_t *)(vio->vio_cap_common.vpc_bar + offset))));
}

static inline void
virtio_put_cmn8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	ddi_put8(vio->vio_cap_common.vpc_barh,
	    (uint8_t *)(vio->vio_cap_common.vpc_bar + offset), value);
}

static inline void
virtio_put_cmn16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_cap_common.vpc_barh,
	    (uint16_t *)(vio->vio_cap_common.vpc_bar + offset),
	    virtio_htole16(value));
}

static inline void
virtio_put_cmn32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_cap_common.vpc_barh,
	    (uint32_t *)(vio->vio_cap_common.vpc_bar + offset),
	    virtio_htole32(value));
}

/*
 * Reads and writes to the modern device configuration area.
 */

static uint8_t
virtio_modern_devcfg_getgen(virtio_t *vio)
{
	return (virtio_get_cmn8(vio, VIRTIO_MODERN_COMMON_CFGGENERATION));
}

static uint8_t
virtio_modern_devcfg_get8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_cap_device.vpc_barh,
	    (uint8_t *)(vio->vio_cap_device.vpc_bar + offset)));
}

static uint16_t
virtio_modern_devcfg_get16(virtio_t *vio, uintptr_t offset)
{
	return (virtio_le16toh(ddi_get16(vio->vio_cap_device.vpc_barh,
	    (uint16_t *)(vio->vio_cap_device.vpc_bar + offset))));
}

static uint32_t
virtio_modern_devcfg_get32(virtio_t *vio, uintptr_t offset)
{
	return (virtio_le32toh(ddi_get32(vio->vio_cap_device.vpc_barh,
	    (uint32_t *)(vio->vio_cap_device.vpc_bar + offset))));
}

static uint64_t
virtio_modern_devcfg_get64(virtio_t *vio, uintptr_t offset)
{
	uint64_t val;
	uint8_t gen;

	/*
	 * On at least some systems, a 64-bit read or write to this BAR is not
	 * possible. Modern devices have a generation number that can be
	 * inspected to determine if configuration may have changed half-way
	 * through a read. We need to continue to read both halves of the
	 * value until we read the same generation value either side.
	 */
	do {
		gen = virtio_modern_devcfg_getgen(vio);
		val = (uint64_t)virtio_le32toh(virtio_modern_devcfg_get32(vio,
		    offset + sizeof (uint32_t))) << 32;
		val |= virtio_le32toh(virtio_modern_devcfg_get32(vio, offset));
	} while (virtio_modern_devcfg_getgen(vio) != gen);

	return (val);
}

static void
virtio_modern_devcfg_put8(virtio_t *vio, uintptr_t offset, uint8_t value)
{
	ddi_put8(vio->vio_cap_device.vpc_barh,
	    (uint8_t *)(vio->vio_cap_device.vpc_bar + offset), value);
}

static void
virtio_modern_devcfg_put16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_cap_device.vpc_barh,
	    (uint16_t *)(vio->vio_cap_device.vpc_bar + offset),
	    virtio_htole16(value));
}

static void
virtio_modern_devcfg_put32(virtio_t *vio, uintptr_t offset, uint32_t value)
{
	ddi_put32(vio->vio_cap_device.vpc_barh,
	    (uint32_t *)(vio->vio_cap_device.vpc_bar + offset),
	    virtio_htole32(value));
}

/*
 * Reads and writes to the modern notification area.
 */

static inline void
virtio_put_nfy16(virtio_t *vio, uintptr_t offset, uint16_t value)
{
	ddi_put16(vio->vio_cap_notify.vpc_barh,
	    (uint16_t *)(vio->vio_cap_notify.vpc_bar + offset),
	    virtio_htole16(value));
}

/*
 * Reads from the modern ISR area.
 */

static inline uint8_t
virtio_get_isr8(virtio_t *vio, uintptr_t offset)
{
	return (ddi_get8(vio->vio_cap_isr.vpc_barh,
	    (uint8_t *)(vio->vio_cap_isr.vpc_bar + offset)));
}

static uint64_t
virtio_modern_device_get_features(virtio_t *vio)
{
	uint64_t features = 0;

	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_DFSELECT, 1);
	features = virtio_get_cmn32(vio, VIRTIO_MODERN_COMMON_DF);
	features <<= 32;
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_DFSELECT, 0);
	features |= virtio_get_cmn32(vio, VIRTIO_MODERN_COMMON_DF);

	return (features);
}

static bool
virtio_modern_device_set_features(virtio_t *vio, uint64_t features)
{
	uint8_t status;

	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_GFSELECT, 1);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_GF, features >> 32);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_GFSELECT, 0);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_GF, features & 0xffffffff);
	/* Signal that we are finished setting guest features */
	mutex_enter(&vio->vio_mutex);
	virtio_modern_set_status_locked(vio, VIRTIO_STATUS_FEAT_OK);
	/*
	 * We now need to check that this bit is still set in the status. If
	 * it is not, then feature negotiation has failed and the device is
	 * unusable.
	 */
	status = virtio_modern_get_status(vio);
	mutex_exit(&vio->vio_mutex);
	return ((status & VIRTIO_STATUS_FEAT_OK) != 0);
}

static void
virtio_modern_set_status_locked(virtio_t *vio, uint8_t status)
{
	VERIFY3U(status, !=, 0);
	VERIFY(MUTEX_HELD(&vio->vio_mutex));

	uint8_t old = virtio_get_cmn8(vio, VIRTIO_MODERN_COMMON_STATUS);
	virtio_put_cmn8(vio, VIRTIO_MODERN_COMMON_STATUS, status | old);
}

static uint8_t
virtio_modern_get_status(virtio_t *vio)
{
	return (virtio_get_cmn8(vio, VIRTIO_MODERN_COMMON_STATUS));
}

static void
virtio_modern_device_reset_locked(virtio_t *vio)
{
	VERIFY(MUTEX_HELD(&vio->vio_mutex));
	virtio_put_cmn8(vio, VIRTIO_MODERN_COMMON_STATUS, VIRTIO_STATUS_RESET);
}

static uint8_t
virtio_modern_isr_status(virtio_t *vio)
{
	return (virtio_get_isr8(vio, 0));
}

static uint16_t
virtio_modern_msix_config_get(virtio_t *vio)
{
	return (virtio_get_cmn16(vio, VIRTIO_MODERN_COMMON_MSIX));
}

static void
virtio_modern_msix_config_set(virtio_t *vio, uint16_t msi)
{
	virtio_put_cmn16(vio, VIRTIO_MODERN_COMMON_MSIX, msi);
}

static void
virtio_modern_queue_notify(virtio_queue_t *viq)
{
	virtio_put_nfy16(viq->viq_virtio, viq->viq_noff, viq->viq_index);
}

static void
virtio_modern_queue_select(virtio_t *vio, uint16_t qidx)
{
	virtio_put_cmn16(vio, VIRTIO_MODERN_COMMON_Q_SELECT, qidx);
}

static uint16_t
virtio_modern_queue_size_get(virtio_t *vio, uint16_t qidx)
{
	uint16_t val;

	virtio_acquireq(vio, qidx);
	val = virtio_get_cmn16(vio, VIRTIO_MODERN_COMMON_Q_SIZE);
	virtio_releaseq(vio);

	return (val);
}

static void
virtio_modern_queue_size_set(virtio_t *vio, uint16_t qidx, uint16_t qsz)
{
	virtio_acquireq(vio, qidx);
	virtio_put_cmn16(vio, VIRTIO_MODERN_COMMON_Q_SIZE, qsz);
	virtio_releaseq(vio);
}

static uint64_t
virtio_modern_queue_noff_get(virtio_t *vio, uint16_t qidx)
{
	uint64_t noff;

	virtio_acquireq(vio, qidx);
	noff = (uint64_t)virtio_get_cmn16(vio, VIRTIO_MODERN_COMMON_Q_NOFF);
	virtio_releaseq(vio);

	noff *= vio->vio_multiplier;

	return (noff);
}

static bool
virtio_modern_queue_enable_get(virtio_t *vio, uint16_t qidx)
{
	bool val;

	virtio_acquireq(vio, qidx);
	val = (virtio_get_cmn16(vio, VIRTIO_MODERN_COMMON_Q_ENABLE) != 0);
	virtio_releaseq(vio);

	return (val);
}

static void
virtio_modern_queue_enable_set(virtio_t *vio, uint16_t qidx, bool enable)
{
	virtio_acquireq(vio, qidx);
	virtio_put_cmn16(vio, VIRTIO_MODERN_COMMON_Q_ENABLE, enable);
	virtio_releaseq(vio);
}

static void
virtio_modern_queue_addr_set(virtio_t *vio, uint16_t qidx, uint64_t descaddr,
    uint64_t availaddr, uint64_t usedaddr)
{
	virtio_acquireq(vio, qidx);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_DESCLO,
	    descaddr & 0xffffffff);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_DESCHI,
	    descaddr >> 32);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_AVAILLO,
	    availaddr & 0xffffffff);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_AVAILHI,
	    availaddr >> 32);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_USEDLO,
	    usedaddr & 0xffffffff);
	virtio_put_cmn32(vio, VIRTIO_MODERN_COMMON_Q_USEDHI,
	    usedaddr >> 32);
	virtio_releaseq(vio);
}

static uint16_t
virtio_modern_msix_queue_get(virtio_t *vio, uint16_t qidx)
{
	uint16_t val;

	virtio_acquireq(vio, qidx);
	val = virtio_get_cmn16(vio, VIRTIO_MODERN_COMMON_Q_MSIX);
	virtio_releaseq(vio);

	return (val);
}

static void
virtio_modern_msix_queue_set(virtio_t *vio, uint16_t qidx, uint16_t msi)
{
	virtio_acquireq(vio, qidx);
	virtio_put_cmn16(vio, VIRTIO_MODERN_COMMON_Q_MSIX, msi);
	virtio_releaseq(vio);
}

virtio_ops_t virtio_modern_ops = {
	.vop_device_get_features = virtio_modern_device_get_features,
	.vop_device_set_features = virtio_modern_device_set_features,
	.vop_set_status_locked = virtio_modern_set_status_locked,
	.vop_get_status = virtio_modern_get_status,
	.vop_device_reset_locked = virtio_modern_device_reset_locked,
	.vop_isr_status = virtio_modern_isr_status,
	.vop_msix_config_get = virtio_modern_msix_config_get,
	.vop_msix_config_set = virtio_modern_msix_config_set,
	.vop_queue_notify = virtio_modern_queue_notify,

	.vop_queue_select = virtio_modern_queue_select,
	.vop_queue_size_get = virtio_modern_queue_size_get,
	.vop_queue_size_set = virtio_modern_queue_size_set,
	.vop_queue_noff_get = virtio_modern_queue_noff_get,
	.vop_queue_enable_get = virtio_modern_queue_enable_get,
	.vop_queue_enable_set = virtio_modern_queue_enable_set,
	.vop_queue_addr_set = virtio_modern_queue_addr_set,
	.vop_msix_queue_get = virtio_modern_msix_queue_get,
	.vop_msix_queue_set = virtio_modern_msix_queue_set,

	.vop_device_cfg_gen = virtio_modern_devcfg_getgen,
	.vop_device_cfg_get8 = virtio_modern_devcfg_get8,
	.vop_device_cfg_get16 = virtio_modern_devcfg_get16,
	.vop_device_cfg_get32 = virtio_modern_devcfg_get32,
	.vop_device_cfg_get64 = virtio_modern_devcfg_get64,
	.vop_device_cfg_put8 = virtio_modern_devcfg_put8,
	.vop_device_cfg_put16 = virtio_modern_devcfg_put16,
	.vop_device_cfg_put32 = virtio_modern_devcfg_put32,
};
