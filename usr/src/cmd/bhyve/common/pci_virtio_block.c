/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright 2020-2021 Joyent, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2025 Oxide Computer Company
 */


#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/sysmacros.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <md5.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "pci_emul.h"
#include "virtio.h"
#include "block_if.h"

#define	VTBLK_BSIZE	512
#define	VTBLK_RINGSZ	128

_Static_assert(VTBLK_RINGSZ <= BLOCKIF_RING_MAX, "Each ring entry must be able to queue a request");

#define	VTBLK_S_OK	0
#define	VTBLK_S_IOERR	1
#define	VTBLK_S_UNSUPP	2

#define	VTBLK_BLK_ID_BYTES	20 + 1

/* Capability bits */
#define	VTBLK_F_BARRIER		(1 << 0) /* Does host support barriers? */
#define	VTBLK_F_SIZE_MAX	(1 << 1) /* Indicates maximum segment size */
#define	VTBLK_F_SEG_MAX		(1 << 2) /* Indicates maximum # of segments */
#define	VTBLK_F_GEOMETRY	(1 << 4) /* Legacy geometry available  */
#define	VTBLK_F_RO		(1 << 5) /* Disk is read-only */
#define	VTBLK_F_BLK_SIZE	(1 << 6) /* Block size of disk is available */
#define	VTBLK_F_SCSI		(1 << 7) /* Supports scsi command passthru */
#define	VTBLK_F_FLUSH		(1 << 9) /* Writeback enabled after reset */
#define	VTBLK_F_WCE		(1 << 9) /* Legacy alias for FLUSH */
#define	VTBLK_F_TOPOLOGY	(1 << 10) /* Topology information available */
#define	VTBLK_F_CONFIG_WCE	(1 << 11) /* Writeback mode avail in config */
#define	VTBLK_F_MQ		(1 << 12) /* Multi-Queue */
#define	VTBLK_F_DISCARD		(1 << 13) /* Trim blocks */
#define	VTBLK_F_WRITE_ZEROES	(1 << 14) /* Write zeros */

/*
 * Host capabilities
 */
#define	VTBLK_S_HOSTCAPS	\
	(VTBLK_F_SEG_MAX  |						\
	VTBLK_F_BLK_SIZE |						\
	VTBLK_F_FLUSH    |						\
	VTBLK_F_TOPOLOGY |						\
	VIRTIO_RING_F_INDIRECT_DESC)	/* indirect descriptors */

/*
 * The current blockif_delete() interface only allows a single delete
 * request at a time.
 */
#define	VTBLK_MAX_DISCARD_SEG	1

/*
 * An arbitrary limit to prevent excessive latency due to large
 * delete requests.
 */
#define	VTBLK_MAX_DISCARD_SECT	((16 << 20) / VTBLK_BSIZE)	/* 16 MiB */

/*
 * Config space "registers"
 */
struct vtblk_config {
	uint64_t	vbc_capacity;
	uint32_t	vbc_size_max;
	uint32_t	vbc_seg_max;
	struct {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} vbc_geometry;
	uint32_t	vbc_blk_size;
	struct {
		uint8_t physical_block_exp;
		uint8_t alignment_offset;
		uint16_t min_io_size;
		uint32_t opt_io_size;
	} vbc_topology;
	uint8_t		vbc_writeback;
	uint8_t		unused0[1];
	uint16_t	num_queues;
	uint32_t	max_discard_sectors;
	uint32_t	max_discard_seg;
	uint32_t	discard_sector_alignment;
	uint32_t	max_write_zeroes_sectors;
	uint32_t	max_write_zeroes_seg;
	uint8_t		write_zeroes_may_unmap;
	uint8_t		unused1[3];
} __packed;

/*
 * Fixed-size block header
 */
struct virtio_blk_hdr {
#define	VBH_OP_READ		0
#define	VBH_OP_WRITE		1
#define	VBH_OP_SCSI_CMD		2
#define	VBH_OP_SCSI_CMD_OUT	3
#define	VBH_OP_FLUSH		4
#define	VBH_OP_FLUSH_OUT	5
#define	VBH_OP_IDENT		8
#define	VBH_OP_DISCARD		11
#define	VBH_OP_WRITE_ZEROES	13

#define	VBH_FLAG_BARRIER	0x80000000	/* OR'ed into vbh_type */
	uint32_t	vbh_type;
	uint32_t	vbh_ioprio;
	uint64_t	vbh_sector;
} __packed;

/*
 * Debug printf
 */
static int pci_vtblk_debug;
#define	DPRINTF(params) if (pci_vtblk_debug) PRINTLN params
#define	WPRINTF(params) PRINTLN params

struct pci_vtblk_ioreq {
	struct blockif_req		io_req;
	struct pci_vtblk_softc		*io_sc;
	uint8_t				*io_status;
	uint16_t			io_idx;
};

struct virtio_blk_discard_write_zeroes {
	uint64_t	sector;
	uint32_t	num_sectors;
	struct {
		uint32_t unmap:1;
		uint32_t reserved:31;
	} flags;
};

/*
 * Per-device softc
 */
struct pci_vtblk_softc {
	struct virtio_softc vbsc_vs;
	pthread_mutex_t vsc_mtx;
	struct vqueue_info vbsc_vq;
	struct vtblk_config vbsc_cfg;
	struct virtio_consts vbsc_consts;
	struct blockif_ctxt *bc;
#ifndef __FreeBSD__
	int vbsc_wce;
#endif
	char vbsc_ident[VTBLK_BLK_ID_BYTES];
	struct pci_vtblk_ioreq vbsc_ios[VTBLK_RINGSZ];
};

static void pci_vtblk_reset(void *);
static void pci_vtblk_notify(void *, struct vqueue_info *);
static int pci_vtblk_cfgread(void *, int, int, uint32_t *);
static int pci_vtblk_cfgwrite(void *, int, int, uint32_t);
#ifndef __FreeBSD__
static void pci_vtblk_apply_feats(void *, uint64_t *);
#endif

static virtio_capstr_t vtblk_caps[] = {
	{ VTBLK_F_BARRIER,	"VTBLK_F_BARRIER" },
	{ VTBLK_F_SIZE_MAX,	"VTBLK_F_SIZE_MAX" },
	{ VTBLK_F_SEG_MAX,	"VTBLK_F_SEG_MAX" },
	{ VTBLK_F_GEOMETRY,	"VTBLK_F_GEOMETRY" },
	{ VTBLK_F_RO,		"VTBLK_F_RO" },
	{ VTBLK_F_BLK_SIZE,	"VTBLK_F_BLK_SIZE" },
	{ VTBLK_F_SCSI,		"VTBLK_F_SCSI" },
	{ VTBLK_F_FLUSH,	"VTBLK_F_FLUSH" },
	{ VTBLK_F_WCE,		"VTBLK_F_WCE" },
	{ VTBLK_F_TOPOLOGY,	"VTBLK_F_TOPOLOGY" },
	{ VTBLK_F_CONFIG_WCE,	"VTBLK_F_CONFIG_WCE" },
	{ VTBLK_F_MQ,		"VTBLK_F_MQ" },
	{ VTBLK_F_DISCARD,	"VTBLK_F_DISCARD" },
	{ VTBLK_F_WRITE_ZEROES,	"VTBLK_F_WRITE_ZEROES" },
};

static struct virtio_consts vtblk_vi_consts = {
	.vc_name =		"vtblk",
	.vc_nvq =		1,
	.vc_cfgsize =		sizeof (struct vtblk_config),
	.vc_reset =		pci_vtblk_reset,
	.vc_qnotify =		pci_vtblk_notify,
	.vc_cfgread =		pci_vtblk_cfgread,
	.vc_cfgwrite =		pci_vtblk_cfgwrite,
#ifndef __FreeBSD__
	.vc_apply_features =	pci_vtblk_apply_feats,
#else
	.vc_apply_features =	NULL,
#endif
	.vc_hv_caps_legacy =	VTBLK_S_HOSTCAPS,
	.vc_hv_caps_modern =	VTBLK_S_HOSTCAPS,
	.vc_capstr =		vtblk_caps,
	.vc_ncapstr =		ARRAY_SIZE(vtblk_caps),
};

static void
pci_vtblk_reset(void *vsc)
{
	struct pci_vtblk_softc *sc = vsc;

	DPRINTF(("vtblk: device reset requested !"));
	vi_reset_dev(&sc->vbsc_vs);
#ifndef __FreeBSD__
	/* Disable write cache until FLUSH feature is negotiated */
	(void) blockif_set_wce(sc->bc, 0);
	sc->vbsc_wce = 0;
#endif
}

static void
pci_vtblk_done_locked(struct pci_vtblk_ioreq *io, int err)
{
	struct pci_vtblk_softc *sc = io->io_sc;

	/* convert errno into a virtio block error return */
	if (err == EOPNOTSUPP || err == ENOSYS)
		*io->io_status = VTBLK_S_UNSUPP;
	else if (err != 0)
		*io->io_status = VTBLK_S_IOERR;
	else
		*io->io_status = VTBLK_S_OK;

	/*
	 * Return the descriptor back to the host.
	 * We wrote 1 byte (our status) to host.
	 */
	vq_relchain(&sc->vbsc_vq, io->io_idx, 1);
	vq_endchains(&sc->vbsc_vq, 0);
}

static void
pci_vtblk_done(struct blockif_req *br, int err)
{
	struct pci_vtblk_ioreq *io = br->br_param;
	struct pci_vtblk_softc *sc = io->io_sc;

	pthread_mutex_lock(&sc->vsc_mtx);
	pci_vtblk_done_locked(io, err);
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_vtblk_proc(struct pci_vtblk_softc *sc, struct vqueue_info *vq)
{
	struct virtio_blk_hdr vbh;
	struct pci_vtblk_ioreq *io;
	int niov;
	int err;
	bool writeop;
	int type;
	struct vi_req req;
	struct iovec iov[BLOCKIF_IOV_MAX + 2];
	struct iovec *siov;
	iov_bunch_t iob;
	size_t len;

	niov = vq_getchain(vq, iov, BLOCKIF_IOV_MAX + 2, &req);

	/*
	 * As a transitional device we cannot make any assumptions about the
	 * descriptor layout. We know that there will always be at least two
	 * descriptors since every request contains at least one RO and one RW
	 * descriptor but it's perfectly valid (although extremely unlikely)
	 * for a driver to combine things like the last data block in a read
	 * request with the final status byte, or the first data block with
	 * the header in a write.
	 */
	if (niov < 2 || niov >= BLOCKIF_IOV_MAX + 2 ||
	    req.readable == 0 || req.writable == 0) {
		EPRINTLN("vioblk: invalid chain niov=0x%x ro=%x rw=%x",
		    niov, req.readable, req.writable);
		vq_relchain(vq, req.idx, 0);
		return;
	}

	len = iov_bunch_init(&iob, iov, niov);
	if (!iov_bunch_copy(&iob, &vbh, sizeof (vbh))) {
		EPRINTLN("vioblk: control header copy failed, chain len 0x%x",
		    len);
		vq_relchain(vq, req.idx, 0);
		return;
	}

	io = &sc->vbsc_ios[req.idx];
	io->io_req.br_offset = vbh.vbh_sector * VTBLK_BSIZE;

	/*
	 * The IO status byte is the last byte in the last descriptor which we
	 * know is writable having checked above.
	 */
	siov = &iov[niov - 1];
	io->io_status = (uint8_t *)&siov->iov_base[siov->iov_len - 1];
	iob.ib_remain--;

	/*
	 * The guest should not be setting the BARRIER flag because
	 * we don't advertise the capability.
	 */
	type = vbh.vbh_type & ~VBH_FLAG_BARRIER;
	writeop = (type == VBH_OP_WRITE || type == VBH_OP_DISCARD);

	switch (type) {
	case VBH_OP_DISCARD: {
		struct virtio_blk_discard_write_zeroes discard;

		/*
		 * We currently only support a single request, as advertised in
		 * the configuration space. If the guest has submitted a
		 * request that doesn't conform to the requirements, we return
		 * a error.
		 */
		if (!iov_bunch_copy(&iob, &discard, sizeof (discard)) ||
		    iob.ib_remain != 0) {
			EPRINTLN("vioblk: bad discard message");
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}

		/*
		 * virtio v1.1 5.2.6.2:
		 * The device MUST set the status byte to VIRTIO_BLK_S_UNSUPP
		 * for discard and write zeroes commands if any unknown flag is
		 * set. Furthermore, the device MUST set the status byte to
		 * VIRTIO_BLK_S_UNSUPP for discard commands if the unmap flag
		 * is set.
		 *
		 * Currently there are no known flags for a DISCARD request.
		 */
		if (discard.flags.unmap != 0 || discard.flags.reserved != 0) {
			pci_vtblk_done_locked(io, ENOTSUP);
			return;
		}

		/* Make sure the request doesn't exceed our size limit */
		if (discard.num_sectors > VTBLK_MAX_DISCARD_SECT) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}

		io->io_req.br_iovcnt = 0;
		io->io_req.br_offset = discard.sector * VTBLK_BSIZE;
		io->io_req.br_resid = discard.num_sectors * VTBLK_BSIZE;

		DPRINTF(("virtio-block: discard op, %zd bytes, offset %ld",
		    io->io_req.br_resid, io->io_req.br_offset));

		err = blockif_delete(sc->bc, &io->io_req);
		return;
	}
	case VBH_OP_IDENT: {
		char *buf;
		size_t len;
		int err;

		len = iob.ib_remain;
		buf = calloc(len, sizeof (char));
		if (buf == NULL) {
			pci_vtblk_done_locked(io, ENOMEM);
			return;
		}
		len = MIN(len, sizeof (sc->vbsc_ident));
		strncpy(buf, sc->vbsc_ident, len);

		DPRINTF(("virtio-block: ident op, '%.*s'", len, buf));

		err = buf_to_iov_bunch(&iob, buf, len) ? 0 : ENOSPC;

		free(buf);
		pci_vtblk_done_locked(io, err);
		return;
	}
	default:
		break;
	}

	/*
	 * Accumulate the remainder of the data into the IO request iov.
	 */
	io->io_req.br_resid = iob.ib_remain;
	iov_bunch_to_iov(&iob, (struct iovec *)&io->io_req.br_iov,
	    &io->io_req.br_iovcnt, ARRAY_SIZE(io->io_req.br_iov));

	DPRINTF(("virtio-block: %s op, %zd bytes, %d segs, offset %ld",
	    writeop ? "write" : "read",
	    io->io_req.br_resid, io->io_req.br_iovcnt, io->io_req.br_offset));

	switch (type) {
	case VBH_OP_READ:
		err = blockif_read(sc->bc, &io->io_req);
		break;
	case VBH_OP_WRITE:
		err = blockif_write(sc->bc, &io->io_req);
		break;
	case VBH_OP_FLUSH:
	case VBH_OP_FLUSH_OUT:
		err = blockif_flush(sc->bc, &io->io_req);
		break;
	default:
		pci_vtblk_done_locked(io, EOPNOTSUPP);
		return;
	}
	assert(err == 0);
}

static void
pci_vtblk_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtblk_softc *sc = vsc;

	while (vq_has_descs(vq))
		pci_vtblk_proc(sc, vq);
}

static void
pci_vtblk_resized(struct blockif_ctxt *bctxt __unused, void *arg,
    size_t new_size)
{
	struct pci_vtblk_softc *sc;

	sc = arg;

	sc->vbsc_cfg.vbc_capacity = new_size / VTBLK_BSIZE; /* 512-byte units */
	vq_devcfg_changed(&sc->vbsc_vs);
}

static int
pci_vtblk_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	char bident[sizeof ("XXX:XXX")];
	struct blockif_ctxt *bctxt;
	const char *path, *serial;
	MD5_CTX mdctx;
	uchar_t digest[16];
	struct pci_vtblk_softc *sc;
	off_t size;
	int i, sectsz, sts, sto;

	/*
	 * The supplied backing file has to exist
	 */
	snprintf(bident, sizeof (bident), "%u:%u", pi->pi_slot, pi->pi_func);
	bctxt = blockif_open(nvl, bident);
	if (bctxt == NULL) {
		perror("Could not open backing file");
		return (1);
	}

	if (blockif_add_boot_device(pi, bctxt)) {
		perror("Invalid boot device");
		return (1);
	}

	size = blockif_size(bctxt);
	sectsz = blockif_sectsz(bctxt);
	blockif_psectsz(bctxt, &sts, &sto);

	sc = calloc(1, sizeof (struct pci_vtblk_softc));
	sc->bc = bctxt;

	if (get_config_bool_default("virtio.blk.debug", false))
		pci_vtblk_debug = 1;
	vi_set_debug(&sc->vbsc_vs, pci_vtblk_debug);

	for (i = 0; i < VTBLK_RINGSZ; i++) {
		struct pci_vtblk_ioreq *io = &sc->vbsc_ios[i];
		io->io_req.br_callback = pci_vtblk_done;
		io->io_req.br_param = io;
		io->io_sc = sc;
		io->io_idx = i;
	}

	bcopy(&vtblk_vi_consts, &sc->vbsc_consts, sizeof (vtblk_vi_consts));
	if (blockif_candelete(sc->bc)) {
		sc->vbsc_consts.vc_hv_caps_legacy |= VTBLK_F_DISCARD;
		sc->vbsc_consts.vc_hv_caps_modern |= VTBLK_F_DISCARD;
	}

#ifndef __FreeBSD__
	/* Disable write cache until FLUSH feature is negotiated */
	(void) blockif_set_wce(sc->bc, 0);
	sc->vbsc_wce = 0;
#endif

	pthread_mutex_init(&sc->vsc_mtx, NULL);

	/* init virtio softc and virtqueues */
	vi_softc_linkup(&sc->vbsc_vs, &sc->vbsc_consts, sc, pi, &sc->vbsc_vq);
	sc->vbsc_vs.vs_mtx = &sc->vsc_mtx;

	sc->vbsc_vq.vq_qsize = VTBLK_RINGSZ;
	/* sc->vbsc_vq.vq_notify = we have no per-queue notify */

	/*
	 * If an explicit identifier is not given, create an
	 * identifier using parts of the md5 sum of the filename.
	 */
	bzero(sc->vbsc_ident, VTBLK_BLK_ID_BYTES);
	if ((serial = get_config_value_node(nvl, "serial")) != NULL ||
	    (serial = get_config_value_node(nvl, "ser")) != NULL) {
		strlcpy(sc->vbsc_ident, serial, VTBLK_BLK_ID_BYTES);
	} else {
		path = get_config_value_node(nvl, "path");
		MD5Init(&mdctx);
		MD5Update(&mdctx, path, strlen(path));
		MD5Final(digest, &mdctx);
		snprintf(sc->vbsc_ident, VTBLK_BLK_ID_BYTES,
		    "BHYVE-%02X%02X-%02X%02X-%02X%02X",
		    digest[0], digest[1], digest[2], digest[3], digest[4],
		    digest[5]);
	}

	/* setup virtio block config space */
	sc->vbsc_cfg.vbc_capacity = size / VTBLK_BSIZE; /* 512-byte units */
	sc->vbsc_cfg.vbc_size_max = 0;	/* not negotiated */

	/*
	 * If Linux is presented with a seg_max greater than the virtio queue
	 * size, it can stumble into situations where it violates its own
	 * invariants and panics.  For safety, we keep seg_max clamped, paying
	 * heed to the two extra descriptors needed for the header and status
	 * of a request.
	 */
	sc->vbsc_cfg.vbc_seg_max = MIN(VTBLK_RINGSZ - 2, BLOCKIF_IOV_MAX);
	sc->vbsc_cfg.vbc_geometry.cylinders = 0;	/* no geometry */
	sc->vbsc_cfg.vbc_geometry.heads = 0;
	sc->vbsc_cfg.vbc_geometry.sectors = 0;
	sc->vbsc_cfg.vbc_blk_size = sectsz;
	sc->vbsc_cfg.vbc_topology.physical_block_exp =
	    (sts > sectsz) ? (ffsll(sts / sectsz) - 1) : 0;
	sc->vbsc_cfg.vbc_topology.alignment_offset =
	    (sto != 0) ? ((sts - sto) / sectsz) : 0;
	sc->vbsc_cfg.vbc_topology.min_io_size = 0;
	sc->vbsc_cfg.vbc_topology.opt_io_size = 0;
	sc->vbsc_cfg.vbc_writeback = 0;
	sc->vbsc_cfg.max_discard_sectors = VTBLK_MAX_DISCARD_SECT;
	sc->vbsc_cfg.max_discard_seg = VTBLK_MAX_DISCARD_SEG;
	sc->vbsc_cfg.discard_sector_alignment = MAX(sectsz, sts) / VTBLK_BSIZE;

	vi_pci_init(pi, VIRTIO_MODE_TRANSITIONAL, VIRTIO_DEV_BLOCK,
	    VIRTIO_ID_BLOCK, PCIC_STORAGE);

	if (!vi_intr_init(&sc->vbsc_vs, true, fbsdrun_virtio_msix()))
		goto fail;
	if (!vi_pcibar_setup(&sc->vbsc_vs))
		goto fail;

	blockif_register_resize_callback(sc->bc, pci_vtblk_resized, sc);
	return (0);

fail:
	blockif_close(sc->bc);
	free(sc);
	return (1);
}

static int
pci_vtblk_cfgwrite(void *vsc __unused, int offset, int size __unused,
    uint32_t value __unused)
{

	DPRINTF(("vtblk: write to readonly reg %d", offset));
	return (1);
}

static int
pci_vtblk_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtblk_softc *sc = vsc;
	void *ptr;

	/* our caller has already verified offset and size */
	ptr = (uint8_t *)&sc->vbsc_cfg + offset;
	memcpy(retval, ptr, size);
	return (0);
}

#ifndef __FreeBSD__
void
pci_vtblk_apply_feats(void *vsc, uint64_t *caps)
{
	struct pci_vtblk_softc *sc = vsc;
	const int wce_next = ((*caps & VTBLK_F_FLUSH) != 0) ? 1 : 0;

	if (sc->vbsc_wce != wce_next) {
		(void) blockif_set_wce(sc->bc, wce_next);
		sc->vbsc_wce = wce_next;
	}
}
#endif /* __FreeBSD__ */

static const struct pci_devemu pci_de_vblk = {
	.pe_emu =	"virtio-blk",
	.pe_init =	pci_vtblk_init,
	.pe_legacy_config = blockif_legacy_config,
	.pe_cfgwrite =	vi_pci_cfgwrite,
	.pe_cfgread =	vi_pci_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
};
PCI_EMUL_SET(pci_de_vblk);
