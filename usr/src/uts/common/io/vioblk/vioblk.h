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
 */

/*
 * VIRTIO BLOCK DRIVER
 */

#ifndef _VIOBLK_H
#define	_VIOBLK_H

#include "virtio.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * VIRTIO BLOCK CONFIGURATION REGISTERS
 *
 * These are offsets into the device-specific configuration space available
 * through the virtio_dev_*() family of functions.
 */
#define	VIRTIO_BLK_CONFIG_CAPACITY	0x00	/* 64 R   */
#define	VIRTIO_BLK_CONFIG_SIZE_MAX	0x08	/* 32 R   */
#define	VIRTIO_BLK_CONFIG_SEG_MAX	0x0C	/* 32 R   */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_C	0x10	/* 16 R   */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_H	0x12	/*  8 R   */
#define	VIRTIO_BLK_CONFIG_GEOMETRY_S	0x13	/*  8 R   */
#define	VIRTIO_BLK_CONFIG_BLK_SIZE	0x14	/* 32 R   */
#define	VIRTIO_BLK_CONFIG_TOPO_PBEXP	0x18	/*  8 R   */
#define	VIRTIO_BLK_CONFIG_TOPO_ALIGN	0x19	/*  8 R   */
#define	VIRTIO_BLK_CONFIG_TOPO_MIN_SZ	0x1A	/* 16 R   */
#define	VIRTIO_BLK_CONFIG_TOPO_OPT_SZ	0x1C	/* 32 R   */

/*
 * VIRTIO BLOCK VIRTQUEUES
 *
 * Virtio block devices have just one queue which is used to make the various
 * supported I/O requests.
 */
#define	VIRTIO_BLK_VIRTQ_IO		0

/*
 * VIRTIO BLOCK FEATURE BITS
 */
#define	VIRTIO_BLK_F_BARRIER		(1ULL << 0)
#define	VIRTIO_BLK_F_SIZE_MAX		(1ULL << 1)
#define	VIRTIO_BLK_F_SEG_MAX		(1ULL << 2)
#define	VIRTIO_BLK_F_GEOMETRY		(1ULL << 4)
#define	VIRTIO_BLK_F_RO			(1ULL << 5)
#define	VIRTIO_BLK_F_BLK_SIZE		(1ULL << 6)
#define	VIRTIO_BLK_F_SCSI		(1ULL << 7)
#define	VIRTIO_BLK_F_FLUSH		(1ULL << 9)
#define	VIRTIO_BLK_F_TOPOLOGY		(1ULL << 10)

/*
 * These features are supported by the driver and we will request them from the
 * device.
 */
#define	VIRTIO_BLK_WANTED_FEATURES	(VIRTIO_BLK_F_RO |		\
					VIRTIO_BLK_F_BLK_SIZE |		\
					VIRTIO_BLK_F_FLUSH |		\
					VIRTIO_BLK_F_TOPOLOGY |		\
					VIRTIO_BLK_F_SEG_MAX |		\
					VIRTIO_BLK_F_SIZE_MAX)

/*
 * VIRTIO BLOCK REQUEST HEADER
 *
 * This structure appears at the start of each I/O request buffer.  Note that
 * neither the data payload nor the status byte appear in this structure as
 * both are handled in separate descriptor entries.
 */
struct vioblk_req_hdr {
	uint32_t			vbh_type;
	uint32_t			vbh_ioprio;
	uint64_t			vbh_sector;
} __packed;

/*
 * VIRTIO BLOCK REQUEST HEADER: COMMANDS (vbh_type)
 *
 * Each of these is a command type, except for BARRIER which is logically
 * OR-ed with one of the other types.
 */
#define	VIRTIO_BLK_T_IN			0
#define	VIRTIO_BLK_T_OUT		1
#define	VIRTIO_BLK_T_SCSI_CMD		2
#define	VIRTIO_BLK_T_SCSI_CMD_OUT	3
#define	VIRTIO_BLK_T_FLUSH		4
#define	VIRTIO_BLK_T_FLUSH_OUT		5
#define	VIRTIO_BLK_T_GET_ID		8
#define	VIRTIO_BLK_T_BARRIER		0x80000000

/*
 * The GET_ID command type does not appear in the specification, but
 * implementations in the wild use a 20 byte buffer into which the device will
 * write an ASCII string.  The string should not be assumed to be
 * NUL-terminated.
 */
#define	VIRTIO_BLK_ID_BYTES		20

/*
 * VIRTIO BLOCK REQUEST HEADER: STATUS CODES
 *
 * These are returned in the writeable status byte descriptor included at the
 * end of each request passed to the device.
 */
#define	VIRTIO_BLK_S_OK			0
#define	VIRTIO_BLK_S_IOERR		1
#define	VIRTIO_BLK_S_UNSUPP		2

/*
 * DRIVER PARAMETERS
 */

/*
 * In the event that the device does not negotiate DMA parameters, we have to
 * make a best guess.
 */
#define	VIRTIO_BLK_DEFAULT_MAX_SEG	128
#define	VIRTIO_BLK_DEFAULT_MAX_SIZE	4096

/*
 * We allocate a fixed number of request buffers in advance and place them in a
 * per-instance free list.
 */
#define	VIRTIO_BLK_REQ_BUFS		256

/*
 * TYPE DEFINITIONS
 */

typedef enum vioblk_req_status {
	VIOBLK_REQSTAT_ALLOCATED =	(0x1 << 0),
	VIOBLK_REQSTAT_INFLIGHT =	(0x1 << 1),
	VIOBLK_REQSTAT_COMPLETE =	(0x1 << 2),
	VIOBLK_REQSTAT_POLLED =		(0x1 << 3),
	VIOBLK_REQSTAT_POLL_COMPLETE =	(0x1 << 4),
} vioblk_req_status_t;

typedef struct vioblk_req {
	vioblk_req_status_t		vbr_status;
	uint64_t			vbr_seqno;
	int				vbr_type;
	int				vbr_error;
	virtio_dma_t			*vbr_dma;
	bd_xfer_t			*vbr_xfer;
	list_node_t			vbr_link;
} vioblk_req_t;

typedef struct vioblk_stats {
	struct kstat_named		vbs_rw_outofmemory;
	struct kstat_named		vbs_rw_badoffset;
	struct kstat_named		vbs_rw_queuemax;
	struct kstat_named		vbs_rw_cookiesmax;
	struct kstat_named		vbs_rw_cacheflush;
	struct kstat_named		vbs_intr_queuemax;
	struct kstat_named		vbs_intr_total;
	struct kstat_named		vbs_io_errors;
	struct kstat_named		vbs_unsupp_errors;
	struct kstat_named		vbs_nxio_errors;
} vioblk_stats_t;

typedef struct vioblk {
	dev_info_t			*vib_dip;
	virtio_t			*vib_virtio;
	virtio_queue_t			*vib_vq;

	kmutex_t			vib_mutex;
	kcondvar_t			vib_cv;

	bd_handle_t			vib_bd_h;
	ddi_dma_attr_t			vib_bd_dma_attr;

	list_t				vib_reqs;
	uint_t				vib_nreqs_alloc;
	uint_t				vib_reqs_capacity;
	vioblk_req_t			*vib_reqs_mem;

	kstat_t				*vib_kstat;
	vioblk_stats_t			*vib_stats;

	uint64_t			vib_nblks;
	boolean_t			vib_readonly;
	uint_t				vib_blk_size;
	uint_t				vib_pblk_size;
	uint_t				vib_seg_max;
	uint_t				vib_seg_size_max;

	boolean_t			vib_devid_fetched;
	char				vib_devid[VIRTIO_BLK_ID_BYTES + 1];
	uint8_t				vib_rawid[VIRTIO_BLK_ID_BYTES];
} vioblk_t;

#ifdef __cplusplus
}
#endif

#endif /* _VIOBLK_H */
