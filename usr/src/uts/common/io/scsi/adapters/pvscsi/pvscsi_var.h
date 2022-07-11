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
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2022 RackTop Systems, Inc.
 */

#ifndef	_PVSCSI_VAR_H_
#define	_PVSCSI_VAR_H_

typedef struct pvscsi_dma_buf {
	ddi_dma_handle_t dmah;
	caddr_t		addr;
	uint64_t	pa;
	ddi_acc_handle_t acch;
} pvscsi_dma_buf_t;

#define	PVSCSI_MAX_IO_PAGES	256
#define	PVSCSI_MAX_IO_SIZE	(PVSCSI_MAX_IO_PAGES * PAGE_SIZE)
#define	PVSCSI_MAX_SG_SIZE	(PVSCSI_MAX_IO_PAGES + 1)

typedef struct pvscsi_cmd {
	struct scsi_pkt		*pkt;
	struct scsi_arq_status	cmd_scb;
	uint8_t			cdb[SCSI_CDB_SIZE];
	size_t			cdblen;
	uint8_t			tag;
	uint8_t			scsi_status;
	uint32_t		host_status;
	uint64_t		transferred;
	boolean_t		poll;
	int			target;
	int			lun;
	uint32_t		ctx;
	list_node_t		queue_node;
	clock_t			timeout;
	clock_t			start;
	struct pvscsi_softc	*pvs;
	struct pvscsi_cmd	*next_cmd;

	ddi_dma_handle_t	sgl_dmah;
	ddi_acc_handle_t	sgl_acch;
	uint64_t		sgl_pa;
	struct PVSCSISGElement	*sgl;

	uint64_t		arq_pa;
	uint8_t			arq_sense[SENSE_LENGTH];
	ddi_dma_handle_t	arq_dmah;

	uint32_t		dma_dir;

	uint8_t			done;
	uint8_t			expired;
} pvscsi_cmd_t;

typedef struct pvscsi_msg {
	struct pvscsi_softc	*pvs;
	int			type;
	int			target;
	int			lun;
} pvscsi_msg_t;

typedef struct pvscsi_device {
	list_node_t		node;
	struct pvscsi_softc	*pvs;
	int			target;
	int			lun;
} pvscsi_device_t;

typedef struct pvscsi_softc {
	dev_info_t		*dip;
	scsi_hba_tran_t		*tran;
	scsi_hba_tgtmap_t	*tgtmap;
	pvscsi_dma_buf_t	state_buf;
	pvscsi_dma_buf_t	req_ring_buf;
	uint_t			req_pages;
	uint_t			req_depth;
	pvscsi_dma_buf_t	cmp_ring_buf;
	uint_t			cmp_pages;
	pvscsi_dma_buf_t	msg_ring_buf;
	uint_t			msg_pages;
	ddi_acc_handle_t	mmio_handle;
	caddr_t			mmio_base;
	int			intr_cnt;
	int			intr_pri;
	int			intr_type;
	uint32_t		max_targets;
	ddi_intr_handle_t	intr_handles[PVSCSI_MAX_INTRS];
	list_t			cmd_queue;
	list_t			devices;
	kmutex_t		lock;
	ddi_taskq_t		*tq;
	timeout_id_t		timeout;
	boolean_t		detach;
} pvscsi_softc_t;

#define	REQ_RING(pvs) \
	((struct PVSCSIRingReqDesc *)((pvs)->req_ring_buf.addr))

#define	CMP_RING(pvs) \
	((struct PVSCSIRingCmpDesc *)((pvs)->cmp_ring_buf.addr))

#define	MSG_RING(pvs) \
	((struct PVSCSIRingMsgDesc *)((pvs)->msg_ring_buf.addr))

#define	RINGS_STATE(pvs) \
	((struct PVSCSIRingsState *)((pvs)->state_buf.addr))

#define	PVSCSI_MAXTGTS	16

#define	PAGE_SIZE	4096
#define	PAGE_SHIFT	12

#define	PVSCSI_DEFAULT_NUM_PAGES_PER_RING	8
#define	PVSCSI_DEFAULT_NUM_PAGES_MSG_RING	1

#endif	/* _PVSCSI_VAR_H_ */
