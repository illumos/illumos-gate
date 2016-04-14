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
 */

#ifndef	_PVSCSI_VAR_H_
#define	_PVSCSI_VAR_H_

typedef struct pvscsi_dma_buf {
	ddi_dma_handle_t dma_handle;
	caddr_t		addr;
	uint64_t	pa;
	size_t		real_length;
	ddi_acc_handle_t acc_handle;
} pvscsi_dma_buf_t;

#define	PVSCSI_TGT_PRIV_SIZE	2

#define	PVSCSI_FLAG_CDB_EXT	0x0001
#define	PVSCSI_FLAG_SCB_EXT	0x0002
#define	PVSCSI_FLAG_PRIV_EXT	0x0004
#define	PVSCSI_FLAG_TAG		0x0008
#define	PVSCSI_FLAG_IO_READ	0x0010
#define	PVSCSI_FLAG_IO_IOPB	0x0040
#define	PVSCSI_FLAG_DONE	0x0080
#define	PVSCSI_FLAG_DMA_VALID	0x0100
#define	PVSCSI_FLAG_XARQ	0x0200
#define	PVSCSI_FLAG_HW_STATUS	0x0400
#define	PVSCSI_FLAG_TIMED_OUT	0x0800
#define	PVSCSI_FLAG_ABORTED	0x1000
#define	PVSCSI_FLAG_RESET_BUS	0x2000
#define	PVSCSI_FLAG_RESET_DEV	0x4000
#define	PVSCSI_FLAG_TRANSPORT	0x8000

/* Flags that must remain during SCSI packet retransmission */
#define	PVSCSI_FLAGS_PERSISTENT	\
	(PVSCSI_FLAG_CDB_EXT	|\
	PVSCSI_FLAG_SCB_EXT	|\
	PVSCSI_FLAG_PRIV_EXT	|\
	PVSCSI_FLAG_TAG		|\
	PVSCSI_FLAG_IO_READ	|\
	PVSCSI_FLAG_IO_IOPB	|\
	PVSCSI_FLAG_DMA_VALID	|\
	PVSCSI_FLAG_XARQ)

#define	PVSCSI_FLAGS_RESET	\
	(PVSCSI_FLAG_RESET_BUS	|\
	PVSCSI_FLAG_RESET_DEV)

#define	PVSCSI_FLAGS_NON_HW_COMPLETION \
	(PVSCSI_FLAG_TIMED_OUT	|\
	PVSCSI_FLAG_ABORTED	|\
	PVSCSI_FLAGS_RESET)

#define	PVSCSI_FLAGS_COMPLETION	\
	(PVSCSI_FLAG_HW_STATUS	|\
	PVSCSI_FLAGS_NON_HW_COMPLETION)

#define	PVSCSI_FLAGS_EXT	\
	(PVSCSI_FLAG_CDB_EXT	|\
	PVSCSI_FLAG_SCB_EXT	|\
	PVSCSI_FLAG_PRIV_EXT)

typedef struct pvscsi_cmd_ctx {
	pvscsi_dma_buf_t	dma_buf;
	struct pvscsi_cmd *cmd;
	list_node_t	list;
} pvscsi_cmd_ctx_t;

typedef struct pvscsi_cmp_desc_stat {
	uchar_t		scsi_status;
	uint32_t	host_status;
	uint64_t	data_len;
} pvscsi_cmp_desc_stat_t;

#define	PVSCSI_MAX_IO_PAGES	256
#define	PVSCSI_MAX_IO_SIZE	(PVSCSI_MAX_IO_PAGES * PAGE_SIZE)
#define	PVSCSI_MAX_SG_SIZE	(PVSCSI_MAX_IO_PAGES + 1)

typedef struct pvscsi_cmd {
	struct scsi_pkt	*pkt;
	uint8_t		cmd_cdb[SCSI_CDB_SIZE];
	struct scsi_arq_status cmd_scb;
	uint64_t	tgt_priv[PVSCSI_TGT_PRIV_SIZE];
	size_t		tgtlen;
	size_t		cmdlen;
	size_t		statuslen;
	uint8_t		tag;
	int		flags;
	ulong_t		dma_count;
	pvscsi_cmp_desc_stat_t cmp_stat;
	pvscsi_cmd_ctx_t *ctx;
	ddi_dma_handle_t cmd_dmahdl;
	ddi_dma_cookie_t cmd_dmac;
	uint_t		cmd_dmaccount;
	uint_t		cmd_winindex;
	uint_t		cmd_nwin;
	off_t		cmd_dma_offset;
	size_t		cmd_dma_len;
	uint_t		cmd_dma_count;
	uint_t		cmd_total_dma_count;
	int		cmd_target;
	list_node_t	cmd_queue_node;
	clock_t		timeout_lbolt;
	struct pvscsi_softc *cmd_pvs;
	struct pvscsi_cmd *next_cmd;
	struct pvscsi_cmd *tail_cmd;
	struct buf	*arqbuf;
	ddi_dma_cookie_t arqc;
	ddi_dma_handle_t arqhdl;
	int		cmd_rqslen;
	struct scsi_pkt	cached_pkt;
	ddi_dma_cookie_t cached_cookies[PVSCSI_MAX_SG_SIZE];
} pvscsi_cmd_t;

#define	AP2PRIV(ap) ((ap)->a_hba_tran->tran_hba_private)
#define	CMD2PKT(cmd) ((struct scsi_pkt *)((cmd)->pkt))
#define	PKT2CMD(pkt) ((pvscsi_cmd_t *)((pkt)->pkt_ha_private))
#define	SDEV2PRIV(sd) ((sd)->sd_address.a_hba_tran->tran_hba_private)
#define	TRAN2PRIV(tran) ((pvscsi_softc_t *)(tran)->tran_hba_private)

#define	CMD_CTX_SGLIST_VA(cmd_ctx) \
	((struct PVSCSISGElement *) \
	(((pvscsi_cmd_ctx_t *)(cmd_ctx))->dma_buf.addr))

#define	CMD_CTX_SGLIST_PA(cmd_ctx) \
	((((pvscsi_cmd_ctx_t *)(cmd_ctx))->dma_buf.pa))

typedef struct pvscsi_msg {
	struct pvscsi_softc *msg_pvs;
	int		type;
	int		target;
} pvscsi_msg_t;

/* Driver-wide flags */
#define	PVSCSI_DRIVER_SHUTDOWN		0x01
#define	PVSCSI_HBA_QUIESCED		0x02
#define	PVSCSI_HBA_QUIESCE_PENDING	0x04
#define	PVSCSI_HBA_AUTO_REQUEST_SENSE	0x08

#define	HBA_IS_QUIESCED(pvs) (((pvs)->flags & PVSCSI_HBA_QUIESCED) != 0)
#define	HBA_QUIESCE_PENDING(pvs) \
	(((pvs)->flags & PVSCSI_HBA_QUIESCE_PENDING) != 0 && \
	((pvs)->cmd_queue_len == 0))

typedef struct pvscsi_softc {
	dev_info_t	*dip;
	int		instance;
	scsi_hba_tran_t	*tran;
	ddi_dma_attr_t	hba_dma_attr;
	ddi_dma_attr_t	io_dma_attr;
	ddi_dma_attr_t	ring_dma_attr;
	pvscsi_dma_buf_t rings_state_buf;
	pvscsi_dma_buf_t req_ring_buf;
	uint_t		req_pages;
	uint_t		req_depth;
	pvscsi_dma_buf_t cmp_ring_buf;
	uint_t		cmp_pages;
	pvscsi_dma_buf_t msg_ring_buf;
	uint_t		msg_pages;
	ddi_acc_handle_t pci_config_handle;
	ddi_acc_handle_t mmio_handle;
	caddr_t		mmio_base;
	int		intr_type;
	int		intr_size;
	int		intr_cnt;
	int		intr_pri;
	int		flags;
	ddi_intr_handle_t *intr_htable;
	pvscsi_cmd_ctx_t *cmd_ctx;
	list_t		cmd_ctx_pool;
	list_t		cmd_queue;
	int		cmd_queue_len;
	kcondvar_t	wd_condvar;
	kmutex_t	mutex;
	kmutex_t	rx_mutex;
	kmutex_t	tx_mutex;
	kmutex_t	intr_mutex;
	struct kmem_cache *cmd_cache;
	list_t		devnodes;
	kcondvar_t	syncvar;
	kcondvar_t	quiescevar;
	kthread_t	*wd_thread;
	int		intr_lock_counter;
	int		num_pollers;
	ddi_taskq_t	*comp_tq;
	ddi_taskq_t	*msg_tq;
} pvscsi_softc_t;

typedef struct pvscsi_device {
	list_node_t	list;
	int		target;
	dev_info_t	*pdip;
	dev_info_t	*parent;
} pvscsi_device_t;

#define	REQ_RING(pvs) \
	((struct PVSCSIRingReqDesc *) \
	(((pvscsi_softc_t *)(pvs))->req_ring_buf.addr))

#define	CMP_RING(pvs) \
	((struct PVSCSIRingCmpDesc *) \
	(((pvscsi_softc_t *)(pvs))->cmp_ring_buf.addr))

#define	MSG_RING(pvs) \
	((struct PVSCSIRingMsgDesc *) \
	(((pvscsi_softc_t *)(pvs))->msg_ring_buf.addr))

#define	RINGS_STATE(pvs) \
	((struct PVSCSIRingsState *)(((pvscsi_softc_t *)\
	(pvs))->rings_state_buf.addr))

#define	PVSCSI_INITIAL_SSTATE_ITEMS	16

#define	SENSE_BUFFER_SIZE	SENSE_LENGTH
#define	USECS_TO_WAIT		1000

#define	PVSCSI_MAXTGTS	16

#define	PAGE_SIZE	4096
#define	PAGE_SHIFT	12

#define	PVSCSI_DEFAULT_NUM_PAGES_PER_RING	8
#define	PVSCSI_DEFAULT_NUM_PAGES_MSG_RING	1

#endif	/* _PVSCSI_VAR_H_ */
