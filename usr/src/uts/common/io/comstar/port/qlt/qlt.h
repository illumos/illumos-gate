/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_QLT_H
#define	_QLT_H

#include <stmf_defines.h>
#include <qlt_regs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Qlogic logging
 */
extern int enable_extended_logging;

/*
 * Caution: 1) LOG will be available in debug/non-debug mode
 *	    2) Anything which can potentially flood the log should be under
 *	       extended logging, and use QLT_EXT_LOG.
 *	    3) Don't use QLT_EXT_LOG in performance-critical code path, such
 *	       as normal SCSI I/O code path. It could hurt system performance.
 *	    4) Use kmdb to change enable_extened_logging in the fly to adjust
 *	       tracing
 */
#define	QLT_EXT_LOG(log_ident, ...)	\
		if (enable_extended_logging) {	\
			stmf_trace(log_ident, __VA_ARGS__);	\
		}

#define	QLT_LOG(log_ident, ...)	\
	stmf_trace(log_ident, __VA_ARGS__)

/*
 * Error codes. FSC stands for Failure sub code.
 */
#define	QLT_FAILURE			FCT_FCA_FAILURE
#define	QLT_SUCCESS			FCT_SUCCESS
#define	QLT_FSC(x)			((uint64_t)(x) << 40)
#define	QLT_DMA_STUCK			(QLT_FAILURE | QLT_FSC(1))
#define	QLT_MAILBOX_STUCK		(QLT_FAILURE | QLT_FSC(2))
#define	QLT_ROM_STUCK			(QLT_FAILURE | QLT_FSC(3))
#define	QLT_UNEXPECTED_RESPONSE		(QLT_FAILURE | QLT_FSC(4))
#define	QLT_MBOX_FAILED			(QLT_FAILURE | QLT_FSC(5))
#define	QLT_MBOX_NOT_INITIALIZED	(QLT_FAILURE | QLT_FSC(6))
#define	QLT_MBOX_BUSY			(QLT_FAILURE | QLT_FSC(7))
#define	QLT_MBOX_ABORTED		(QLT_FAILURE | QLT_FSC(8))
#define	QLT_MBOX_TIMEOUT		(QLT_FAILURE | QLT_FSC(9))
#define	QLT_RESP_TIMEOUT		(QLT_FAILURE | QLT_FSC(10))
#define	QLT_FLASH_TIMEOUT		(QLT_FAILURE | QLT_FSC(11))
#define	QLT_FLASH_ACCESS_ERROR		(QLT_FAILURE | QLT_FSC(12))
#define	QLT_BAD_NVRAM_DATA		(QLT_FAILURE | QLT_FSC(13))
#define	QLT_FIRMWARE_ERROR_CODE		(QLT_FAILURE | QLT_FSC(14))

#define	QLT_FIRMWARE_ERROR(s, c1, c2)	(QLT_FIRMWARE_ERROR_CODE | \
	(((uint64_t)s) << 32) | (((uint64_t)c1) << 24) | ((uint64_t)c2))

extern uint32_t fw2400_code01[];
extern uint32_t fw2400_length01;
extern uint32_t fw2400_addr01;
extern uint32_t fw2400_code02[];
extern uint32_t fw2400_length02;
extern uint32_t fw2400_addr02;

extern uint32_t fw2500_code01[];
extern uint32_t fw2500_length01;
extern uint32_t fw2500_addr01;
extern uint32_t fw2500_code02[];
extern uint32_t fw2500_length02;
extern uint32_t fw2500_addr02;

typedef enum {
	MBOX_STATE_UNKNOWN = 0,
	MBOX_STATE_READY,
	MBOX_STATE_CMD_RUNNING,
	MBOX_STATE_CMD_DONE
} mbox_state_t;

#define	IOCB_SIZE		64

/*
 * These should not be constents but should be obtained from fw.
 */
#define	QLT_MAX_LOGINS	2048
#define	QLT_MAX_XCHGES	2048

#define	MAX_MBOXES	32
#define	MBOX_TIMEOUT	(2*1000*1000)
#define	DEREG_RP_TIMEOUT	(2*1000*1000)

typedef struct {
	uint16_t	to_fw[MAX_MBOXES];
	uint32_t	to_fw_mask;
	uint16_t	from_fw[MAX_MBOXES];
	uint32_t	from_fw_mask;
	stmf_data_buf_t *dbuf;
} mbox_cmd_t;

typedef struct qlt_abts_cmd {
	uint8_t		buf[IOCB_SIZE];
} qlt_abts_cmd_t;

struct qlt_dmem_bucket;

#define	QLT_INTR_FIXED	0x1
#define	QLT_INTR_MSI	0x2
#define	QLT_INTR_MSIX	0x4

typedef struct qlt_state {
	dev_info_t		*dip;
	char			qlt_minor_name[16];
	char			qlt_port_alias[16];
	fct_local_port_t	*qlt_port;
	struct qlt_dmem_bucket	**dmem_buckets;

	int			instance;
	uint8_t			qlt_state:7,
				qlt_state_not_acked:1;
	uint8_t			qlt_intr_enabled:1,
				qlt_25xx_chip:1,
				qlt_stay_offline:1,
				qlt_link_up,
				qlt_rsvd1:4;
	uint8_t			cur_topology;

	/* Registers */
	caddr_t		regs;
	ddi_acc_handle_t regs_acc_handle;
	ddi_acc_handle_t pcicfg_acc_handle;

	/* Interrupt stuff */
	kmutex_t		intr_lock;	/* Only used by intr routine */
	int			intr_sneak_counter;
	ddi_intr_handle_t	*htable;
	int			intr_size;
	int			intr_cnt;
	uint_t			intr_pri;
	int			intr_cap;
	int			intr_flags;

	/* Queues */
	ddi_dma_handle_t queue_mem_dma_handle;
	ddi_acc_handle_t queue_mem_acc_handle;
	caddr_t		 queue_mem_ptr;
	ddi_dma_cookie_t queue_mem_cookie;

	kmutex_t	req_lock;
	caddr_t		req_ptr;
	uint32_t	req_ndx_to_fw;
	uint32_t	req_ndx_from_fw;
	uint32_t	req_available;

	caddr_t		resp_ptr;
	uint32_t	resp_ndx_to_fw;
	uint32_t	resp_ndx_from_fw;

	kmutex_t	preq_lock;
	caddr_t		preq_ptr;
	uint32_t	preq_ndx_to_fw;
	uint32_t	preq_ndx_from_fw;

	kcondvar_t	rp_dereg_cv; /* for deregister cmd */
	uint32_t	rp_id_in_dereg; /* remote port in deregistering */
	fct_status_t	rp_dereg_status;

	caddr_t		atio_ptr;
	uint16_t	atio_ndx_to_fw;
	uint16_t	atio_ndx_from_fw;

	kmutex_t	dma_mem_lock;

	/* MailBox data */
	kmutex_t	mbox_lock;
	kcondvar_t	mbox_cv;
	mbox_state_t	mbox_io_state;
	mbox_cmd_t	*mcp;
	qlt_nvram_t	*nvram;

	uint8_t		link_speed;	/* Cached from intr routine */
	uint16_t	fw_major;
	uint16_t	fw_minor;
	uint16_t	fw_subminor;
	uint16_t	fw_endaddrlo;
	uint16_t	fw_endaddrhi;
	uint16_t	fw_attr;

	uint32_t	fw_addr01;
	uint32_t	fw_length01;
	uint32_t	*fw_code01;
	uint32_t	fw_addr02;
	uint32_t	fw_length02;
	uint32_t	*fw_code02;

	uint32_t	qlt_ioctl_flags;
	kmutex_t	qlt_ioctl_lock;
	caddr_t		qlt_fwdump_buf;	/* FWDUMP will use ioctl flags/lock */
	uint32_t	qlt_change_state_flags;	/* Cached for ACK handling */
} qlt_state_t;

/*
 * FWDUMP flags (part of IOCTL flags)
 */
#define	QLT_FWDUMP_INPROGRESS		0x0100	/* if it's dumping now */
#define	QLT_FWDUMP_TRIGGERED_BY_USER	0x0200	/* if users triggered it */
#define	QLT_FWDUMP_FETCHED_BY_USER	0x0400	/* if users have viewed it */
#define	QLT_FWDUMP_ISVALID		0x0800

/*
 * IOCTL supporting stuff
 */
#define	QLT_IOCTL_FLAG_MASK		0xFF
#define	QLT_IOCTL_FLAG_IDLE		0x00
#define	QLT_IOCTL_FLAG_OPEN		0x01
#define	QLT_IOCTL_FLAG_EXCL		0x02

typedef struct qlt_cmd {
	stmf_data_buf_t	*dbuf;		/* dbuf with handle 0 for SCSI cmds */
	stmf_data_buf_t	*dbuf_rsp_iu;	/* dbuf for possible FCP_RSP IU */
	uint32_t	fw_xchg_addr;
	uint16_t	flags;
	union {
		uint16_t	resp_offset;
		uint8_t		atio_byte3;
	} param;
} qlt_cmd_t;

/*
 * cmd flags
 */
#define	QLT_CMD_ABORTING		1
#define	QLT_CMD_ABORTED			2
#define	QLT_CMD_TYPE_SOLICITED		4

typedef struct {
	int	dummy;
} qlt_remote_port_t;

#define	REQUEST_QUEUE_ENTRIES	2048
#define	RESPONSE_QUEUE_ENTRIES	2048
#define	ATIO_QUEUE_ENTRIES	2048
#define	PRIORITY_QUEUE_ENTRIES	128

#define	REQUEST_QUEUE_OFFSET	0
#define	RESPONSE_QUEUE_OFFSET	(REQUEST_QUEUE_OFFSET + \
				    (REQUEST_QUEUE_ENTRIES * IOCB_SIZE))
#define	ATIO_QUEUE_OFFSET	(RESPONSE_QUEUE_OFFSET + \
				    (RESPONSE_QUEUE_ENTRIES * IOCB_SIZE))
#define	PRIORITY_QUEUE_OFFSET	(ATIO_QUEUE_OFFSET + \
				    (ATIO_QUEUE_ENTRIES * IOCB_SIZE))
#define	MBOX_DMA_MEM_SIZE	4096
#define	MBOX_DMA_MEM_OFFSET		(PRIORITY_QUEUE_OFFSET + \
				    (PRIORITY_QUEUE_ENTRIES * IOCB_SIZE))
#define	TOTAL_DMA_MEM_SIZE	(MBOX_DMA_MEM_OFFSET + MBOX_DMA_MEM_SIZE)

#define	QLT_MAX_ITERATIONS_PER_INTR	32

#define	REG_RD16(qlt, addr) \
	ddi_get16(qlt->regs_acc_handle, (uint16_t *)(qlt->regs + addr))
#define	REG_RD32(qlt, addr) \
	ddi_get32(qlt->regs_acc_handle, (uint32_t *)(qlt->regs + addr))
#define	REG_WR16(qlt, addr, data) \
	ddi_put16(qlt->regs_acc_handle, (uint16_t *)(qlt->regs + addr), \
	(uint16_t)(data))
#define	REG_WR32(qlt, addr, data) \
	ddi_put32(qlt->regs_acc_handle, (uint32_t *)(qlt->regs + addr), \
	(uint32_t)(data))
#define	PCICFG_RD16(qlt, addr) \
	pci_config_get16(qlt->pcicfg_acc_handle, (off_t)(addr))
#define	PCICFG_RD32(qlt, addr) \
	pci_config_get32(qlt->pcicfg_acc_handle, (off_t)(addr))
#define	PCICFG_WR16(qlt, addr, data) \
	pci_config_put16(qlt->pcicfg_acc_handle, (off_t)(addr), \
		(uint16_t)(data))
#define	QMEM_RD16(qlt, addr) \
	ddi_get16(qlt->queue_mem_acc_handle, (uint16_t *)(addr))
#define	DMEM_RD16(qlt, addr) LE_16((uint16_t)(*((uint16_t *)(addr))))
#define	QMEM_RD32(qlt, addr) \
	ddi_get32(qlt->queue_mem_acc_handle, (uint32_t *)(addr))
#define	DMEM_RD32(qlt, addr) LE_32((uint32_t)(*((uint32_t *)(addr))))
/*
 * #define	QMEM_RD64(qlt, addr) \
 *	ddi_get64(qlt->queue_mem_acc_handle, (uint64_t *)(addr))
 */
#define	QMEM_WR16(qlt, addr, data) \
	ddi_put16(qlt->queue_mem_acc_handle, (uint16_t *)(addr), \
	(uint16_t)(data))
#define	DMEM_WR16(qlt, addr, data) (*((uint16_t *)(addr)) = \
						LE_16((uint16_t)(data)))
#define	QMEM_WR32(qlt, addr, data) \
	ddi_put32(qlt->queue_mem_acc_handle, (uint32_t *)(addr), \
	(uint32_t)(data))
#define	DMEM_WR32(qlt, addr, data) (*((uint32_t *)(addr)) = \
						LE_32((uint32_t)(data)))

/*
 * [QD]MEM is always little endian so the [QD]MEM_WR64 macro works for
 * both sparc and x86.
 */
#define	QMEM_WR64(qlt, addr, data) \
	QMEM_WR32(qlt, addr, (data & 0xffffffff)), \
	QMEM_WR32(qlt, (addr)+4, ((uint64_t)data) >> 32)

#define	DMEM_WR64(qlt, addr, data) \
	DMEM_WR32(qlt, addr, (data & 0xffffffff)), \
	DMEM_WR32(qlt, (addr)+4, ((uint64_t)data) >> 32)


#ifdef	__cplusplus
}
#endif

#endif /* _QLT_H */
