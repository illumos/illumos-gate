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
 * Copyright 2009 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_QLT_H
#define	_QLT_H

#include <sys/stmf_defines.h>
#include "qlt_regs.h"

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

extern uint32_t fw8100_code01[];
extern uint32_t fw8100_length01;
extern uint32_t fw8100_addr01;
extern uint32_t fw8100_code02[];
extern uint32_t fw8100_length02;
extern uint32_t fw8100_addr02;

typedef enum {
	MBOX_STATE_UNKNOWN = 0,
	MBOX_STATE_READY,
	MBOX_STATE_CMD_RUNNING,
	MBOX_STATE_CMD_DONE
} mbox_state_t;

/*
 * ISP mailbox commands
 */
#define	MBC_LOAD_RAM			0x01	/* Load RAM. */
#define	MBC_EXECUTE_FIRMWARE		0x02	/* Execute firmware. */
#define	MBC_DUMP_RAM			0x03	/* Dump RAM. */
#define	MBC_WRITE_RAM_WORD		0x04	/* Write RAM word. */
#define	MBC_READ_RAM_WORD		0x05	/* Read RAM word. */
#define	MBC_MAILBOX_REGISTER_TEST	0x06	/* Wrap incoming mailboxes */
#define	MBC_VERIFY_CHECKSUM		0x07	/* Verify checksum. */
#define	MBC_ABOUT_FIRMWARE		0x08	/* About Firmware. */
#define	MBC_DUMP_RISC_RAM		0x0a	/* Dump RISC RAM command. */
#define	MBC_LOAD_RAM_EXTENDED		0x0b	/* Load RAM extended. */
#define	MBC_DUMP_RAM_EXTENDED		0x0c	/* Dump RAM extended. */
#define	MBC_WRITE_RAM_EXTENDED		0x0d	/* Write RAM word. */
#define	MBC_READ_RAM_EXTENDED		0x0f	/* Read RAM extended. */
#define	MBC_SERDES_TRANSMIT_PARAMETERS	0x10	/* Serdes Xmit Parameters */
#define	MBC_2300_EXECUTE_IOCB		0x12	/* ISP2300 Execute IOCB cmd */
#define	MBC_GET_IO_STATUS		0x12	/* ISP2422 Get I/O Status */
#define	MBC_STOP_FIRMWARE		0x14	/* Stop firmware */
#define	MBC_ABORT_COMMAND_IOCB		0x15	/* Abort IOCB command. */
#define	MBC_ABORT_DEVICE		0x16	/* Abort device (ID/LUN). */
#define	MBC_ABORT_TARGET		0x17	/* Abort target (ID). */
#define	MBC_RESET			0x18	/* Target reset. */
#define	MBC_XMIT_PARM			0x19	/* Change default xmit parms */
#define	MBC_PORT_PARAM			0x1a	/* Get/set port speed parms */
#define	MBC_GET_ID			0x20	/* Get loop id of ISP2200. */
#define	MBC_GET_TIMEOUT_PARAMETERS	0x22	/* Get Timeout Parameters. */
#define	MBC_TRACE_CONTROL		0x27	/* Trace control. */
#define	MBC_GET_FIRMWARE_OPTIONS	0x28	/* Get firmware options */
#define	MBC_READ_SFP			0x31	/* Read SFP. */

#define	MBC_SET_ADDITIONAL_FIRMWARE_OPT	0x38	/* set firmware options */

#define	OPT_PUREX_ENABLE			(BIT_10)

#define	MBC_RESET_MENLO			0x3a	/* Reset Menlo. */
#define	MBC_RESTART_MPI			0x3d	/* Restart MPI. */
#define	MBC_FLASH_ACCESS		0x3e	/* Flash Access Control */
#define	MBC_LOOP_PORT_BYPASS		0x40	/* Loop Port Bypass. */
#define	MBC_LOOP_PORT_ENABLE		0x41	/* Loop Port Enable. */
#define	MBC_GET_RESOURCE_COUNTS		0x42	/* Get Resource Counts. */
#define	MBC_NON_PARTICIPATE		0x43	/* Non-Participating Mode. */
#define	MBC_ECHO			0x44	/* ELS ECHO */
#define	MBC_DIAGNOSTIC_LOOP_BACK	0x45	/* Diagnostic loop back. */
#define	MBC_ONLINE_SELF_TEST		0x46	/* Online self-test. */
#define	MBC_ENHANCED_GET_PORT_DATABASE	0x47	/* Get Port Database + login */
#define	MBC_INITIALIZE_MULTI_ID_FW	0x48	/* Initialize multi-id fw */
#define	MBC_GET_DCBX_PARAMS		0x51	/* Get DCBX parameters */
#define	MBC_RESET_LINK_STATUS		0x52	/* Reset Link Error Status */
#define	MBC_EXECUTE_IOCB		0x54	/* 64 Bit Execute IOCB cmd. */
#define	MBC_SEND_RNID_ELS		0x57	/* Send RNID ELS request */

#define	MBC_SET_PARAMETERS		0x59	/* Set parameters */

#define	RNID_PARAMS_DF_FMT		0x00
#define	RNID_PARAMS_E0_FMT		0x01
#define	PUREX_ELS_CMDS			0x05
#define	FLOGI_PARAMS			0x06

#define	PARAM_TYPE_FIELD_MASK		0xff
#define	PARAM_TYPE_FIELD_SHIFT		8
#define	PARAM_TYPE(type)		((type & PARAM_TYPE_FIELD_MASK) << \
					    PARAM_TYPE_FIELD_SHIFT)

#define	MBC_GET_PARAMETERS		0x5a	/* Get RNID parameters */
#define	MBC_DATA_RATE			0x5d	/* Data Rate */
#define	MBC_INITIALIZE_FIRMWARE		0x60	/* Initialize firmware */
#define	MBC_INITIATE_LIP		0x62	/* Initiate LIP */
#define	MBC_GET_FC_AL_POSITION_MAP	0x63	/* Get FC_AL Position Map. */
#define	MBC_GET_PORT_DATABASE		0x64	/* Get Port Database. */
#define	MBC_CLEAR_ACA			0x65	/* Clear ACA. */
#define	MBC_TARGET_RESET		0x66	/* Target Reset. */
#define	MBC_CLEAR_TASK_SET		0x67	/* Clear Task Set. */
#define	MBC_ABORT_TASK_SET		0x68	/* Abort Task Set. */
#define	MBC_GET_FIRMWARE_STATE		0x69	/* Get firmware state. */
#define	MBC_GET_PORT_NAME		0x6a	/* Get port name. */
#define	MBC_GET_LINK_STATUS		0x6b	/* Get Link Status. */
#define	MBC_LIP_RESET			0x6c	/* LIP reset. */
#define	MBC_GET_STATUS_COUNTS		0x6d	/* Get Link Statistics and */
						/* Private Data Counts */
#define	MBC_SEND_SNS_COMMAND		0x6e	/* Send Simple Name Server */
#define	MBC_LOGIN_FABRIC_PORT		0x6f	/* Login fabric port. */
#define	MBC_SEND_CHANGE_REQUEST		0x70	/* Send Change Request. */
#define	MBC_LOGOUT_FABRIC_PORT		0x71	/* Logout fabric port. */
#define	MBC_LIP_FULL_LOGIN		0x72	/* Full login LIP. */
#define	MBC_LOGIN_LOOP_PORT		0x74	/* Login Loop Port. */
#define	MBC_PORT_NODE_NAME_LIST		0x75	/* Get port/node name list */
#define	MBC_INITIALIZE_IP		0x77	/* Initialize IP */
#define	MBC_SEND_FARP_REQ_COMMAND	0x78	/* FARP request. */
#define	MBC_UNLOAD_IP			0x79	/* Unload IP */
#define	MBC_GET_XGMAC_STATS		0x7a	/* Get XGMAC Statistics. */
#define	MBC_GET_ID_LIST			0x7c	/* Get port ID list. */
#define	MBC_SEND_LFA_COMMAND		0x7d	/* Send Loop Fabric Address */
#define	MBC_LUN_RESET			0x7e	/* Send Task mgmt LUN reset */
#define	MBC_IDC_REQUEST			0x100	/* IDC request */
#define	MBC_IDC_ACK			0x101	/* IDC acknowledge */
#define	MBC_IDC_TIME_EXTEND		0x102	/* IDC extend time */
#define	MBC_PORT_RESET			0x120	/* Port Reset */
#define	MBC_SET_PORT_CONFIG		0x122	/* Set port configuration */
#define	MBC_GET_PORT_CONFIG		0x123	/* Get port configuration */

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
struct qlt_ddi_dma_handle_pool;

#define	QLT_INTR_FIXED	0x1
#define	QLT_INTR_MSI	0x2
#define	QLT_INTR_MSIX	0x4

typedef struct qlt_el_trace_desc {
	kmutex_t	mutex;
	uint16_t	next;
	uint32_t	trace_buffer_size;
	char		*trace_buffer;
} qlt_el_trace_desc_t;

typedef struct qlt_state {
	dev_info_t		*dip;
	char			qlt_minor_name[16];
	char			qlt_port_alias[16];
	fct_local_port_t	*qlt_port;
	struct qlt_dmem_bucket	**dmem_buckets;

	struct qlt_dma_handle_pool
				*qlt_dma_handle_pool;

	int			instance;
	uint8_t			qlt_state:7,
				qlt_state_not_acked:1;
	uint8_t			qlt_intr_enabled:1,
				qlt_25xx_chip:1,
				qlt_stay_offline:1,
				qlt_link_up,
				qlt_81xx_chip:1,
				qlt_rsvd1:3;
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

	qlt_el_trace_desc_t	*el_trace_desc;

	/* temp ref & stat counters */
	uint32_t	qlt_bucketcnt[5];	/* element 0 = 2k */
	uint64_t	qlt_bufref[5];		/* element 0 = 2k */
	uint64_t	qlt_bumpbucket;		/* bigger buffer supplied */
	uint64_t	qlt_pmintry;
	uint64_t	qlt_pmin_ok;
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
#define	QLT_INFO_LEN			160

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
	(uint16_t)LE_16((uint16_t)(data)))
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

/*
 * Structure used to associate values with strings which describe them.
 */
typedef struct string_table_entry {
	uint32_t value;
	char    *string;
} string_table_t;

char *prop_text(int prop_status);
char *value2string(string_table_t *entry, int value, int delimiter);

#define	PROP_STATUS_DELIMITER	((uint32_t)0xFFFF)

#define	DDI_PROP_STATUS()					\
{								\
	{DDI_PROP_SUCCESS, "DDI_PROP_SUCCESS"},			\
	{DDI_PROP_NOT_FOUND, "DDI_PROP_NOT_FOUND"},		\
	{DDI_PROP_UNDEFINED, "DDI_PROP_UNDEFINED"},		\
	{DDI_PROP_NO_MEMORY, "DDI_PROP_NO_MEMORY"},		\
	{DDI_PROP_INVAL_ARG, "DDI_PROP_INVAL_ARG"},		\
	{DDI_PROP_BUF_TOO_SMALL, "DDI_PROP_BUF_TOO_SMALL"},	\
	{DDI_PROP_CANNOT_DECODE, "DDI_PROP_CANNOT_DECODE"},	\
	{DDI_PROP_CANNOT_ENCODE, "DDI_PROP_CANNOT_ENCODE"},	\
	{DDI_PROP_END_OF_DATA, "DDI_PROP_END_OF_DATA"},		\
	{PROP_STATUS_DELIMITER, "DDI_PROP_UNKNOWN"}		\
}

#ifndef TRUE
#define	TRUE	B_TRUE
#endif

#ifndef FALSE
#define	FALSE	B_FALSE
#endif

/* Little endian machine correction defines. */
#ifdef _LITTLE_ENDIAN
#define	LITTLE_ENDIAN_16(x)
#define	LITTLE_ENDIAN_24(x)
#define	LITTLE_ENDIAN_32(x)
#define	LITTLE_ENDIAN_64(x)
#define	LITTLE_ENDIAN(bp, bytes)
#define	BIG_ENDIAN_16(x)	qlt_chg_endian((uint8_t *)x, 2)
#define	BIG_ENDIAN_24(x)	qlt_chg_endian((uint8_t *)x, 3)
#define	BIG_ENDIAN_32(x)	qlt_chg_endian((uint8_t *)x, 4)
#define	BIG_ENDIAN_64(x)	qlt_chg_endian((uint8_t *)x, 8)
#define	BIG_ENDIAN(bp, bytes)	qlt_chg_endian((uint8_t *)bp, bytes)
#endif /* _LITTLE_ENDIAN */

/* Big endian machine correction defines. */
#ifdef _BIG_ENDIAN
#define	LITTLE_ENDIAN_16(x)		qlt_chg_endian((uint8_t *)x, 2)
#define	LITTLE_ENDIAN_24(x)		qlt_chg_endian((uint8_t *)x, 3)
#define	LITTLE_ENDIAN_32(x)		qlt_chg_endian((uint8_t *)x, 4)
#define	LITTLE_ENDIAN_64(x)		qlt_chg_endian((uint8_t *)x, 8)
#define	LITTLE_ENDIAN(bp, bytes)	qlt_chg_endian((uint8_t *)bp, bytes)
#define	BIG_ENDIAN_16(x)
#define	BIG_ENDIAN_24(x)
#define	BIG_ENDIAN_32(x)
#define	BIG_ENDIAN_64(x)
#define	BIG_ENDIAN(bp, bytes)
#endif /* _BIG_ENDIAN */

#define	LSB(x)		(uint8_t)(x)
#define	MSB(x)		(uint8_t)((uint16_t)(x) >> 8)
#define	MSW(x)		(uint16_t)((uint32_t)(x) >> 16)
#define	LSW(x)		(uint16_t)(x)
#define	LSD(x)		(uint32_t)(x)
#define	MSD(x)		(uint32_t)((uint64_t)(x) >> 32)

void	qlt_chg_endian(uint8_t *, size_t);

void qlt_el_msg(qlt_state_t *qlt, const char *fn, int ce, ...);
void qlt_dump_el_trace_buffer(qlt_state_t *qlt);
#define	EL(qlt, ...) 	qlt_el_msg(qlt, __func__, CE_CONT, __VA_ARGS__);
#define	EL_TRACE_BUF_SIZE	8192
#define	EL_BUFFER_RESERVE	256
#define	DEBUG_STK_DEPTH		24
#define	EL_TRACE_BUF_SIZE	8192

#ifdef	__cplusplus
}
#endif

#endif /* _QLT_H */
