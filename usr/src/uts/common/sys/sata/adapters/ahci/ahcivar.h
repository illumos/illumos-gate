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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */


#ifndef _AHCIVAR_H
#define	_AHCIVAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sata/adapters/ahci/ahciem.h>

/*
 * AHCI address qualifier flags (in qual field of ahci_addr struct).
 */
#define	AHCI_ADDR_NULL		0x00
#define	AHCI_ADDR_PORT		0x01
#define	AHCI_ADDR_PMPORT	0x02
#define	AHCI_ADDR_PMULT		0x04
#define	AHCI_ADDR_VALID		(AHCI_ADDR_PORT | \
				AHCI_ADDR_PMULT | \
				AHCI_ADDR_PMPORT)

/*
 * AHCI address structure.
 */
struct ahci_addr {

	/* HBA port number */
	uint8_t			aa_port;

	/* Port multiplier port number */
	uint8_t			aa_pmport;

	/*
	 * AHCI_ADDR_NULL
	 * AHCI_ADDR_PORT
	 * AHCI_ADDR_PMPORT
	 * AHCI_ADDR_PMULT
	 */
	uint8_t			aa_qual;
};
typedef struct ahci_addr ahci_addr_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", ahci_addr))

#define	AHCI_ADDR_IS_PORT(addrp)					\
	((addrp)->aa_qual & AHCI_ADDR_PORT)
#define	AHCI_ADDR_IS_PMPORT(addrp)					\
	((addrp)->aa_qual & AHCI_ADDR_PMPORT)
#define	AHCI_ADDR_IS_PMULT(addrp)					\
	((addrp)->aa_qual & AHCI_ADDR_PMULT)
#define	AHCI_ADDR_IS_VALID(addrp)					\
	((addrp)->aa_port < SATA_MAX_CPORTS) &&				\
	((addrp)->aa_pmport < SATA_MAX_PMPORTS) &&			\
	((addrp)->aa_qual & AHCI_ADDR_VALID)

#define	AHCI_ADDR_SET(addrp, port, pmport, qual)			\
	{								\
		(addrp)->aa_port = port;				\
		(addrp)->aa_pmport = pmport;				\
		(addrp)->aa_qual = qual;				\
	}
#define	AHCI_ADDR_SET_PORT(addrp, port)					\
	AHCI_ADDR_SET(addrp, port, 0, AHCI_ADDR_PORT)
#define	AHCI_ADDR_SET_PMPORT(addrp, port, pmport)			\
	AHCI_ADDR_SET(addrp, port, pmport, AHCI_ADDR_PMPORT)
#define	AHCI_ADDR_SET_PMULT(addrp, port)				\
	AHCI_ADDR_SET(addrp, port, SATA_PMULT_HOSTPORT, AHCI_ADDR_PMULT)

/* Type for argument of event handler */
typedef	struct ahci_event_arg {
	void		*ahciea_ctlp;
	void		*ahciea_portp;
	void		*ahciea_addrp;
	uint32_t	ahciea_event;
} ahci_event_arg_t;

/* Warlock annotation */
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_ctlp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_portp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_addrp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_event))


/*
 * ahci_pmult_info stores the information of a port multiplier and its
 * sub-devices in case a port multiplier is attached to an HBA port.
 */
struct ahci_pmult_info {

	/* Number of the device ports */
	int			ahcipmi_num_dev_ports;

	/* Device type of the sub-devices of the port multipler */
	uint8_t			ahcipmi_device_type[SATA_MAX_PMPORTS];

	/* State of port multiplier port */
	uint32_t		ahcipmi_port_state[SATA_MAX_PMPORTS];

	/*
	 * Port multiplier port on which there is outstanding NCQ
	 * commands. Only make sense in command based switching mode.
	 */
	uint8_t			ahcipmi_ncq_pmport;

	/* Pending asynchronous notification events tags */
	uint32_t		ahcipmi_snotif_tags;
};
typedef struct ahci_pmult_info ahci_pmult_info_t;

/*
 * flags for ahciport_flags
 *
 * AHCI_PORT_FLAG_MOPPING: this flag will be set when the HBA is stopped,
 * and all the outstanding commands need to be aborted and sent to upper
 * layers.
 *
 * AHCI_PORT_FLAG_POLLING: this flag will be set when the interrupt is
 * disabled, and the command is executed in POLLING mode.
 *
 * AHCI_PORT_FLAG_RQSENSE: this flag will be set when a REQUEST SENSE which
 * is used to retrieve sense data is being executed.
 *
 * AHCI_PORT_FLAG_STARTED: this flag will be set when the port is started,
 * that is PxCMD.ST is set with '1', and be cleared when the port is put into
 * idle, that is PxCMD.ST is changed from '1' to '0'.
 *
 * AHCI_PORT_FLAG_RDLOGEXT: this flag will be set when a READ LOG EXT which
 * is used to retrieve NCQ failure context is being executed.
 *
 * AHCI_PORT_FLAG_NODEV: this flag will be set when a device is found gone
 * during ahci_restart_port_wait_till_ready process.
 *
 * AHCI_PORT_FLAG_RDWR_PMULT: this flag will be set when a READ/WRITE
 * PORTMULT command is being executed.
 *
 * AHCI_PORT_FLAG_IGNORE_IPMS: this flag will be set when enumerating a port
 * multiplier. According AHCI spec, IPMS error should be ignore during
 * enumeration of port multiplier.
 *
 * AHCI_PORT_FLAG_PMULT_SNTF: this flag will be set when the a asynchronous
 * notification event on the port multiplier is being handled.
 *
 * AHCI_PORT_FLAG_HOTPLUG: this flag will be set when a hot plug event is
 * being handled.
 *
 * AHCI_PORT_FLAG_ERRPRINT: this flag will be set when error recovery message
 * will be printed. Note that, for INDENTIFY DEVICE command sent to ATAPI
 * device or ATAPI PACKET command, this flag won't be set.
 */
#define	AHCI_PORT_FLAG_MOPPING		0x02
#define	AHCI_PORT_FLAG_POLLING		0x04
#define	AHCI_PORT_FLAG_RQSENSE		0x08
#define	AHCI_PORT_FLAG_STARTED		0x10
#define	AHCI_PORT_FLAG_RDLOGEXT		0x20
#define	AHCI_PORT_FLAG_NODEV		0x40
#define	AHCI_PORT_FLAG_RDWR_PMULT	0x80
#define	AHCI_PORT_FLAG_IGNORE_IPMS	0x100
#define	AHCI_PORT_FLAG_PMULT_SNTF	0x200
#define	AHCI_PORT_FLAG_HOTPLUG		0x400
#define	AHCI_PORT_FLAG_ERRPRINT		0x800

typedef struct ahci_port {
	/* The physical port number */
	uint8_t			ahciport_port_num;

	/* Type of the device attached to the port */
	uint8_t			ahciport_device_type;
	/* State of the port */
	uint32_t		ahciport_port_state;

	/* Port multiplier struct */
	ahci_pmult_info_t	*ahciport_pmult_info;

	/*
	 * AHCI_PORT_FLAG_MOPPING
	 * AHCI_PORT_FLAG_POLLING
	 * AHCI_PORT_FLAG_RQSENSE
	 * AHCI_PORT_FLAG_STARTED
	 * AHCI_PORT_FLAG_RDLOGEXT
	 * AHCI_PORT_FLAG_NODEV
	 * AHCI_PORT_FLAG_RDWR_PMULT
	 * AHCI_PORT_FLAG_IGNORE_IPMS
	 * AHCI_PORT_FLAG_PMULT_SNTF
	 * AHCI_PORT_FLAG_HOTPLUG
	 * AHCI_PORT_FLAG_ERRPRINT
	 */
	int			ahciport_flags;

	/* Pointer to received FIS structure */
	ahci_rcvd_fis_t		*ahciport_rcvd_fis;
	ddi_dma_handle_t	ahciport_rcvd_fis_dma_handle;
	ddi_acc_handle_t	ahciport_rcvd_fis_acc_handle;
	ddi_dma_cookie_t	ahciport_rcvd_fis_dma_cookie;

	/* Pointer to command list structure */
	ahci_cmd_header_t	*ahciport_cmd_list;
	ddi_dma_handle_t	ahciport_cmd_list_dma_handle;
	ddi_acc_handle_t	ahciport_cmd_list_acc_handle;
	ddi_dma_cookie_t	ahciport_cmd_list_dma_cookie;

	/* Pointer to cmmand table structure */
	ahci_cmd_table_t	\
			*ahciport_cmd_tables[AHCI_PORT_MAX_CMD_SLOTS];
	ddi_dma_handle_t	\
			ahciport_cmd_tables_dma_handle[AHCI_PORT_MAX_CMD_SLOTS];
	ddi_acc_handle_t	\
			ahciport_cmd_tables_acc_handle[AHCI_PORT_MAX_CMD_SLOTS];

	/* Condition variable used for sync mode commands */
	kcondvar_t		ahciport_cv;

	/* The whole mutex for the port structure */
	kmutex_t		ahciport_mutex;

	/* The maximum number of tags for native queuing command transfers */
	int			ahciport_max_ncq_tags;

	/* Keep the tags of all pending non-ncq commands */
	uint32_t		ahciport_pending_tags;

	/*
	 * Keep the tags of all pending ncq commands
	 * (READ/WRITE FPDMA QUEUED)
	 */
	uint32_t		ahciport_pending_ncq_tags;

	/* Keep all the pending sata packets */
	sata_pkt_t		*ahciport_slot_pkts[AHCI_PORT_MAX_CMD_SLOTS];

	/* Used to check whether corresponding packet is timeout */
	int			ahciport_slot_timeout[AHCI_PORT_MAX_CMD_SLOTS];

	/* Queue of completed (done) sata packet */
	sata_pkt_t		*ahciport_doneq;

	/* Pointer of the tail of completed sata packet queue */
	sata_pkt_t		**ahciport_doneqtail;

	/* the length of the completed sata packet queue */
	uint32_t		ahciport_doneq_len;

	/* Keep the byte count of all PRD entries for every sata packet */
	uint32_t		\
			ahciport_prd_bytecounts[AHCI_PORT_MAX_CMD_SLOTS];

	/* Keep the error retrieval sata packet */
	sata_pkt_t		*ahciport_err_retri_pkt;

	/* Keep the read/write port multiplier packet */
	sata_pkt_t		*ahciport_rdwr_pmult_pkt;

	/*
	 * SATA HBA driver is supposed to remember and maintain device
	 * reset state. While the reset is in progress, it doesn't accept
	 * any more commands until receiving the command with
	 * SATA_CLEAR_DEV_RESET_STATE flag and SATA_IGNORE_DEV_RESET_STATE.
	 */
	int			ahciport_reset_in_progress;

	/* Taskq for handling event */
	ddi_taskq_t		*ahciport_event_taskq;

	/* This is for error recovery handler */
	ahci_event_arg_t	*ahciport_event_args;

	/* This is to calculate how many mops are in progress */
	int			ahciport_mop_in_progress;
} ahci_port_t;

/* Warlock annotation */
_NOTE(READ_ONLY_DATA(ahci_port_t::ahciport_rcvd_fis_dma_handle))
_NOTE(READ_ONLY_DATA(ahci_port_t::ahciport_cmd_list_dma_handle))
_NOTE(READ_ONLY_DATA(ahci_port_t::ahciport_cmd_tables_dma_handle))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_device_type))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_port_state))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_flags))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_pending_tags))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_slot_pkts))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_slot_timeout))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_doneq))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_doneqtail))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_doneq_len))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_reset_in_progress))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_mop_in_progress))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_event_taskq))

#define	AHCI_NUM_PORTS(ctlp)						\
	(ctlp)->ahcictl_num_ports

#define	AHCIPORT_NUM_PMPORTS(portp)					\
	(portp)->ahciport_pmult_info->ahcipmi_num_dev_ports

#define	AHCIPORT_NCQ_PMPORT(ahci_portp)					\
	(ahci_portp->ahciport_pmult_info->ahcipmi_ncq_pmport)

#define	AHCIPORT_DEV_TYPE(portp, addrp)					\
	(portp)->ahciport_device_type

#define	AHCIPORT_PMDEV_TYPE(portp, addrp)				\
	(portp)->ahciport_pmult_info->ahcipmi_device_type		\
	[(addrp)->aa_pmport]

#define	AHCIPORT_GET_DEV_TYPE(portp, addrp)				\
	(AHCI_ADDR_IS_PORT(addrp) | AHCI_ADDR_IS_PMULT(addrp) ?		\
	AHCIPORT_DEV_TYPE(portp, addrp) :				\
	AHCIPORT_PMDEV_TYPE(portp, addrp))

#define	AHCIPORT_SET_DEV_TYPE(portp, addrp, type)			\
	if (AHCI_ADDR_IS_PORT(addrp) | AHCI_ADDR_IS_PMULT(addrp))	\
		AHCIPORT_DEV_TYPE(portp, addrp) = type;			\
	else								\
		AHCIPORT_PMDEV_TYPE(portp, addrp) = type;

#define	AHCIPORT_STATE(portp, addrp)					\
	(portp)->ahciport_port_state

#define	AHCIPORT_PMSTATE(portp, addrp)					\
	(portp)->ahciport_pmult_info->ahcipmi_port_state		\
	[(addrp)->aa_pmport]

#define	AHCIPORT_GET_STATE(portp, addrp)				\
	(AHCI_ADDR_IS_PORT(addrp) | AHCI_ADDR_IS_PMULT(addrp) ?		\
	AHCIPORT_STATE(portp, addrp) : AHCIPORT_PMSTATE(portp, addrp))

#define	AHCIPORT_SET_STATE(portp, addrp, state)				\
	if (AHCI_ADDR_IS_PORT(addrp) | AHCI_ADDR_IS_PMULT(addrp))	\
		AHCIPORT_STATE(portp, addrp) = state;			\
	else								\
		AHCIPORT_PMSTATE(portp, addrp) = state;

typedef enum ahci_em_flags {
	AHCI_EM_PRESENT		= 1 << 0,
	AHCI_EM_RESETTING	= 1 << 1,
	AHCI_EM_TIMEOUT		= 1 << 2,
	AHCI_EM_QUIESCE		= 1 << 3,
	AHCI_EM_READY		= 1 << 4,
} ahci_em_flags_t;

#define	AHCI_EM_USABLE		(AHCI_EM_PRESENT | AHCI_EM_READY)

typedef struct ahci_ctl {
	dev_info_t		*ahcictl_dip;

	ushort_t		ahcictl_venid;
	ushort_t		ahcictl_devid;

	/* To map port number to cport number */
	uint8_t			ahcictl_port_to_cport[AHCI_MAX_PORTS];
	/* To map cport number to port number */
	uint8_t			ahcictl_cport_to_port[AHCI_MAX_PORTS];

	/* Number of controller ports */
	int			ahcictl_num_ports;
	/* Number of command slots */
	int			ahcictl_num_cmd_slots;
	/* Number of implemented ports */
	int			ahcictl_num_implemented_ports;
	/* Bit map to indicate which port is implemented */
	uint32_t		ahcictl_ports_implemented;
	ahci_port_t		*ahcictl_ports[AHCI_MAX_PORTS];

	int			ahcictl_flags;
	int			ahcictl_power_level;
	off_t			ahcictl_pmcsr_offset;

	/*
	 * AHCI_CAP_PIO_MDRQ
	 * AHCI_CAP_NO_MCMDLIST_NONQUEUE
	 * AHCI_CAP_NCQ
	 * AHCI_CAP_PM
	 * AHCI_CAP_BUF_32BIT_DMA
	 * AHCI_CAP_SCLO
	 * AHCI_CAP_COMMU_32BIT_DMA
	 * AHCI_CAP_INIT_PORT_RESET
	 * AHCI_CAP_SNTF
	 * AHCI_CAP_PMULT_CBSS
	 * AHCI_CAP_PMULT_FBSS
	 * AHCI_CAP_SRST_NO_HOSTPORT
	 */
	int			ahcictl_cap;

	/* Pci configuration space handle */
	ddi_acc_handle_t	ahcictl_pci_conf_handle;

	/* Mapping into bar 5 - AHCI base address */
	ddi_acc_handle_t	ahcictl_ahci_acc_handle;
	uintptr_t		ahcictl_ahci_addr;

	/* Pointer used for sata hba framework registration */
	struct sata_hba_tran	*ahcictl_sata_hba_tran;

	/* DMA attributes for the data buffer */
	ddi_dma_attr_t		ahcictl_buffer_dma_attr;
	/* DMA attributes for the rcvd FIS */
	ddi_dma_attr_t		ahcictl_rcvd_fis_dma_attr;
	/* DMA attributes for the command list */
	ddi_dma_attr_t		ahcictl_cmd_list_dma_attr;
	/* DMA attributes for command tables */
	ddi_dma_attr_t		ahcictl_cmd_table_dma_attr;

	/* Used for watchdog handler */
	timeout_id_t		ahcictl_timeout_id;

	/* Per controller mutex */
	kmutex_t		ahcictl_mutex;

	/* Components for interrupt */
	ddi_intr_handle_t	*ahcictl_intr_htable;   /* For array of intrs */
	int			ahcictl_intr_type; /* What type of interrupt */
	int			ahcictl_intr_cnt;  /* # of intrs returned */
	size_t			ahcictl_intr_size; /* Size of intr array */
	uint_t			ahcictl_intr_pri;  /* Intr priority */
	int			ahcictl_intr_cap;  /* Intr capabilities */

	/* FMA capabilities */
	int			ahcictl_fm_cap;

	/*
	 * Enclosure information
	 */
	uint32_t		ahcictl_em_loc;
	uint32_t		ahcictl_em_ctl;
	uintptr_t		ahcictl_em_tx_off;
	ahci_em_flags_t		ahcictl_em_flags;
	ddi_taskq_t		*ahcictl_em_taskq;
	ahci_em_led_state_t	ahcictl_em_state[AHCI_MAX_PORTS];
} ahci_ctl_t;

/* Warlock annotation */
_NOTE(READ_ONLY_DATA(ahci_ctl_t::ahcictl_ports))
_NOTE(READ_ONLY_DATA(ahci_ctl_t::ahcictl_cport_to_port))
_NOTE(READ_ONLY_DATA(ahci_ctl_t::ahcictl_port_to_cport))

_NOTE(MUTEX_PROTECTS_DATA(ahci_ctl_t::ahcictl_mutex,
					ahci_ctl_t::ahcictl_power_level))
_NOTE(MUTEX_PROTECTS_DATA(ahci_ctl_t::ahcictl_mutex,
					ahci_ctl_t::ahcictl_flags))
_NOTE(MUTEX_PROTECTS_DATA(ahci_ctl_t::ahcictl_mutex,
					ahci_ctl_t::ahcictl_timeout_id))

#define	AHCI_SUCCESS	(0)  /* Successful return */
#define	AHCI_TIMEOUT	(1)  /* Timed out */
#define	AHCI_FAILURE	(-1) /* Unsuccessful return */

/* Flags for ahcictl_flags */
#define	AHCI_ATTACH		0x1
#define	AHCI_DETACH		0x2
#define	AHCI_SUSPEND		0x4
#define	AHCI_QUIESCE		0x8

/* Values for ahcictl_cap */
/* PIO Multiple DRQ Block */
#define	AHCI_CAP_PIO_MDRQ		0x1
/*
 * Multiple command slots in the command list cannot be used for
 * non-queued commands
 */
#define	AHCI_CAP_NO_MCMDLIST_NONQUEUE	0x2
/* Native Command Queuing (NCQ) */
#define	AHCI_CAP_NCQ			0x4
/* Power Management (PM) */
#define	AHCI_CAP_PM			0x8
/* 32-bit DMA addressing for buffer block */
#define	AHCI_CAP_BUF_32BIT_DMA		0x10
/* Supports Command List Override */
#define	AHCI_CAP_SCLO			0x20
/* 32-bit DMA addressing for communication memory descriptors */
#define	AHCI_CAP_COMMU_32BIT_DMA	0x40
/* Port reset is needed for initialization */
#define	AHCI_CAP_INIT_PORT_RESET	0x80
/* Port Asychronous Notification */
#define	AHCI_CAP_SNTF			0x100
/* Port Multiplier Command-Based Switching Support (PMULT_CBSS) */
#define	AHCI_CAP_PMULT_CBSS		0x200
/* Port Multiplier FIS-Based Switching Support (PMULT_FBSS) */
#define	AHCI_CAP_PMULT_FBSS		0x400
/* Software Reset FIS cannot set pmport with 0xf for direct access device */
#define	AHCI_CAP_SRST_NO_HOSTPORT	0x800
/* Enclosure Management Services available */
#define	AHCI_CAP_EMS			0x1000

/* Flags controlling the restart port behavior */
#define	AHCI_PORT_RESET		0x0001	/* Reset the port */
#define	AHCI_RESET_NO_EVENTS_UP	0x0002	/* Don't send reset events up */

#define	ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)		\
	(ahci_portp->ahciport_flags &			\
	(AHCI_PORT_FLAG_RQSENSE|AHCI_PORT_FLAG_RDLOGEXT))

#define	RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)		\
	(ahci_portp->ahciport_flags &			\
	AHCI_PORT_FLAG_RDWR_PMULT)

#define	NON_NCQ_CMD_IN_PROGRESS(ahci_portp)		\
	(!ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) &&	\
	ahci_portp->ahciport_pending_tags != 0 &&	\
	ahci_portp->ahciport_pending_ncq_tags == 0)

#define	NCQ_CMD_IN_PROGRESS(ahci_portp)			\
	(!ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) &&	\
	ahci_portp->ahciport_pending_ncq_tags != 0)

/* Command type for ahci_claim_free_slot routine */
#define	AHCI_NON_NCQ_CMD	0x0
#define	AHCI_NCQ_CMD		0x1
#define	AHCI_ERR_RETRI_CMD	0x2
#define	AHCI_RDWR_PMULT_CMD	0x4

/* State values for ahci_attach */
#define	AHCI_ATTACH_STATE_NONE			(0x1 << 0)
#define	AHCI_ATTACH_STATE_STATEP_ALLOC		(0x1 << 1)
#define	AHCI_ATTACH_STATE_FMA			(0x1 << 2)
#define	AHCI_ATTACH_STATE_REG_MAP		(0x1 << 3)
#define	AHCI_ATTACH_STATE_PCICFG_SETUP		(0x1 << 4)
#define	AHCI_ATTACH_STATE_INTR_ADDED		(0x1 << 5)
#define	AHCI_ATTACH_STATE_MUTEX_INIT		(0x1 << 6)
#define	AHCI_ATTACH_STATE_PORT_ALLOC		(0x1 << 7)
#define	AHCI_ATTACH_STATE_HW_INIT		(0x1 << 8)
#define	AHCI_ATTACH_STATE_TIMEOUT_ENABLED	(0x1 << 9)
#define	AHCI_ATTACH_STATE_ENCLOSURE		(0x1 << 10)

/* Interval used for delay */
#define	AHCI_10MS_TICKS	(drv_usectohz(10000))	/* ticks in 10 ms */
#define	AHCI_1MS_TICKS	(drv_usectohz(1000))	/* ticks in 1 ms */
#define	AHCI_100US_TICKS	(drv_usectohz(100))	/* ticks in 100 us */
#define	AHCI_10MS_USECS		(10000)		/* microsecs in 10 millisec */
#define	AHCI_1MS_USECS		(1000)		/* microsecs in 1 millisec */
#define	AHCI_100US_USECS	(100)

/*
 * The following values are the numbers of times to retry polled requests.
 */
#define	AHCI_POLLRATE_HBA_RESET		100
#define	AHCI_POLLRATE_PORT_SSTATUS	10
#define	AHCI_POLLRATE_PORT_TFD_ERROR	1100
#define	AHCI_POLLRATE_PORT_IDLE		50
#define	AHCI_POLLRATE_PORT_SOFTRESET	100
#define	AHCI_POLLRATE_GET_SPKT		100
#define	AHCI_POLLRATE_PORT_IDLE_FR	500


/* Clearing & setting the n'th bit in a given tag */
#define	CLEAR_BIT(tag, bit)	(tag &= ~(0x1<<bit))
#define	SET_BIT(tag, bit)	(tag |= (0x1<<bit))


#if DEBUG

#define	AHCI_DEBUG		1

#endif

#define	AHCIDBG_INIT		0x0001
#define	AHCIDBG_ENTRY		0x0002
#define	AHCIDBG_PRDT		0x0004
#define	AHCIDBG_EVENT		0x0008
#define	AHCIDBG_POLL_LOOP	0x0010
#define	AHCIDBG_PKTCOMP		0x0020
#define	AHCIDBG_TIMEOUT		0x0040
#define	AHCIDBG_INFO		0x0080
#define	AHCIDBG_VERBOSE		0x0100
#define	AHCIDBG_INTR		0x0200
#define	AHCIDBG_ERRS		0x0400
#define	AHCIDBG_ATACMD		0x0800
#define	AHCIDBG_ATAPICMD	0x1000
#define	AHCIDBG_SENSEDATA	0x2000
#define	AHCIDBG_NCQ		0x4000
#define	AHCIDBG_PM		0x8000
#define	AHCIDBG_UNDERFLOW	0x10000
#define	AHCIDBG_MSI		0x20000
#define	AHCIDBG_PMULT		0x40000

extern uint32_t ahci_debug_flags;

#if DEBUG

#define	AHCIDBG(flag, ahci_ctlp, fmt, args ...)			\
	if (ahci_debug_flags & (flag)) {			\
		ahci_log(ahci_ctlp, CE_WARN, fmt, ## args);	\
		if (ahci_ctlp == NULL)				\
			sata_trace_debug(NULL, fmt, ## args);	\
		else						\
			sata_trace_debug(ahci_ctlp->ahcictl_dip,\
			    fmt, ## args);			\
	}

#else

#define	AHCIDBG(flag, ahci_ctlp, fmt, args ...)			\
	if (ahci_debug_flags & (flag)) {			\
		if (ahci_ctlp == NULL)				\
			sata_trace_debug(NULL, fmt, ## args);	\
		else						\
			sata_trace_debug(ahci_ctlp->ahcictl_dip,\
			    fmt, ## args);			\
	}

#endif /* DEBUG */

/*
 * Minimum size required for the enclosure message buffer. This value is in
 * 4-byte quantities. So we need to multiply it by two.
 */
#define	AHCI_EM_BUFFER_MIN	2

/*
 * Enclosure Management LED message format values
 */
#define	AHCI_LED_OFF	0
#define	AHCI_LED_ON	1

#define	AHCI_LED_ACTIVITY_OFF	0
#define	AHCI_LED_IDENT_OFF	3
#define	AHCI_LED_FAULT_OFF	6

#define	AHCI_LED_MASK	0x7

#define	AHCI_EM_MSG_TYPE_LED	0
#define	AHCI_EM_MSG_TYPE_SAFTE	1
#define	AHCI_EM_MSG_TYPE_SES	2
#define	AHCI_EM_MSG_TYPE_SGPIO	3

#pragma pack(1)
typedef struct ahci_em_led_msg {
	uint8_t		alm_hba;
	uint8_t		alm_pminfo;
	uint16_t	alm_value;
} ahci_em_led_msg_t;

typedef struct ahci_em_msg_hdr {
	uint8_t		aemh_rsvd;
	uint8_t		aemh_mlen;
	uint8_t		aemh_dlen;
	uint8_t		aemh_mtype;
} ahci_em_msg_hdr_t;
#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif /* _AHCIVAR_H */
