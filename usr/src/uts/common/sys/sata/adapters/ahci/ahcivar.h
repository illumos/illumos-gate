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


#ifndef _AHCIVAR_H
#define	_AHCIVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Type for argument of event handler */
typedef	struct ahci_event_arg {
	void		*ahciea_ctlp;
	void		*ahciea_portp;
	uint32_t	ahciea_event;
} ahci_event_arg_t;

/* Warlock annotation */
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_ctlp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_portp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ahci_event_arg_t::ahciea_event))

/*
 * flags for ahciport_flags
 *
 * AHCI_PORT_FLAG_SPINUP: this flag will be set when a HBA which supports
 * staggered spin-up needs to do a spin-up.
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
 */
#define	AHCI_PORT_FLAG_SPINUP	0x01
#define	AHCI_PORT_FLAG_MOPPING	0x02
#define	AHCI_PORT_FLAG_POLLING	0x04
#define	AHCI_PORT_FLAG_RQSENSE	0x08
#define	AHCI_PORT_FLAG_STARTED	0x10
#define	AHCI_PORT_FLAG_RDLOGEXT	0x20
#define	AHCI_PORT_FLAG_NODEV	0x40

typedef struct ahci_port {
	/* The physical port number */
	uint8_t			ahciport_port_num;

	/* Type of the device attached to the port */
	uint8_t			ahciport_device_type;
	/* State of the port */
	uint32_t		ahciport_port_state;

	/*
	 * AHCI_PORT_FLAG_SPINUP
	 * AHCI_PORT_FLAG_MOPPING
	 * AHCI_PORT_FLAG_POLLING
	 * AHCI_PORT_FLAG_RQSENSE
	 * AHCI_PORT_FLAG_STARTED
	 * AHCI_PORT_FLAG_RDLOGEXT
	 * AHCI_PORT_FLAG_NODEV
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

	/* Keep the error retrieval sata packet */
	sata_pkt_t		*ahciport_err_retri_pkt;

	/*
	 * SATA HBA driver is supposed to remember and maintain device
	 * reset state. While the reset is in progress, it doesn't accept
	 * any more commands until receiving the command with
	 * SATA_CLEAR_DEV_RESET_STATE flag and SATA_IGNORE_DEV_RESET_STATE.
	 */
	int			ahciport_reset_in_progress;

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
				    ahci_port_t::ahciport_reset_in_progress))
_NOTE(MUTEX_PROTECTS_DATA(ahci_port_t::ahciport_mutex,
				    ahci_port_t::ahciport_mop_in_progress))

typedef struct ahci_ctl {
	dev_info_t		*ahcictl_dip;
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

	/* Taskq for handling event */
	ddi_taskq_t		*ahcictl_event_taskq;
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

/* Flags controlling the restart port behavior */
#define	AHCI_PORT_RESET		0x0001	/* Reset the port */
#define	AHCI_PORT_INIT		0x0002	/* Initialize port */
#define	AHCI_RESET_NO_EVENTS_UP	0x0004	/* Don't send reset events up */

#define	ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)		\
	(ahci_portp->ahciport_flags &			\
	(AHCI_PORT_FLAG_RQSENSE|AHCI_PORT_FLAG_RDLOGEXT))

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

/* State values for ahci_attach */
#define	AHCI_ATTACH_STATE_NONE			(0x1 << 0)
#define	AHCI_ATTACH_STATE_STATEP_ALLOC		(0x1 << 1)
#define	AHCI_ATTACH_STATE_REG_MAP		(0x1 << 2)
#define	AHCI_ATTACH_STATE_PCICFG_SETUP		(0x1 << 3)
#define	AHCI_ATTACH_STATE_INTR_ADDED		(0x1 << 4)
#define	AHCI_ATTACH_STATE_MUTEX_INIT		(0x1 << 5)
#define	AHCI_ATTACH_STATE_PORT_ALLOC		(0x1 << 6)
#define	AHCI_ATTACH_STATE_ERR_RECV_TASKQ	(0x1 << 7)
#define	AHCI_ATTACH_STATE_HW_INIT		(0x1 << 8)
#define	AHCI_ATTACH_STATE_TIMEOUT_ENABLED	(0x1 << 9)

/* Interval used for delay */
#define	AHCI_10MS_TICKS	(drv_usectohz(10000))	/* ticks in 10 millisec */
#define	AHCI_1MS_TICKS	(drv_usectohz(1000))	/* ticks in 1 millisec */
#define	AHCI_100US_TICKS	(drv_usectohz(100))	/* ticks in 100  */
#define	AHCI_1MS_USECS	(1000)			/* usecs in 1 millisec */

/*
 * The following values are the numbers of times to retry polled requests.
 */
#define	AHCI_POLLRATE_HBA_RESET		100
#define	AHCI_POLLRATE_PORT_SSTATUS	10
#define	AHCI_POLLRATE_PORT_TFD_ERROR	1100
#define	AHCI_POLLRATE_PORT_IDLE		50
#define	AHCI_POLLRATE_PORT_SOFTRESET	100
#define	AHCI_POLLRATE_GET_SPKT		100


/* Clearing & setting the n'th bit in a given tag */
#define	CLEAR_BIT(tag, bit)	(tag &= ~(0x1<<bit))
#define	SET_BIT(tag, bit)	(tag |= (0x1<<bit))


#if DEBUG

#define	AHCI_DEBUG		1

#define	AHCIDBG_INIT		0x0001
#define	AHCIDBG_ENTRY		0x0002
#define	AHCIDBG_DUMP_PRB	0x0004
#define	AHCIDBG_EVENT		0x0008
#define	AHCIDBG_POLL_LOOP	0x0010
#define	AHCIDBG_PKTCOMP		0x0020
#define	AHCIDBG_TIMEOUT		0x0040
#define	AHCIDBG_INFO		0x0080
#define	AHCIDBG_VERBOSE		0x0100
#define	AHCIDBG_INTR		0x0200
#define	AHCIDBG_ERRS		0x0400
#define	AHCIDBG_COOKIES		0x0800
#define	AHCIDBG_POWER		0x1000
#define	AHCIDBG_COMMAND		0x2000
#define	AHCIDBG_SENSEDATA	0x4000
#define	AHCIDBG_NCQ		0x8000
#define	AHCIDBG_PM		0x10000

extern int ahci_debug_flag;

#define	AHCIDBG0(flag, ahci_ctlp, format)			\
	if (ahci_debug_flags & (flag)) {			\
		ahci_log(ahci_ctlp, CE_WARN, format);		\
	}

#define	AHCIDBG1(flag, ahci_ctlp, format, arg1)			\
	if (ahci_debug_flags & (flag)) {			\
		ahci_log(ahci_ctlp, CE_WARN, format, arg1);	\
	}

#define	AHCIDBG2(flag, ahci_ctlp, format, arg1, arg2)			\
	if (ahci_debug_flags & (flag)) {				\
		ahci_log(ahci_ctlp, CE_WARN, format, arg1, arg2);	\
	}

#define	AHCIDBG3(flag, ahci_ctlp, format, arg1, arg2, arg3)		\
	if (ahci_debug_flags & (flag)) {				\
		ahci_log(ahci_ctlp, CE_WARN, format, arg1, arg2, arg3); \
	}

#define	AHCIDBG4(flag, ahci_ctlp, format, arg1, arg2, arg3, arg4)	\
	if (ahci_debug_flags & (flag)) {				\
		ahci_log(ahci_ctlp, CE_WARN, format, arg1, arg2, arg3, arg4); \
	}

#define	AHCIDBG5(flag, ahci_ctlp, format, arg1, arg2, arg3, arg4, arg5)	\
	if (ahci_debug_flags & (flag)) {				\
		ahci_log(ahci_ctlp, CE_WARN, format, arg1, arg2,	\
		    arg3, arg4, arg5); 					\
	}
#else

#define	AHCIDBG0(flag, dip, frmt)
#define	AHCIDBG1(flag, dip, frmt, arg1)
#define	AHCIDBG2(flag, dip, frmt, arg1, arg2)
#define	AHCIDBG3(flag, dip, frmt, arg1, arg2, arg3)
#define	AHCIDBG4(flag, dip, frmt, arg1, arg2, arg3, arg4)
#define	AHCIDBG5(flag, dip, frmt, arg1, arg2, arg3, arg4, arg5)

#endif /* DEBUG */


#ifdef	__cplusplus
}
#endif

#endif /* _AHCIVAR_H */
