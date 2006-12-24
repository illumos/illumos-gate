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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _AHCIVAR_H
#define	_AHCIVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ahci_port {
	/* The physical port number - for debug message */
	uint8_t			ahciport_port_num;
	/* Type of the device attached to the port */
	uint8_t			ahciport_device_type;
	/* State of the port */
	uint32_t		ahciport_port_state;
	/* Only used for staggered spin-up */
	int			ahciport_flags;

	/* Pointer to received FIS structure */
	ahci_rcvd_fis_t		*ahciport_rcvd_fis;
	ddi_dma_handle_t	ahciport_rcvd_fis_dma_handle;
	ddi_acc_handle_t	ahciport_rcvd_fis_acc_handle;

	/* Pointer to command list structure */
	ahci_cmd_header_t	*ahciport_cmd_list;
	ddi_dma_handle_t	ahciport_cmd_list_dma_handle;
	ddi_acc_handle_t	ahciport_cmd_list_acc_handle;

	/* Pointer to cmmand table structure */
	ahci_cmd_table_t	\
			*ahciport_cmd_tables[AHCI_PORT_MAX_CMD_SLOTS];
	ddi_dma_handle_t	\
			ahciport_cmd_tables_dma_handle[AHCI_PORT_MAX_CMD_SLOTS];
	ddi_acc_handle_t	\
			ahciport_cmd_tables_acc_handle[AHCI_PORT_MAX_CMD_SLOTS];

	kmutex_t		ahciport_mutex;
	uint32_t		ahciport_pending_tags;
	sata_pkt_t		*ahciport_slot_pkts[AHCI_PORT_MAX_CMD_SLOTS];

	/*
	 * SATA HBA driver is supposed to remember and maintain device
	 * reset state. While the reset is in progress, it doesn't accept
	 * any more commands until receiving the command with
	 * SATA_CLEAR_DEV_RESET_STATE flag and SATA_IGNORE_DEV_RESET_STATE.
	 */
	int			ahciport_reset_in_progress;

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

/* Port flags */
#define	AHCI_PORT_STATE_SPINUP	0x1
#define	AHCI_PORT_STATE_MOPPING	0x2

/* Flags for ahcictl_flags */
#define	AHCI_PM			0x1
#define	AHCI_ATTACH		0x2
#define	AHCI_DETACH		0x4
/* PIO Multiple DRQ Block */
#define	AHCI_PMD		0x8


/* Flags controlling the reset behavior */
#define	AHCI_PORT_RESET		0x0001	/* Reset the port */
#define	AHCI_PORT_INIT		0x0002	/* Initialize port */
#define	AHCI_RESET_NO_EVENTS_UP	0x0004	/* Don't send reset events up */


/* State values for ahci_attach */
#define	AHCI_ATTACH_STATE_NONE			(0x1 << 0)
#define	AHCI_ATTACH_STATE_STATEP_ALLOC		(0x1 << 1)
#define	AHCI_ATTACH_STATE_REG_MAP		(0x1 << 2)
#define	AHCI_ATTACH_STATE_INTR_ADDED		(0x1 << 3)
#define	AHCI_ATTACH_STATE_MUTEX_INIT		(0x1 << 4)
#define	AHCI_ATTACH_STATE_HW_INIT		(0x1 << 5)
#define	AHCI_ATTACH_STATE_TIMEOUT_ENABLED	(0x1 << 6)

/* Interval used for delay */
#define	AHCI_10MS_TICKS	(drv_usectohz(10000))	/* ticks in 10 millisec */
#define	AHCI_1MS_TICKS	(drv_usectohz(1000))	/* ticks in 1 millisec */
#define	AHCI_1MS_USECS	(1000)			/* usecs in 1 millisec */

/*
 * The following values are the numbers of times to retry polled requests.
 */
#define	AHCI_POLLRATE_HBA_RESET		100
#define	AHCI_POLLRATE_PORT_COMRESET	10
#define	AHCI_POLLRATE_PORT_SSTATUS	10
#define	AHCI_POLLRATE_PORT_TFD_BSY	1100
#define	AHCI_POLLRATE_PORT_TFD_ERROR	10
#define	AHCI_POLLRATE_PORT_IDLE		50
#define	AHCI_POLLRATE_PORT_SOFTRESET	100


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

#else

#define	AHCIDBG0(flag, dip, frmt)
#define	AHCIDBG1(flag, dip, frmt, arg1)
#define	AHCIDBG2(flag, dip, frmt, arg1, arg2)
#define	AHCIDBG3(flag, dip, frmt, arg1, arg2, arg3)
#define	AHCIDBG4(flag, dip, frmt, arg1, arg2, arg3, arg4)

#endif /* DEBUG */


#ifdef	__cplusplus
}
#endif

#endif /* _AHCIVAR_H */
