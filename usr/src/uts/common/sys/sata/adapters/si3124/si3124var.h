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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SI3124VAR_H
#define	_SI3124VAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SI3124_MAX_PORTS		4
#define	SI3132_MAX_PORTS		2
#define	SI_MAX_PORTS			SI3124_MAX_PORTS

#define	SI_SUCCESS			(0)	/* successful return */
#define	SI_TIMEOUT			(1)	/* timed out */
#define	SI_FAILURE			(-1)	/* unsuccessful return */

#define	SI_MAX_SGT_TABLES_PER_PRB	10

/*
 * While the si_sge_t and si_sgt_t correspond to the actual SGE and SGT
 * definitions as per the datasheet, the si_sgblock_t (i.e scatter gather
 * block) is a logical data structure which holds multiple SGT tables.
 * The idea is to use multiple chained SGT tables per each PRB request.
 */

typedef struct si_sgblock {
	si_sgt_t sgb_sgt[SI_MAX_SGT_TABLES_PER_PRB];
} si_sgblock_t;

/*
 * Each SGT (Scatter Gather Table) has 4 SGEs (Scatter Gather Entries).
 * But each SGT effectively can host only 3 SGEs since the last SGE entry
 * is used to hold a link to the next SGT in the chain. However the last
 * SGT in the chain can host all the 4 entries since it does not need to
 * link any more.
 */
#define	SI_MAX_SGL_LENGTH	(3*SI_MAX_SGT_TABLES_PER_PRB)+1

typedef struct si_portmult_state {
	int sipm_num_ports;
	uint8_t sipm_port_type[15];
	/* one of PORT_TYPE_[NODEV | MULTIPLIER | ATAPI | DISK | UNKNOWN] */

	/*
	 * sipm_port_type[] is good enough to capture the state of ports
	 * behind the multiplier. Since any of the port behind a multiplier
	 * is accessed through the same main controller port, we don't need
	 * additional si_port_state_t here.
	 */

} si_portmult_state_t;


/* The following are for port types */
#define	PORT_TYPE_NODEV		0x0
#define	PORT_TYPE_MULTIPLIER	0x1
#define	PORT_TYPE_ATAPI		0x2
#define	PORT_TYPE_DISK		0x3
#define	PORT_TYPE_UNKNOWN	0x4

/* The following are for active state */
#define	PORT_INACTIVE		0x0
#define	PORT_ACTIVE		0x1

typedef struct si_port_state {
	uint8_t siport_port_type;
	/* one of PORT_TYPE_[NODEV | MULTIPLIER | ATAPI | DISK | UNKNOWN] */

	uint8_t siport_active;		/* one of ACTIVE or INACTIVE */

	si_portmult_state_t siport_portmult_state;

	si_prb_t *siport_prbpool; 	/* These are 31 incore PRBs */
	uint64_t siport_prbpool_physaddr;
	ddi_dma_handle_t siport_prbpool_dma_handle;
	ddi_acc_handle_t siport_prbpool_acc_handle;


	si_sgblock_t *siport_sgbpool; 	/* These are 31 incore sg blocks */
	uint64_t siport_sgbpool_physaddr;
	ddi_dma_handle_t siport_sgbpool_dma_handle;
	ddi_acc_handle_t siport_sgbpool_acc_handle;

	kmutex_t siport_mutex; 		/* main per port mutex */
	uint32_t siport_pending_tags;	/* remembers the pending tags */
	sata_pkt_t *siport_slot_pkts[SI_NUM_SLOTS];

	/*
	 * While the reset is in progress, we don't accept any more commands
	 * until we receive the command with SATA_CLEAR_DEV_RESET_STATE flag.
	 * However any commands with SATA_IGNORE_DEV_RESET_STATE are allowed in
	 * during such blockage.
	 */
	int siport_reset_in_progress;

	/*
	 * We mop the commands for either abort, reset, timeout or
	 * error handling cases. This counts how many mops are in progress.
	 * It is also used to return BUSY in tran_start if a mop is going on.
	 */
	int mopping_in_progress;

	/* error recovery related info */
	uint32_t siport_err_tags_SDBERROR;
	uint32_t siport_err_tags_nonSDBERROR;
	int siport_pending_ncq_count;

} si_port_state_t;

/* Warlock annotation */
_NOTE(MUTEX_PROTECTS_DATA(si_port_state_t::siport_mutex, si_port_state_t))
_NOTE(READ_ONLY_DATA(si_port_state_t::siport_prbpool_dma_handle))
_NOTE(READ_ONLY_DATA(si_port_state_t::siport_sgbpool_dma_handle))


typedef struct si_ctl_state {

	dev_info_t *sictl_devinfop;

	int sictl_num_ports;	/* number of controller ports */
	si_port_state_t *sictl_ports[SI_MAX_PORTS];

	int sictl_devid; /* whether it is 3124 or 3132 */
	int sictl_flags; /* some important state of controller */
	int sictl_power_level;

	/* pci config space handle */
	ddi_acc_handle_t sictl_pci_conf_handle;

	/* mapping into bar 0 */
	ddi_acc_handle_t sictl_global_acc_handle;
	uintptr_t sictl_global_addr;

	/* mapping into bar 1 */
	ddi_acc_handle_t sictl_port_acc_handle;
	uintptr_t sictl_port_addr;

	struct sata_hba_tran *sictl_sata_hba_tran;
	timeout_id_t sictl_timeout_id;

	kmutex_t sictl_mutex; 			/* per controller mutex */

	ddi_intr_handle_t *sictl_htable;	/* For array of interrupts */
	int sictl_intr_type;			/* What type of interrupt */
	int sictl_intr_cnt;			/* # of intrs count returned */
	size_t sictl_intr_size;			/* Size of intr array */
	uint_t sictl_intr_pri;			/* Interrupt priority */
	int sictl_intr_cap;			/* Interrupt capabilities */

} si_ctl_state_t;

/* Warlock annotation */
_NOTE(MUTEX_PROTECTS_DATA(si_ctl_state_t::sictl_mutex,
					si_ctl_state_t::sictl_ports))
_NOTE(MUTEX_PROTECTS_DATA(si_ctl_state_t::sictl_mutex,
					si_ctl_state_t::sictl_power_level))
_NOTE(MUTEX_PROTECTS_DATA(si_ctl_state_t::sictl_mutex,
					si_ctl_state_t::sictl_flags))
_NOTE(MUTEX_PROTECTS_DATA(si_ctl_state_t::sictl_mutex,
					si_ctl_state_t::sictl_timeout_id))
/*
 * flags for si_flags
 */
#define	SI_PM			0x01
#define	SI_ATTACH		0x02
#define	SI_DETACH		0x04
#define	SI_NO_TIMEOUTS		0x08
#define	SI_FRAMEWORK_ATTACHED	0x10	/* are we attached to framework ? */

/* progress values for si_attach */
#define	ATTACH_PROGRESS_NONE			(1<<0)
#define	ATTACH_PROGRESS_STATEP_ALLOC		(1<<1)
#define	ATTACH_PROGRESS_CONF_HANDLE		(1<<2)
#define	ATTACH_PROGRESS_BAR0_MAP		(1<<3)
#define	ATTACH_PROGRESS_BAR1_MAP		(1<<4)
#define	ATTACH_PROGRESS_INTR_ADDED		(1<<5)
#define	ATTACH_PROGRESS_MUTEX_INIT		(1<<6)
#define	ATTACH_PROGRESS_HW_INIT			(1<<7)

#define	SI_10MS_TICKS	(drv_usectohz(10000))	/* ticks in 10 millisec */
#define	SI_1MS_TICKS	(drv_usectohz(1000))	/* ticks in 1 millisec */
#define	SI_1MS_USECS	(1000)			/* usecs in 1 millisec */
#define	SI_POLLRATE_SOFT_RESET		1000
#define	SI_POLLRATE_SSTATUS		10
#define	SI_POLLRATE_PORTREADY		50
#define	SI_POLLRATE_SLOTSTATUS		50
#define	SI_POLLRATE_RECOVERPORTMULT	1000

#define	PORTMULT_CONTROL_PORT		0xf

/* clearing & setting the n'th bit in a given tag */
#define	CLEAR_BIT(tag, bit)	(tag &= ~(0x1<<bit))
#define	SET_BIT(tag, bit)	(tag |= (0x1<<bit))

#if DEBUG

#define	SI_DEBUG	1

#define	SIDBG_TEST	0x0001
#define	SIDBG_INIT	0x0002
#define	SIDBG_ENTRY	0x0004
#define	SIDBG_DUMP_PRB	0x0008
#define	SIDBG_EVENT	0x0010
#define	SIDBG_POLL_LOOP	0x0020
#define	SIDBG_PKTCOMP	0x0040
#define	SIDBG_TIMEOUT	0x0080
#define	SIDBG_INFO	0x0100
#define	SIDBG_VERBOSE	0x0200
#define	SIDBG_INTR	0x0400
#define	SIDBG_ERRS	0x0800
#define	SIDBG_COOKIES	0x1000
#define	SIDBG_POWER	0x2000

extern int si_debug_flag;

#define	SIDBG0(flag, softp, format) \
	if (si_debug_flags & (flag)) { \
		si_log(softp, CE_WARN, format); \
	}

#define	SIDBG1(flag, softp, format, arg1) \
	if (si_debug_flags & (flag)) { \
		si_log(softp, CE_WARN, format, arg1); \
	}

#define	SIDBG2(flag, softp, format, arg1, arg2) \
	if (si_debug_flags & (flag)) { \
		si_log(softp, CE_WARN, format, arg1, arg2); \
	}

#define	SIDBG3(flag, softp, format, arg1, arg2, arg3) \
	if (si_debug_flags & (flag)) { \
		si_log(softp, CE_WARN, format, arg1, arg2, arg3); \
	}

#define	SIDBG4(flag, softp, format, arg1, arg2, arg3, arg4) \
	if (si_debug_flags & (flag)) { \
		si_log(softp, CE_WARN, format, arg1, arg2, arg3, arg4); \
	}
#else

#define	SIDBG0(flag, dip, frmt)
#define	SIDBG1(flag, dip, frmt, arg1)
#define	SIDBG2(flag, dip, frmt, arg1, arg2)
#define	SIDBG3(flag, dip, frmt, arg1, arg2, arg3)
#define	SIDBG4(flag, dip, frmt, arg1, arg2, arg3, arg4)

#endif /* DEBUG */

/* Flags controlling the reset behavior */
#define	SI_PORT_RESET		0x1	/* Reset the port */
#define	SI_DEVICE_RESET		0x2	/* Reset the device, not the port */
#define	SI_RESET_NO_EVENTS_UP	0x4	/* Don't send reset events up */

#ifdef	__cplusplus
}
#endif

#endif /* _SI3124VAR_H */
