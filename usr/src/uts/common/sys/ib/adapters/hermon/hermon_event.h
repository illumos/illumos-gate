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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_EVENT_H
#define	_SYS_IB_ADAPTERS_HERMON_EVENT_H

/*
 * hermon_event.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Interrupt and Event Processing routines
 *    Specifically it contains the various event types, event flags,
 *    structures used for managing Hermon event queues, and prototypes for
 *    many of the functions consumed by other parts of the Hermon driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hermon UAR Doorbell Write Macro - writes UAR registers
 *
 * If on a 32-bit system, we must hold a lock around the ddi_put64() to
 * ensure that the 64-bit write is an atomic operation.  This is a
 * requirement of the Hermon hardware and is to protect from the race
 * condition present when more than one kernel thread attempts to do each
 * of their two 32-bit accesses (for 64-bit doorbell) simultaneously.
 *
 * If we are on a 64-bit system then the ddi_put64() is completed as one
 * 64-bit instruction, and the lock is not needed.
 *
 * This is done as a preprocessor #if to speed up execution at run-time
 * since doorbell ringing is a "fast-path" operation.
 */
#if (DATAMODEL_NATIVE == DATAMODEL_ILP32)
#define	HERMON_UAR_DOORBELL(state, uarhdl, hs_uar, doorbell)	{	\
	mutex_enter(&state->hs_uar_lock);				\
	ddi_put64(uarhdl, hs_uar, doorbell);				\
	mutex_exit(&state->hs_uar_lock);				\
}
#else
#define	HERMON_UAR_DOORBELL(state, uarhdl, hs_uar, doorbell)	{	\
	ddi_put64(uarhdl, hs_uar, doorbell);				\
}
#endif

/*
 * HERMON Doorbell Record (DBr) Write Macro - writes doorbell record in memory
 *
 * Since the DBr is only 32 bits at a time, this can be just a put32, not
 * put64.
 */

#define	HERMON_UAR_DB_RECORD_WRITE(db_addr, dbr)			\
	*(uint32_t *)(db_addr) = htonl(dbr)

/*
 * The following defines specify the default number of Event Queues (EQ) and
 * their default size.  By default the size of each EQ is set to 8K entries,
 * but this value is controllable through the "cp_log_eq_sz" configuration
 * variable.  We also specify the number of EQs which the Arbel driver
 * currently uses (HERMON_NUM_EQ_USED).  Note: this value should be less than
 * or equal to HERMON_NUM_EQ.
 * HERMON:  will limit to 4 total - in anticipation of VMM implementation
 *    logical Eq (0)-catastrophic,
 *		 (1)-error completions,
 *		 (2)-misc events and
 *		 (3)-completions
 */

#define	HERMON_NUM_EQ_SHIFT		0x9 /* hermon has 512 EQs available */
#define	HERMON_NUM_EQ			(1 << HERMON_NUM_EQ_SHIFT)

#define	HERMON_NUM_EQ_USED		4  		/* four per domain */
#define	HERMON_DEFAULT_EQ_SZ_SHIFT	0xd		/* 8192 entries/EQ */
#define	HERMON_EQ_CI_MASK		0xFFFFFF 	/* low 24 bits */

/*
 * These are the defines for the Hermon event types.  They are specified by
 * the Hermon PRM.  Below are the "event type masks" in
 * which each event type corresponds to one of the 64-bits in the mask.
 */

/* Note:  In order per PRM listing */
/* Completion Events */
#define	HERMON_EVT_COMPLETION			0x00
/* IB Affiliated Asynch Events */
#define	HERMON_EVT_PATH_MIGRATED		0x01
#define	HERMON_EVT_COMM_ESTABLISHED		0x02
#define	HERMON_EVT_SEND_QUEUE_DRAINED		0x03
#define	HERMON_EVT_SRQ_LAST_WQE_REACHED		0x13
#define	HERMON_EVT_SRQ_LIMIT			0x14
/* QP Affiliated Asynch Event */
#define	HERMON_EVT_CQ_ERRORS			0x04 /* overrun, protection */
#define	HERMON_EVT_LOCAL_WQ_CAT_ERROR		0x05
#define	HERMON_EVT_LOCAL_QPC_CAT_ERROR		0x06
#define	HERMON_EVT_PATH_MIGRATE_FAILED		0x07
#define	HERMON_EVT_INV_REQ_LOCAL_WQ_ERROR	0x10
#define	HERMON_EVT_LOCAL_ACC_VIO_WQ_ERROR	0x11
#define	HERMON_EVT_SRQ_CATASTROPHIC_ERROR	0x12
#define	HERMON_EVT_SPOOF_FAIL			0x16	/* enet only */
/* FEXCH Errors (QP Affiliated) */
#define	HERMON_EVT_FEXCH_ERROR			0x0B

/* Unaffiliated Asynch Events/Errors */
#define	HERMON_EVT_PORT_STATE_CHANGE		0x09
#define	HERMON_EVT_GPIO				0x15
/* Command Interface */
#define	HERMON_EVT_COMMAND_INTF_COMP		0x0A
/* Miscellaneous */
#define	HERMON_EVT_LOCAL_CAT_ERROR		0x08


#define	HERMON_EVT_MSK_COMPLETION		\
	(1 << HERMON_EVT_COMPLETION)

#define	HERMON_EVT_MSK_PATH_MIGRATED		\
	(1 << HERMON_EVT_PATH_MIGRATED)
#define	HERMON_EVT_MSK_COMM_ESTABLISHED		\
	(1 << HERMON_EVT_COMM_ESTABLISHED)
#define	HERMON_EVT_MSK_SEND_QUEUE_DRAINED	\
	(1 << HERMON_EVT_SEND_QUEUE_DRAINED)
#define	HERMON_EVT_MSK_SRQ_LAST_WQE_REACHED	\
	(1 << HERMON_EVT_SRQ_LAST_WQE_REACHED)
#define	HERMON_EVT_MSK_SRQ_LIMIT		\
	(1 << HERMON_EVT_SRQ_LIMIT)

#define	HERMON_EVT_MSK_CQ_ERRORS		\
	(1 << HERMON_EVT_CQ_ERRORS)
#define	HERMON_EVT_MSK_LOCAL_WQ_CAT_ERROR	\
	(1 << HERMON_EVT_LOCAL_WQ_CAT_ERROR)
#define	HERMON_EVT_MSK_LOCAL_QPC_CAT_ERROR	\
	(1 << HERMON_EVT_LOCAL_QPC_CAT_ERROR)
#define	HERMON_EVT_MSK_PATH_MIGRATE_FAILED	\
	(1 << HERMON_EVT_PATH_MIGRATE_FAILED)
#define	HERMON_EVT_MSK_INV_REQ_LOCAL_WQ_ERROR	\
	(1 << HERMON_EVT_INV_REQ_LOCAL_WQ_ERROR)
#define	HERMON_EVT_MSK_LOCAL_ACC_VIO_WQ_ERROR	\
	(1 << HERMON_EVT_LOCAL_ACC_VIO_WQ_ERROR)
#define	HERMON_EVT_MSK_SRQ_CATASTROPHIC_ERROR	\
	(1 << HERMON_EVT_SRQ_CATASTROPHIC_ERROR)
#define	HERMON_EVT_MSK_SPOOF_FAIL		\
	(1 << HERMON_EVT_SPOOF_FAIL)

#define	HERMON_EVT_MSK_FEXCH_ERROR		\
	(1 << HERMON_EVT_FEXCH_ERROR)

#define	HERMON_EVT_MSK_PORT_STATE_CHANGE	\
	(1 << HERMON_EVT_PORT_STATE_CHANGE)
#define	HERMON_EVT_MSK_GPIO			\
	(1 << HERMON_EVT_GPIO)

#define	HERMON_EVT_MSK_COMMAND_INTF_COMP	\
	(1 << HERMON_EVT_COMMAND_INTF_COMP)

#define	HERMON_EVT_MSK_LOCAL_CAT_ERROR		\
	(1 << HERMON_EVT_LOCAL_CAT_ERROR)


#define	HERMON_EVT_NO_MASK			0

/* For now, "catchall" is just HERMON_EVT_LOCAL_QPC_CAT_ERROR. */
#define	HERMON_EVT_CATCHALL_MASK		0x0040

/*
 * The last defines are used by hermon_eqe_sync() to indicate whether or not
 * to force a DMA sync.  The case for forcing a DMA sync on a EQE comes from
 * the possibility that we could receive an interrupt, read of the ECR, and
 * have each of these operations complete successfully _before_ the hardware
 * has finished its DMA to the event queue.
 */
#define	HERMON_EQ_SYNC_NORMAL			0x0
#define	HERMON_EQ_SYNC_FORCE			0x1

/*
 * Catastrophic error values.  In case of a catastrophic error, the following
 * errors are reported in a special buffer space.  The buffer location is
 * returned from a QUERY_FW command.  We check that buffer against these error
 * values to determine what kind of error occurred.
 */
#define	HERMON_CATASTROPHIC_INTERNAL_ERROR		0x0
#define	HERMON_CATASTROPHIC_UPLINK_BUS_ERROR	0x3
#define	HERMON_CATASTROPHIC_INTERNAL_PARITY_ERROR	0x5
/* Presumably, this is no longer supported */
#define	HERMON_CATASTROPHIC_DDR_DATA_ERROR		0x4

/*
 * This define is the 'enable' flag used when programming the MSI number
 * into event queues.  It is or'd with the MSI number and the result is
 * written into the EX context.
 */

#define	HERMON_EQ_MSI_ENABLE_FLAG	0x200  /* bit 9 of 0x14 in EQC */

/*
 * The following#defines are for the EQ's in the UAR pages.  In Hermon, the
 * arm mechanism is new - in the first 128 (that is, 0 - 127) UAR pages, which
 * are reserved, the only useful thing is the EQ registers.  In turn those
 * locations are ignored in any other UAR page.
 *
 * The driver writes to the with the MSB bit set to arm it, and the current
 * CI (consumer index).
 */
#define	G_EQ0		0x0800
#define	G_EQ1		0x0808
#define	G_EQ2		0x0810
#define	G_EQ3		0x0818

/*
 * They should be written as a 32-bit entity:
 * bit 31:  Arm (if set)
 * bit 23:0 Consumer Index
 */
#define	EQ_ARM_BIT	0x80000000

/*
 * The register to be written is:
 * 	(EQ_num / 4) == UAR page
 *	(EQ_NUM % 4) == G_EQx
 */

#define	ARM_EQ_INDEX(eq) \
	(((eq >> 2) * PAGESIZE) + (0x0800 + ((eq & 0x03) * 0x08)))


/*
 * The hermon_sw_eq_s structure is also referred to using the "hermon_eqhdl_t"
 * typedef (see hermon_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, poll, and
 * (later) free an event queue (EQ).
 *
 * Specifically, it has a consumer index and a lock to ensure single threaded
 * access to it.  It has pointers to the various resources allocated for the
 * event queue, i.e. an EQC resource and the memory for the event queue
 * itself.  It has flags to indicate which type of event class(es) the EQ
 * has been mapped to (eq_evttypemask).
 *
 * It also has a pointer to the associated MR handle (for the mapped queue
 * memory) and a function pointer that points to the handler that should
 * be called when the corresponding EQ has fired.  Note: the "eq_func"
 * handler takes a Hermon softstate pointer, a pointer to the EQ handle, and a
 * pointer to a generic hermon_hw_eqe_t structure.  It is up to the "eq_func"
 * handler function to determine what specific type of event is being passed.
 *
 * Lastly, we have the always necessary backpointer to the resource for the
 * EQ handle structure itself.
 */
struct hermon_sw_eq_s {
	uint32_t		eq_consindx;
	uint32_t		eq_eqnum;
	hermon_hw_eqe_t		*eq_buf;
	uint32_t		*eq_doorbell;
	hermon_mrhdl_t		eq_mrhdl;
	uint32_t		eq_bufsz;
	uint32_t		eq_log_eqsz;
	uint_t			eq_evttypemask;
	hermon_rsrc_t		*eq_eqcrsrcp;
	hermon_rsrc_t		*eq_rsrcp;
	int (*eq_func)(hermon_state_t *state, hermon_eqhdl_t eq,
	    hermon_hw_eqe_t *eqe);

	struct hermon_qalloc_info_s eq_eqinfo;
};

int hermon_eq_init_all(hermon_state_t *state);
int hermon_eq_fini_all(hermon_state_t *state);
int hermon_eq_arm_all(hermon_state_t *state);
uint_t hermon_isr(caddr_t arg1, caddr_t arg2);
void hermon_eq_doorbell(hermon_state_t *state, uint32_t eq_cmd, uint32_t eqn,
    uint32_t eq_param);
void hermon_eq_overflow_handler(hermon_state_t *state, hermon_eqhdl_t eq,
    hermon_hw_eqe_t *eqe);
void hermon_eq_reset_uar_baseaddr(hermon_state_t *state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_EVENT_H */
