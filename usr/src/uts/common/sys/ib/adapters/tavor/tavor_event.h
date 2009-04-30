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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_EVENT_H
#define	_SYS_IB_ADAPTERS_TAVOR_EVENT_H

/*
 * tavor_event.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Interrupt and Event Processing routines
 *    Specifically it contains the various event types, event flags,
 *    structures used for managing Tavor event queues, and prototypes for
 *    many of the functions consumed by other parts of the Tavor driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tavor UAR Doorbell Write Macro
 *
 * If on a 32-bit system, we must hold a lock around the ddi_put64() to
 * ensure that the 64-bit write is an atomic operation.  This is a
 * requirement of the Tavor hardware and is to protect from the race
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
#define	TAVOR_UAR_DOORBELL(state, ts_uar, doorbell)		{	\
	mutex_enter(&state->ts_uar_lock);				\
	ddi_put64(state->ts_reg_uarhdl, ts_uar, doorbell);		\
	mutex_exit(&state->ts_uar_lock);				\
}
#else
#define	TAVOR_UAR_DOORBELL(state, ts_uar, doorbell)		{	\
	ddi_put64(state->ts_reg_uarhdl, ts_uar, doorbell);		\
}
#endif

/*
 * The following defines specify the default number of Event Queues (EQ) and
 * their default size.  By default the size of each EQ is set to 4K entries,
 * but this value is controllable through the "log_default_eq_sz"
 * configuration variable.  We also specify the number of EQs which the Tavor
 * driver currently uses (TAVOR_NUM_EQ_USED).  Note: this value should be
 * less than or equal to TAVOR_NUM_EQ.  Because there are only so many classes
 * of events today, it is unnecessary to allocate all 64 EQs only to leave
 * several of them unused.
 */
#define	TAVOR_NUM_EQ_SHIFT			0x6
#define	TAVOR_NUM_EQ				(1 << TAVOR_NUM_EQ_SHIFT)
#define	TAVOR_NUM_EQ_USED			47
#define	TAVOR_DEFAULT_EQ_SZ_SHIFT		0xC

/*
 * The following macro determines whether the contents of EQ memory (EQEs)
 * need to be sync'd (with ddi_dma_sync()).  This decision is based on whether
 * the EQ memory is in DDR memory (no sync) or system memory (sync required).
 * Note: It doesn't make much sense to put EQEs in DDR memory (since they are
 * primarily written by HW and read by the CPU), but the driver does support
 * that possibility.  And it also supports the possibility that if a CQ in
 * system memory is mapped DDI_DMA_CONSISTENT, it can be configured to not be
 * sync'd because of the "sync override" parameter in the config profile.
 */
#define	TAVOR_EQ_IS_SYNC_REQ(state, eqinfo)				\
	((((((state)->ts_cfg_profile->cp_streaming_consistent) &&	\
	((state)->ts_cfg_profile->cp_consistent_syncoverride))) ||      \
	((eqinfo).qa_location == TAVOR_QUEUE_LOCATION_INDDR))	\
	? 0 : 1)

/*
 * The following defines specify the size of the individual Event Queue
 * Context (EQC) entries
 */
#define	TAVOR_EQC_SIZE_SHIFT			0x6
#define	TAVOR_EQC_SIZE				(1 << TAVOR_EQC_SIZE_SHIFT)

/*
 * These are the defines for the Tavor event types.  They are specified by
 * the Tavor register specification.  Below are the "event type masks" in
 * which each event type corresponds to one of the 64-bits in the mask.
 */
#define	TAVOR_EVT_COMPLETION			0x00
#define	TAVOR_EVT_PATH_MIGRATED			0x01
#define	TAVOR_EVT_COMM_ESTABLISHED		0x02
#define	TAVOR_EVT_SEND_QUEUE_DRAINED		0x03
#define	TAVOR_EVT_CQ_ERRORS			0x04
#define	TAVOR_EVT_LOCAL_WQ_CAT_ERROR		0x05
#define	TAVOR_EVT_LOCAL_EEC_CAT_ERROR		0x06	/* unsupported: RD */
#define	TAVOR_EVT_PATH_MIGRATE_FAILED		0x07
#define	TAVOR_EVT_LOCAL_CAT_ERROR		0x08
#define	TAVOR_EVT_PORT_STATE_CHANGE		0x09
#define	TAVOR_EVT_COMMAND_INTF_COMP		0x0A
#define	TAVOR_EVT_WQE_PG_FAULT			0x0B
#define	TAVOR_EVT_UNSUPPORTED_PG_FAULT		0x0C
#define	TAVOR_EVT_ECC_DETECTION			0x0E
#define	TAVOR_EVT_EQ_OVERFLOW			0x0F
#define	TAVOR_EVT_INV_REQ_LOCAL_WQ_ERROR	0x10
#define	TAVOR_EVT_LOCAL_ACC_VIO_WQ_ERROR	0x11
#define	TAVOR_EVT_SRQ_CATASTROPHIC_ERROR	0x12
#define	TAVOR_EVT_SRQ_LAST_WQE_REACHED		0x13

#define	TAVOR_EVT_MSK_COMPLETION		\
	(1 << TAVOR_EVT_COMPLETION)
#define	TAVOR_EVT_MSK_PATH_MIGRATED		\
	(1 << TAVOR_EVT_PATH_MIGRATED)
#define	TAVOR_EVT_MSK_COMM_ESTABLISHED		\
	(1 << TAVOR_EVT_COMM_ESTABLISHED)
#define	TAVOR_EVT_MSK_SEND_QUEUE_DRAINED	\
	(1 << TAVOR_EVT_SEND_QUEUE_DRAINED)
#define	TAVOR_EVT_MSK_CQ_ERRORS			\
	(1 << TAVOR_EVT_CQ_ERRORS)
#define	TAVOR_EVT_MSK_LOCAL_WQ_CAT_ERROR	\
	(1 << TAVOR_EVT_LOCAL_WQ_CAT_ERROR)
#define	TAVOR_EVT_MSK_LOCAL_EEC_CAT_ERROR	\
	(1 << TAVOR_EVT_LOCAL_EEC_CAT_ERROR)		/* unsupported: RD */
#define	TAVOR_EVT_MSK_PATH_MIGRATE_FAILED	\
	(1 << TAVOR_EVT_PATH_MIGRATE_FAILED)
#define	TAVOR_EVT_MSK_LOCAL_CAT_ERROR		\
	(1 << TAVOR_EVT_LOCAL_CAT_ERROR)
#define	TAVOR_EVT_MSK_PORT_STATE_CHANGE		\
	(1 << TAVOR_EVT_PORT_STATE_CHANGE)
#define	TAVOR_EVT_MSK_COMMAND_INTF_COMP		\
	(1 << TAVOR_EVT_COMMAND_INTF_COMP)
#define	TAVOR_EVT_MSK_WQE_PG_FAULT		\
	(1 << TAVOR_EVT_WQE_PG_FAULT)
#define	TAVOR_EVT_MSK_UNSUPPORTED_PG_FAULT	\
	(1 << TAVOR_EVT_UNSUPPORTED_PG_FAULT)
#define	TAVOR_EVT_MSK_INV_REQ_LOCAL_WQ_ERROR	\
	(1 << TAVOR_EVT_INV_REQ_LOCAL_WQ_ERROR)
#define	TAVOR_EVT_MSK_LOCAL_ACC_VIO_WQ_ERROR	\
	(1 << TAVOR_EVT_LOCAL_ACC_VIO_WQ_ERROR)
#define	TAVOR_EVT_MSK_SRQ_CATASTROPHIC_ERROR	\
	(1 << TAVOR_EVT_SRQ_CATASTROPHIC_ERROR)
#define	TAVOR_EVT_MSK_SRQ_LAST_WQE_REACHED	\
	(1 << TAVOR_EVT_SRQ_LAST_WQE_REACHED)
#define	TAVOR_EVT_MSK_ECC_DETECTION		\
	(1 << TAVOR_EVT_ECC_DETECTION)
#define	TAVOR_EVT_NO_MASK			0
#define	TAVOR_EVT_CATCHALL_MASK			0x1840

/*
 * The last defines are used by tavor_eqe_sync() to indicate whether or not
 * to force a DMA sync.  The case for forcing a DMA sync on a EQE comes from
 * the possibility that we could receive an interrupt, read of the ECR, and
 * have each of these operations complete successfully _before_ the hardware
 * has finished its DMA to the event queue.
 */
#define	TAVOR_EQ_SYNC_NORMAL			0x0
#define	TAVOR_EQ_SYNC_FORCE			0x1

/*
 * Catastrophic error values.  In case of a catastrophic error, the following
 * errors are reported in a special buffer space.  The buffer location is
 * returned from a QUERY_FW command.  We check that buffer against these error
 * values to determine what kind of error occurred.
 */
#define	TAVOR_CATASTROPHIC_INTERNAL_ERROR		0x0
#define	TAVOR_CATASTROPHIC_UPLINK_BUS_ERROR		0x3
#define	TAVOR_CATASTROPHIC_DDR_DATA_ERROR		0x4
#define	TAVOR_CATASTROPHIC_INTERNAL_PARITY_ERROR	0x5

/*
 * This define is the 'enable' flag used when programming the MSI number
 * into event queues.  It is or'd with the MSI number and the result is
 * written into the EX context.
 */

#define	TAVOR_EQ_MSI_ENABLE_FLAG		0x80

/*
 * The tavor_sw_eq_s structure is also referred to using the "tavor_eqhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, poll, and
 * (later) free an event queue (EQ).
 *
 * Specifically, it has a consumer index and a lock to ensure single threaded
 * access to it.  It has pointers to the various resources allocated for the
 * event queue, i.e. an EQC resource and the memory for the event queue
 * itself.  It has flags to indicate whether the EQ requires ddi_dma_sync()
 * ("eq_sync") or to indicate which type of event class(es) the EQ has been
 * mapped to (eq_evttypemask).
 *
 * It also has a pointer to the associated MR handle (for the mapped queue
 * memory) and a function pointer that points to the handler that should
 * be called when the corresponding EQ has fired.  Note: the "eq_func"
 * handler takes a Tavor softstate pointer, a pointer to the EQ handle, and a
 * pointer to a generic tavor_hw_eqe_t structure.  It is up to the "eq_func"
 * handler function to determine what specific type of event is being passed.
 *
 * Lastly, we have the always necessary backpointer to the resource for the
 * EQ handle structure itself.
 */
struct tavor_sw_eq_s {
	uint32_t		eq_consindx;
	uint32_t		eq_eqnum;
	tavor_hw_eqe_t		*eq_buf;
	tavor_mrhdl_t		eq_mrhdl;
	uint32_t		eq_bufsz;
	uint_t			eq_sync;
	uint_t			eq_evttypemask;
	tavor_rsrc_t		*eq_eqcrsrcp;
	tavor_rsrc_t		*eq_rsrcp;
	int (*eq_func)(tavor_state_t *state, tavor_eqhdl_t eq,
	    tavor_hw_eqe_t *eqe);

	struct tavor_qalloc_info_s eq_eqinfo;
};

int tavor_eq_init_all(tavor_state_t *state);
int tavor_eq_fini_all(tavor_state_t *state);
void tavor_eq_arm_all(tavor_state_t *state);
uint_t tavor_isr(caddr_t arg1, caddr_t arg2);
void tavor_eq_doorbell(tavor_state_t *state, uint32_t eq_cmd, uint32_t eqn,
    uint32_t eq_param);
void tavor_eq_overflow_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_EVENT_H */
