/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * hci1394_async.c
 *    These routines manipulate the 1394 asynchronous dma engines.  This
 *    includes incoming and outgoing reads, writes, and locks and their
 *    associated responses.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/note.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>


/*
 * ASYNC_ARRESP_ACK_ERROR is or'd into the error status when we get an ACK error
 * on an ARRESP.  Since the 1394 response code overlaps with the OpenHCI ACK/EVT
 * errors, we use this to distinguish between the errors in process_arresp().
 */
#define	ASYNC_ARRESP_ACK_ERROR		0x8000

/* Macro's to help extract 48-bit 1394 address into a uint64_t */
#define	HCI1394_TO_ADDR_HI(data) (((uint64_t)((data) & 0xFFFF)) << 32)
#define	HCI1394_TO_ADDR_LO(data) ((uint64_t)((data) & 0xFFFFFFFF))

/*
 * Macro to convert a byte stream into a big endian quadlet or octlet or back
 * the other way. 1394 arithmetic lock operations are done on big endian
 * quadlets or octlets. compare swaps and bit masks are done on a byte streams.
 * All data is treated as byte streams over the bus. These macros will convert
 * the data to a big endian "integer" on x86 plaforms if the operation is an
 * arithmetic lock operation.  It will do nothing if it is not on x86 or is not
 * an arithmetic lock operation.
 */
#ifdef _LITTLE_ENDIAN
#define	HCI1394_ARITH_LOCK_SWAP32(tcode, data) \
	(((tcode) == CMD1394_LOCK_FETCH_ADD) || \
	((tcode) == CMD1394_LOCK_BOUNDED_ADD) || \
	((tcode) == CMD1394_LOCK_WRAP_ADD)) ? \
	(ddi_swap32(data)) : (data)
#define	HCI1394_ARITH_LOCK_SWAP64(tcode, data) \
	(((tcode) == CMD1394_LOCK_FETCH_ADD) || \
	((tcode) == CMD1394_LOCK_BOUNDED_ADD) || \
	((tcode) == CMD1394_LOCK_WRAP_ADD)) ? \
	(ddi_swap64(data)) : (data)
#else
#define	HCI1394_ARITH_LOCK_SWAP32(tcode, data) (data)
#define	HCI1394_ARITH_LOCK_SWAP64(tcode, data) (data)
#endif



static int hci1394_async_arresp_read(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, uint_t *tcode, hci1394_async_cmd_t **hcicmd,
    uint_t *size);
static int hci1394_async_arresp_size_get(uint_t tcode, hci1394_q_handle_t q,
    uint32_t *addr, uint_t *size);

static int hci1394_async_arreq_read(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, uint_t *tcode, hci1394_async_cmd_t **hcicmd,
    uint_t *size);
static int hci1394_async_arreq_read_qrd(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size);
static int hci1394_async_arreq_read_qwr(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size);
static int hci1394_async_arreq_read_brd(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size);
static int hci1394_async_arreq_read_bwr(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size);
static int hci1394_async_arreq_read_lck(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size);
static int hci1394_async_arreq_read_phy(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size,
    boolean_t *bus_reset_token);

static void hci1394_async_hcicmd_init(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv,
    hci1394_async_cmd_t **hcicmd);

static void hci1394_async_atreq_start(void *async, uint32_t command_ptr);
static void hci1394_async_arresp_start(void *async, uint32_t command_ptr);
static void hci1394_async_arreq_start(void *async, uint32_t command_ptr);
static void hci1394_async_atresp_start(void *async, uint32_t command_ptr);

static void hci1394_async_atreq_wake(void *async);
static void hci1394_async_arresp_wake(void *async);
static void hci1394_async_arreq_wake(void *async);
static void hci1394_async_atresp_wake(void *async);

static void hci1394_async_atreq_flush(hci1394_async_handle_t async_handle);
static void hci1394_async_arresp_flush(hci1394_async_handle_t async_handle);
static void hci1394_async_arreq_flush(hci1394_async_handle_t async_handle);
static void hci1394_async_atresp_flush(hci1394_async_handle_t async_handle);
static void hci1394_async_pending_list_flush(hci1394_async_handle_t
    async_handle);

static void hci1394_async_pending_timeout(hci1394_tlist_node_t *node,
    void *arg);
static uint_t hci1394_async_timeout_calc(hci1394_async_handle_t async_handle,
    uint_t current_time);

_NOTE(SCHEME_PROTECTS_DATA("unique", msgb))

/*
 * hci1394_async_init()
 *    Initialize the async DMA engines and state. We init the tlabels; ATREQ
 *    pending Q; and ATREQ, ARRESP, ARREQ, and ATRESP Q's. init() returns a
 *    handle to be used in rest of the functions.
 */
int
hci1394_async_init(hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t ohci_handle, hci1394_csr_handle_t csr_handle,
    hci1394_async_handle_t *async_handle)
{
	hci1394_tlist_timer_t timer_info;
	hci1394_q_info_t qinfo;
	hci1394_async_t *async;
	int status;


	ASSERT(drvinfo != NULL);
	ASSERT(ohci_handle != NULL);
	ASSERT(csr_handle != NULL);
	ASSERT(async_handle != NULL);

	/* alloc the space to keep track of the list */
	async = kmem_alloc(sizeof (hci1394_async_t), KM_SLEEP);

	/* copy in parms to our local state */
	async->as_drvinfo = drvinfo;
	async->as_ohci = ohci_handle;
	async->as_csr = csr_handle;
	async->as_flushing_arreq = B_FALSE;
	async->as_phy_reset = 0xFFFFFFFF;
	mutex_init(&async->as_atomic_lookup, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);

	/*
	 * Initialize the tlabels. Reclaim a bad tlabel after the split timeout
	 * has gone by. This time is in reference to the point the transaction
	 * has been marked as bad. Therefore the tlabel will be reclaimed at
	 * twice the split_timeout. (i.e. if the split timeout was set to 100mS
	 * and the transaction has timed out, 100mS has already gone by. We need
	 * to wait for 100mS more before we can reuse the tlabel. Therefore, the
	 * reclaim time is split_timeout and not split_timeout * 2. The split
	 * timeout is stored as the number of bus cycles.  We need to convert
	 * this to nS since the reclaim time is passed as nS.
	 */
	hci1394_tlabel_init(drvinfo, OHCI_BUS_CYCLE_TO_nS(
	    hci1394_csr_split_timeout_get(csr_handle)), &async->as_tlabel);

	/*
	 * Initialize ATREQ pending list. A pended ATREQ will be timed out after
	 * "split_timeout" has gone by. split timeout is in bus cycles so we
	 * need to convert that to nS for the tlist timer info. We will set the
	 * timer resolution to 1/2 of the timeout so that we will have a worst
	 * case timeout of split timeout + (1/2 * split timeout).  See
	 * hci1394_tlist.h for more information about this.
	 */
	timer_info.tlt_timeout =
	    OHCI_BUS_CYCLE_TO_nS(hci1394_csr_split_timeout_get(csr_handle));
	timer_info.tlt_timer_resolution = timer_info.tlt_timeout / 2;
	timer_info.tlt_callback = hci1394_async_pending_timeout;
	timer_info.tlt_callback_arg = async;
	hci1394_tlist_init(drvinfo, &timer_info, &async->as_pending_list);

	/* Initialize ATREQ Q */
	qinfo.qi_desc_size = ASYNC_ATREQ_DESC_SIZE;
	qinfo.qi_data_size = ASYNC_ATREQ_DATA_SIZE;
	qinfo.qi_mode = HCI1394_ATQ;
	qinfo.qi_start = hci1394_async_atreq_start;
	qinfo.qi_wake = hci1394_async_atreq_wake;
	qinfo.qi_callback_arg = async;
	status = hci1394_q_init(drvinfo, async->as_ohci, &qinfo,
	    &async->as_atreq_q);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&async->as_atomic_lookup);
		hci1394_tlist_fini(&async->as_pending_list);
		hci1394_tlabel_fini(&async->as_tlabel);
		kmem_free(async, sizeof (hci1394_async_t));
		*async_handle = NULL;
		return (DDI_FAILURE);
	}

	/* Initialize ARRESP Q */
	qinfo.qi_desc_size = ASYNC_ARRESP_DESC_SIZE;
	qinfo.qi_data_size = ASYNC_ARRESP_DATA_SIZE;
	qinfo.qi_mode = HCI1394_ARQ;
	qinfo.qi_start = hci1394_async_arresp_start;
	qinfo.qi_wake = hci1394_async_arresp_wake;
	qinfo.qi_callback_arg = async;
	status = hci1394_q_init(drvinfo, async->as_ohci, &qinfo,
	    &async->as_arresp_q);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&async->as_atomic_lookup);
		hci1394_tlist_fini(&async->as_pending_list);
		hci1394_tlabel_fini(&async->as_tlabel);
		hci1394_q_fini(&async->as_atreq_q);
		kmem_free(async, sizeof (hci1394_async_t));
		*async_handle = NULL;
		return (DDI_FAILURE);
	}

	/* Initialize ARREQ Q */
	qinfo.qi_desc_size = ASYNC_ARREQ_DESC_SIZE;
	qinfo.qi_data_size = ASYNC_ARREQ_DATA_SIZE;
	qinfo.qi_mode = HCI1394_ARQ;
	qinfo.qi_start = hci1394_async_arreq_start;
	qinfo.qi_wake = hci1394_async_arreq_wake;
	qinfo.qi_callback_arg = async;
	status = hci1394_q_init(drvinfo, async->as_ohci, &qinfo,
	    &async->as_arreq_q);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&async->as_atomic_lookup);
		hci1394_tlist_fini(&async->as_pending_list);
		hci1394_tlabel_fini(&async->as_tlabel);
		hci1394_q_fini(&async->as_atreq_q);
		hci1394_q_fini(&async->as_arresp_q);
		kmem_free(async, sizeof (hci1394_async_t));
		*async_handle = NULL;
		return (DDI_FAILURE);
	}

	/* Initialize ATRESP Q */
	qinfo.qi_desc_size = ASYNC_ATRESP_DESC_SIZE;
	qinfo.qi_data_size = ASYNC_ATRESP_DATA_SIZE;
	qinfo.qi_mode = HCI1394_ATQ;
	qinfo.qi_start = hci1394_async_atresp_start;
	qinfo.qi_wake = hci1394_async_atresp_wake;
	qinfo.qi_callback_arg = async;
	status = hci1394_q_init(drvinfo, async->as_ohci, &qinfo,
	    &async->as_atresp_q);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&async->as_atomic_lookup);
		hci1394_tlist_fini(&async->as_pending_list);
		hci1394_tlabel_fini(&async->as_tlabel);
		hci1394_q_fini(&async->as_atreq_q);
		hci1394_q_fini(&async->as_arresp_q);
		hci1394_q_fini(&async->as_arreq_q);
		kmem_free(async, sizeof (hci1394_async_t));
		*async_handle = NULL;
		return (DDI_FAILURE);
	}

	*async_handle = async;

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_fini()
 *    Free's up the space allocated in init().  Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set your handle to NULL
 *    before returning.
 */
void
hci1394_async_fini(hci1394_async_handle_t *async_handle)
{
	hci1394_async_t *async;


	ASSERT(async_handle != NULL);

	async = (hci1394_async_t *)*async_handle;

	mutex_destroy(&async->as_atomic_lookup);
	hci1394_tlabel_fini(&async->as_tlabel);
	hci1394_tlist_fini(&async->as_pending_list);
	hci1394_q_fini(&async->as_atreq_q);
	hci1394_q_fini(&async->as_atresp_q);
	hci1394_q_fini(&async->as_arreq_q);
	hci1394_q_fini(&async->as_arresp_q);

	kmem_free(async, sizeof (hci1394_async_t));

	/* set handle to null.  This helps catch bugs. */
	*async_handle = NULL;
}


/*
 * hci1394_async_suspend()
 *    The system is getting ready to be suspended.  Make sure that all of
 *    the Q's are clean and that the there are no scheduled timeouts in the
 *    pending Q.
 */
void
hci1394_async_suspend(hci1394_async_handle_t async_handle)
{
	ASSERT(async_handle != NULL);

	/* Flush out async DMA Q's */
	hci1394_async_flush(async_handle);

	/* Cancel any scheduled pending timeouts */
	hci1394_tlist_timeout_cancel(async_handle->as_pending_list);
}


/*
 * hci1394_async_resume()
 *    Re-setup the DMA Q's during a resume after a successful suspend. The
 *    tlabels will be re-initialized during the bus reset and the pending Q will
 *    be flushed during the suspend.
 */
int
hci1394_async_resume(hci1394_async_handle_t async_handle)
{
	ASSERT(async_handle != NULL);

	hci1394_q_resume(async_handle->as_atreq_q);
	hci1394_q_resume(async_handle->as_atresp_q);
	hci1394_q_resume(async_handle->as_arreq_q);
	hci1394_q_resume(async_handle->as_arresp_q);

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_cmd_overhead()
 *    Return the size of the HAL private area to attach to every alloced 1394
 *    framework command.  This allows us to track command state without having
 *    to alloc memory every time a command comes down the pipe.
 */
uint_t
hci1394_async_cmd_overhead()
{
	return (sizeof (hci1394_async_cmd_t));
}


/*
 * hci1394_async_flush()
 *    Flush out the Async Q's and the ATREQ pending list.  This is called every
 *    bus reset so that we're sync'd up with the HW and when shutting down or
 *    suspending to make sure we cleanup after all commands.
 */
void
hci1394_async_flush(hci1394_async_handle_t async_handle)
{
	ASSERT(async_handle != NULL);

	hci1394_async_atreq_flush(async_handle);
	hci1394_async_arresp_flush(async_handle);
	hci1394_async_pending_list_flush(async_handle);
	hci1394_async_arreq_flush(async_handle);
	hci1394_async_atresp_flush(async_handle);
	hci1394_tlabel_reset(async_handle->as_tlabel);
}


/*
 * hci1394_async_pending_timeout_update()
 *    Update the timeout for the pending list. This updates both the pending
 *    list timeout and time we wait to reclaim  bad tlabels.  timeout is the
 *    time in nS so we do not have to do any conversions. This routine will be
 *    called when the CSR split timeout registers are updated.
 */
void
hci1394_async_pending_timeout_update(hci1394_async_handle_t async_handle,
    hrtime_t timeout)
{
	ASSERT(async_handle != NULL);
	hci1394_tlist_timeout_update(async_handle->as_pending_list, timeout);
	hci1394_tlabel_set_reclaim_time(async_handle->as_tlabel, timeout);
}


/*
 * hci1394_async_atreq_process()
 *    Process an atreq, if one has completed. This is called during interrupt
 *    processing and will process a completed atreq. It returns status if an
 *    atreq was processed so that the ISR knows that it needs to be called
 *    again to see if another ATREQ has completed. flush_q set to B_TRUE tells
 *    this routine to process all commands regardless of their completion
 *    status.  This is used during bus reset processing to remove all commands
 *    from the Q.
 *
 *    There are a few race conditions that we have to watch for in atreq/arresp.
 *    They all have to do with pended responses so they are not applicable in
 *    the ARREQ/ATRESP engine (since ATRESP's can't be pended).
 *
 *    Since the race conditions only exist for pended responses, we will only
 *    talk about that sequence here. We're also going to simplify the discussion
 *    so what the code does, so it won't exactly match what we say (e.g. we
 *    don't always setup a timeout for every single command, etc.)
 *
 *    After Q'ing up an ATREQ, we will process the result of that command in
 *    one of a couple different paths. A normal condition would be that we Q up
 *    a command, we get an ATREQ complete interrupt and look at the ATREQ
 *    result. In the case it has been pended, we setup a timeout to wait for the
 *    response. If we receive the response before the timeout, the command is
 *    done and we send the response up the chain, if we do not, the command is
 *    done and we send a timeout notification up the chain.
 *
 *    The first race condition is when we get the timeout at the same time as
 *    the response. At first glance a mutex around the command state would
 *    solve this problem. But on a multi-processor machine, we may have the
 *    ARRESP interrupt handler(ISR) running on one processor and the timeout on
 *    another. This means that the command state could change between two
 *    reads while in the ISR. This means we need to have a little more complex
 *    logic around changing the command state and have to be careful how and
 *    when we do this.
 *
 *    The second race condition is that we could see the ARRESP before we
 *    process the ATREQ. We could be processing a few ARRESP from previous
 *    ATREQ's when the ATREQ completes and then the ARRESP comes in.  Since we
 *    already are in the interrupt handler, the ATREQ complete will not preempt
 *    us.
 *
 *    We will never see a race condition between the ATREQ interrupt for a
 *    command and the pending timeout since the command is not being timed until
 *    this routine is run for that command.
 */
int
hci1394_async_atreq_process(hci1394_async_handle_t async_handle,
    boolean_t flush_q, boolean_t *request_available)
{
	hci1394_async_cmd_t *hcicmd;
	hci1394_q_cmd_t *qcmd;
	int cmd_status;


	ASSERT(async_handle != NULL);
	ASSERT(request_available != NULL);

	/*
	 * Get the next ATREQ that has completed (if one has). Space is free'd
	 * up in atreq_q and atreq_data_q as part of this function call.
	 */
	hci1394_q_at_next(async_handle->as_atreq_q, flush_q, &qcmd);

	/*
	 * See if there were anymore requests on ATREQ Q. A NULL means there
	 * were no completed commands left on the Q
	 */
	if (qcmd == NULL) {
		*request_available = B_FALSE;
		return (DDI_SUCCESS);
	}

	/* There is a completed ATREQ, setup the HAL command pointer */
	*request_available = B_TRUE;
	hcicmd = (hci1394_async_cmd_t *)qcmd->qc_arg;

	/* save away the command completed timestamp for the services layer */
	hcicmd->ac_priv->ack_tstamp = qcmd->qc_timestamp;

	/*
	 * Make sure this command has not already been processed. This command
	 * may have already received a response.  If the ACK was not an ACK
	 * pending, we have a HW error (i.e. The target HW sent a response to a
	 * non-pended request). There is a race condition where the software
	 * will see and complete a response before processing it's ACK Pending.
	 * This can only happen for ACK pendings. We have seen this race
	 * condition and response to a non-pended request during real-world
	 * testing :-)
	 */
	if (hcicmd->ac_state != HCI1394_CMD_STATE_IN_PROGRESS) {
		/*
		 * we already processed the ARRESP in arresp_process(), it
		 * better have been ACK pended. Otherwise the target device
		 * performed an illegal action.
		 */
		if (qcmd->qc_status == OHCI_ACK_PENDING) {
			/*
			 * Tell source that their command has completed. We're
			 * done with this command.
			 * NOTE: We use ac_status which was set in
			 * process_arresp()
			 */
			h1394_cmd_is_complete(
			    async_handle->as_drvinfo->di_sl_private,
			    hcicmd->ac_cmd, H1394_AT_REQ,
			    hcicmd->ac_status);
			return (DDI_SUCCESS);
		/*
		 * This is a HW error.  Process the ACK like we never saw the
		 * response. We will do this below.
		 */
		}
	}

	/*
	 * if we got an ack pending, add it to the pending list and leave. We
	 * will either get an ARRESP or the pending list will timeout the
	 * response.
	 */
	if (qcmd->qc_status == OHCI_ACK_PENDING) {
		hcicmd->ac_state = HCI1394_CMD_STATE_PENDING;
		/* Add this command to the pending list */
		hcicmd->ac_plist_node.tln_addr = hcicmd;
		hci1394_tlist_add(async_handle->as_pending_list,
		    &hcicmd->ac_plist_node);
		return (DDI_SUCCESS);
	}

	/*
	 * setup our return command status based on the ACK from the HW. See the
	 * OpenHCI 1.0 spec (table 3.2 on pg. 18) for more information about
	 * these ACK/EVT's.
	 */
	switch (qcmd->qc_status) {
	case OHCI_ACK_COMPLETE:
		cmd_status = H1394_CMD_SUCCESS;
		break;

	/*
	 * we can get a nostatus during a bus reset (i.e. we shutdown the AT
	 * engine before it flushed all the commands)
	 */
	case OHCI_EVT_FLUSHED:
	case OHCI_EVT_NO_STATUS:
		cmd_status = H1394_CMD_EBUSRESET;
		break;

	case OHCI_EVT_MISSING_ACK:
	case OHCI_EVT_TIMEOUT:
		cmd_status = H1394_CMD_ETIMEOUT;
		break;

	case OHCI_ACK_BUSY_X:
	case OHCI_ACK_BUSY_A:
	case OHCI_ACK_BUSY_B:
		cmd_status = H1394_CMD_EDEVICE_BUSY;
		break;

	case OHCI_ACK_TARDY:
		cmd_status = H1394_CMD_EDEVICE_POWERUP;
		break;

	case OHCI_ACK_DATA_ERROR:
		cmd_status = H1394_CMD_EDATA_ERROR;
		break;

	case OHCI_ACK_TYPE_ERROR:
		cmd_status = H1394_CMD_ETYPE_ERROR;
		break;

	case OHCI_ACK_CONFLICT_ERROR:
		cmd_status = H1394_CMD_ERSRC_CONFLICT;
		break;

	case OHCI_ACK_ADDRESS_ERROR:
		cmd_status = H1394_CMD_EADDR_ERROR;
		break;

	case OHCI_EVT_UNDERRUN:
	case OHCI_EVT_DATA_READ:
	case OHCI_EVT_TCODE_ERR:
	case OHCI_EVT_DESCRIPTOR_READ:
	case OHCI_EVT_UNKNOWN:
	default:
		cmd_status = H1394_CMD_EUNKNOWN_ERROR;
		break;
	}

	/*
	 * Free the tlabel that was used for this transfer. We will not try and
	 * free the tlabel in the case that we already received a response or if
	 * we did not allocate one (PHY packet). If we already received a
	 * response, the tlabel would have been free'd in
	 * hci1394_async_arresp_process().
	 */
	if ((hcicmd->ac_state == HCI1394_CMD_STATE_IN_PROGRESS) &&
	    (hcicmd->ac_tlabel_alloc == B_TRUE)) {
		hci1394_tlabel_free(async_handle->as_tlabel,
		    &hcicmd->ac_tlabel);
	}

	/*
	 * if we got anything other than and ACK pending, we are done w/ this
	 * transaction.
	 */
	hcicmd->ac_state = HCI1394_CMD_STATE_COMPLETED;

	/* tell the services layer that the command has completed */
	h1394_cmd_is_complete(async_handle->as_drvinfo->di_sl_private,
	    hcicmd->ac_cmd, H1394_AT_REQ, cmd_status);

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arresp_process()
 *    Process an arresp, if one has completed. This is called during interrupt
 *    processing and will process a completed arresp. It returns status if an
 *    arresp was processed so that the ISR knows that it needs to be called
 *    again to see if another ARRESP has completed.
 */
int
hci1394_async_arresp_process(hci1394_async_handle_t async_handle,
    boolean_t *response_available)
{
	hci1394_async_cmd_t *hcicmd;
	uint32_t *addr;
	int cmd_status;
	uint_t tcode;
	uint_t size;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(response_available != NULL);

	/*
	 * See if there were any responses on ARRESP Q. A NULL means there
	 * were no responses on the Q. This call does NOT free up space. We
	 * need to do that later after we figure out how much space the
	 * response takes up.
	 */
	hci1394_q_ar_next(async_handle->as_arresp_q, &addr);
	if (addr == NULL) {
		*response_available = B_FALSE;
		return (DDI_SUCCESS);
	}

	/*
	 * We got a response. Lock out pending timeout callback from marking
	 * tlabel bad.
	 */
	*response_available = B_TRUE;
	mutex_enter(&async_handle->as_atomic_lookup);

	/*
	 * Read in the response into the 1394 framework command. We could get a
	 * NULL for a command if we got a response with an error (i.e. tlabel
	 * that didn't match a request) This would be a successful read but with
	 * a NULL hcicmd returned. If we ever get a DDI_FAILURE, we will
	 * shutdown.
	 */
	status = hci1394_async_arresp_read(async_handle,
	    (hci1394_basic_pkt_t *)addr, &tcode, &hcicmd, &size);
	if (status != DDI_SUCCESS) {
		mutex_exit(&async_handle->as_atomic_lookup);
		h1394_error_detected(async_handle->as_drvinfo->di_sl_private,
		    H1394_SELF_INITIATED_SHUTDOWN, NULL);
		cmn_err(CE_WARN, "hci1394(%d): driver shutdown: "
		    "unrecoverable error interrupt detected",
		    async_handle->as_drvinfo->di_instance);
		hci1394_shutdown(async_handle->as_drvinfo->di_dip);
		return (DDI_FAILURE);
	}

	/* Free up the arresp Q space, we are done with the data */
	hci1394_q_ar_free(async_handle->as_arresp_q, size);

	/*
	 * if we did not get a valid command response (i.e. we got a bad tlabel
	 * or something like that) we don't have anything else to do.  We will
	 * say that we processed a response and will return successfully. We
	 * still may have other responses on the Q.
	 */
	if (hcicmd == NULL) {
		mutex_exit(&async_handle->as_atomic_lookup);
		return (DDI_SUCCESS);
	}

	/*
	 * Make sure this is in the pending list. There is a small chance that
	 * we will see the response before we see the ACK PENDING. If it is the
	 * expected case, it is in the pending list.  We will remove it since
	 * we are done with the command.
	 *
	 * NOTE: there is a race condition here with the pending timeout.  Look
	 * at the comments before hci1394_async_atreq_process() for more info.
	 */
	if (hcicmd->ac_state == HCI1394_CMD_STATE_PENDING) {
		/* remove this transfer from our the pending list */
		status = hci1394_tlist_delete(async_handle->as_pending_list,
		    &hcicmd->ac_plist_node);
		if (status != DDI_SUCCESS) {
			mutex_exit(&async_handle->as_atomic_lookup);
			return (DDI_SUCCESS);
		}
	}

	/* allow pending timeout callback to mark tlabel as bad */
	mutex_exit(&async_handle->as_atomic_lookup);

	/*
	 * We got a valid response that we were able to read in. Free the tlabel
	 * that was used for this transfer.
	 */
	hci1394_tlabel_free(async_handle->as_tlabel, &hcicmd->ac_tlabel);

	/*
	 * Setup our return command status based on the RESP or ACK or SW error.
	 * See the IEEE1394-1995 spec (6.2.4.10 on pg. 159) for more information
	 * on response codes. See the OpenHCI 1.0 spec (table 3.2 on pg. 18) for
	 * more information about ACK/EVT's. ac_status could have an IEEE1394
	 * response in it, a 1394 EVT/ACK, or a special cmd1394 error for a
	 * device error caught in SW (e.g. for a block read request that got a
	 * quadlet read response). We use a special mask to separate the
	 * ACK/EVT's from the responses (ASYNC_ARRESP_ACK_ERROR).
	 */
	switch (hcicmd->ac_status) {
	case IEEE1394_RESP_COMPLETE:
		cmd_status = H1394_CMD_SUCCESS;
		break;
	case IEEE1394_RESP_DATA_ERROR:
		cmd_status = H1394_CMD_EDATA_ERROR;
		break;
	case IEEE1394_RESP_TYPE_ERROR:
		cmd_status = H1394_CMD_ETYPE_ERROR;
		break;
	case IEEE1394_RESP_CONFLICT_ERROR:
		cmd_status = H1394_CMD_ERSRC_CONFLICT;
		break;
	case IEEE1394_RESP_ADDRESS_ERROR:
		cmd_status = H1394_CMD_EADDR_ERROR;
		break;
	case H1394_CMD_EDEVICE_ERROR:
		cmd_status = H1394_CMD_EDEVICE_ERROR;
		break;
	case OHCI_ACK_DATA_ERROR | ASYNC_ARRESP_ACK_ERROR:
		cmd_status = H1394_CMD_EDATA_ERROR;
		break;
	case OHCI_ACK_TYPE_ERROR | ASYNC_ARRESP_ACK_ERROR:
		cmd_status = H1394_CMD_ETYPE_ERROR;
		break;
	case OHCI_EVT_UNDERRUN | ASYNC_ARRESP_ACK_ERROR:
	case OHCI_EVT_DATA_READ | ASYNC_ARRESP_ACK_ERROR:
	case OHCI_EVT_TCODE_ERR | ASYNC_ARRESP_ACK_ERROR:
		cmd_status = H1394_CMD_EUNKNOWN_ERROR;
		break;
	default:
		cmd_status = H1394_CMD_EUNKNOWN_ERROR;
		break;
	}

	/*
	 * if we have already processed the atreq and put it on the pending Q
	 * (normal case), tell the services layer it completed.
	 */
	if (hcicmd->ac_state == HCI1394_CMD_STATE_PENDING) {
		/* Set state indicating that we are done with this cmd */
		hcicmd->ac_state = HCI1394_CMD_STATE_COMPLETED;

		/* tell the services lyaer the command has completed */
		h1394_cmd_is_complete(async_handle->as_drvinfo->di_sl_private,
		    hcicmd->ac_cmd, H1394_AT_REQ, cmd_status);

	/*
	 * We have not seen the atreq status yet.  We will call
	 * h1394_command_is_complete() in atreq_process() in case we did not get
	 * an ack pending (target HW error -> this is based on real world
	 * experience :-))
	 */
	} else {
		/* Set state indicating that we are done with this cmd */
		hcicmd->ac_state = HCI1394_CMD_STATE_COMPLETED;

		/* save away the status for atreq_process() */
		hcicmd->ac_status = cmd_status;
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_process()
 *    Process an arreq, if one has arrived. This is called during interrupt
 *    processing and will process an arreq that has arrived. It returns status
 *    if an arreq was processed so that the ISR knows that it needs to be
 *    called again to see if another ARREQ has arrived.
 */
int
hci1394_async_arreq_process(hci1394_async_handle_t async_handle,
    boolean_t *request_available)
{
	hci1394_async_cmd_t *hcicmd;
	uint32_t *addr;
	uint_t tcode;
	uint_t size;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(request_available != NULL);

	/*
	 * See if there were any requests on ARREQ Q. A NULL means there
	 * were no requests on the Q. This call does NOT free up space. We
	 * need to do that later after we figure out how much space the
	 * request takes up.
	 */
	hci1394_q_ar_next(async_handle->as_arreq_q, &addr);
	if (addr == NULL) {
		*request_available = B_FALSE;
		return (DDI_SUCCESS);
	}

	/*
	 * We got a request. Read the request into a 1394 framework command.
	 * We could get a NULL for a command if we got a request with an error
	 * (i.e. ARREQ ACK was not ack pending or ack complete). This would be a
	 * successful read but with a NULL hcicmd returned. If we ever get a
	 * DDI_FAILURE, we will shutdown.
	 */
	*request_available = B_TRUE;
	status = hci1394_async_arreq_read(async_handle,
	    (hci1394_basic_pkt_t *)addr, &tcode, &hcicmd, &size);
	if (status != DDI_SUCCESS) {
		h1394_error_detected(async_handle->as_drvinfo->di_sl_private,
		    H1394_SELF_INITIATED_SHUTDOWN, NULL);
		cmn_err(CE_WARN, "hci1394(%d): driver shutdown: "
		    "unrecoverable error interrupt detected",
		    async_handle->as_drvinfo->di_instance);
		hci1394_shutdown(async_handle->as_drvinfo->di_dip);
		return (DDI_FAILURE);
	}

	/* Free up the arreq Q space, we are done with the data */
	hci1394_q_ar_free(async_handle->as_arreq_q, size);

	/*
	 * if we did not get a valid request (i.e. The ARREQ had a bad ACK
	 * or something like that) we don't have anything else to do.  We will
	 * say that we processed a request and will return successfully. We
	 * still may have other requests on the Q.
	 */
	if (hcicmd == NULL) {
		return (DDI_SUCCESS);
	}

	/*
	 * If as_flushing_arreq is set, we do not want to send any requests up
	 * to the Services Layer. We are flushing the ARREQ until we see a bus
	 * reset token that matches the current bus generation. Free up the
	 * alloc'd command and return success.
	 */
	if (async_handle->as_flushing_arreq == B_TRUE) {
		hci1394_async_response_complete(async_handle, hcicmd->ac_cmd,
		    hcicmd->ac_priv);
		return (DDI_SUCCESS);
	}

	/*
	 * We got a valid request that we were able to read in. Call into the
	 * services layer based on the type of request.
	 */
	switch (tcode) {
	case IEEE1394_TCODE_READ_QUADLET:
	case IEEE1394_TCODE_READ_BLOCK:
		h1394_read_request(async_handle->as_drvinfo->di_sl_private,
		    hcicmd->ac_cmd);
		break;
	case IEEE1394_TCODE_WRITE_QUADLET:
	case IEEE1394_TCODE_WRITE_BLOCK:
		h1394_write_request(async_handle->as_drvinfo->di_sl_private,
		    hcicmd->ac_cmd);
		break;
	case IEEE1394_TCODE_LOCK:
		h1394_lock_request(async_handle->as_drvinfo->di_sl_private,
		    hcicmd->ac_cmd);
		break;
	case IEEE1394_TCODE_PHY:
		/*
		 * OpenHCI only handles 1 PHY quadlet at a time. If a selfid
		 * packet was received with multiple quadlets, we will treat
		 * each quadlet as a separate call.  We do not notify the
		 * services layer through the normal command interface, we will
		 * treat it like a command internally and then free up the
		 * command ourselves when we are done with it.
		 */
		h1394_phy_packet(async_handle->as_drvinfo->di_sl_private,
		    &hcicmd->ac_cmd->cmd_u.q.quadlet_data, 1,
		    hcicmd->ac_priv->recv_tstamp);
		/* free alloc'd command */
		hci1394_async_response_complete(async_handle, hcicmd->ac_cmd,
		    hcicmd->ac_priv);
		break;
	default:
		/* free alloc'd command */
		hci1394_async_response_complete(async_handle, hcicmd->ac_cmd,
		    hcicmd->ac_priv);
		break;
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_atresp_process()
 *    Process an atresp, if one has completed. This is called during interrupt
 *    processing and will process a completed atresp. It returns status if an
 *    atresp was processed so that the ISR knows that it needs to be called
 *    again to see if another ATRESP has completed. flush_q set to B_TRUE tells
 *    this routine to process all commands regardless of their completion
 *    status.  This is used during bus reset processing to remove all commands
 *    from the Q.
 */
int
hci1394_async_atresp_process(hci1394_async_handle_t async_handle,
    boolean_t flush_q, boolean_t *response_available)
{
	hci1394_async_cmd_t *hcicmd;
	hci1394_q_cmd_t *qcmd;
	int cmd_status;


	ASSERT(async_handle != NULL);
	ASSERT(response_available != NULL);

	/*
	 * Get the next ATRESP that has completed (if one has). Space is free'd
	 * up in atresp_q and atresp_data_q as part of this function call.
	 */
	hci1394_q_at_next(async_handle->as_atresp_q, flush_q, &qcmd);

	/*
	 * See if there were anymore requests on ATRESP Q. A NULL means there
	 * were no completed commands left on the Q.
	 */
	if (qcmd == NULL) {
		*response_available = B_FALSE;
		return (DDI_SUCCESS);
	}

	/* There is a completed ATRESP, setup the HAL command pointer */
	*response_available = B_TRUE;
	hcicmd = (hci1394_async_cmd_t *)qcmd->qc_arg;

	/* save away the command completed timestamp for the services layer */
	hcicmd->ac_priv->ack_tstamp = qcmd->qc_timestamp;

	/*
	 * setup our return command status based on the ACK from the HW. See the
	 * OpenHCI 1.0 spec (table 3.2 on pg. 18) for more information about
	 * these ACK/EVT's.
	 */
	switch (qcmd->qc_status) {
	case OHCI_ACK_COMPLETE:
		cmd_status = H1394_CMD_SUCCESS;
		break;

	/*
	 * we can get a nostatus during a bus reset (i.e. we shutdown the AT
	 * engine before it flushed all the commands)
	 */
	case OHCI_EVT_FLUSHED:
	case OHCI_EVT_NO_STATUS:
		cmd_status = H1394_CMD_EBUSRESET;
		break;

	case OHCI_EVT_MISSING_ACK:
	case OHCI_EVT_TIMEOUT:
		cmd_status = H1394_CMD_ETIMEOUT;
		break;

	case OHCI_ACK_BUSY_X:
	case OHCI_ACK_BUSY_A:
	case OHCI_ACK_BUSY_B:
		cmd_status = H1394_CMD_EDEVICE_BUSY;
		break;

	case OHCI_ACK_TARDY:
		cmd_status = H1394_CMD_EDEVICE_POWERUP;
		break;

	case OHCI_ACK_DATA_ERROR:
		cmd_status = H1394_CMD_EDATA_ERROR;
		break;

	case OHCI_ACK_TYPE_ERROR:
		cmd_status = H1394_CMD_ETYPE_ERROR;
		break;

	case OHCI_ACK_CONFLICT_ERROR:
		cmd_status = H1394_CMD_ERSRC_CONFLICT;
		break;

	case OHCI_ACK_ADDRESS_ERROR:
		cmd_status = H1394_CMD_EADDR_ERROR;
		break;

	case OHCI_EVT_UNKNOWN:
		cmd_status = H1394_CMD_EUNKNOWN_ERROR;
		break;

	case OHCI_EVT_UNDERRUN:
	case OHCI_EVT_DATA_READ:
	case OHCI_EVT_TCODE_ERR:
	case OHCI_EVT_DESCRIPTOR_READ:
	default:
		cmd_status = H1394_CMD_EUNKNOWN_ERROR;
		break;
	}

	/* tell the services layer that the command has completed */
	h1394_cmd_is_complete(async_handle->as_drvinfo->di_sl_private,
	    hcicmd->ac_cmd, H1394_AT_RESP, cmd_status);

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arresp_read()
 *    Read ARRESP in from memory into 1394 Framework command. We read the tcode
 *    which tells us which kind of arresp the packet is, get the size of the
 *    response, read in the sender, tlabel, and response code, and then
 *    lookup the command based on the sender and tlabel. Once we get the command
 *    (corresponding to the ATREQ), we will copy the rest of the response into
 *    that command.
 *
 *    The only time this routine should return DDI_FAILURE is if it was unable
 *    to maintain a good state in the ARRESP Q (i.e. an unknown response was
 *    received and we can not cleanup after it.)  If we detect a recoverable
 *    error, and it doesn't make sense to pass the response up to the Services
 *    Layer, we should return DDI_SUCCESS with hcicmd = NULL.
 */
static int
hci1394_async_arresp_read(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt,  uint_t *tcode, hci1394_async_cmd_t **hcicmd,
    uint_t *size)
{
	hci1394_tlabel_info_t ac_tlabel;
	h1394_cmd_priv_t *cmd_priv;
	cmd1394_cmd_t *cmd;
	uint32_t *status_addr;
	uint_t data_length;
	uint32_t quadlet;
	void *command;
	uint_t rcode;
	uint_t ack;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(tcode != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* read in the arresp tcode */
	quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q, &pkt->q1);
	*tcode = HCI1394_DESC_TCODE_GET(quadlet);

	/* Get the size of the arresp */
	status = hci1394_async_arresp_size_get(*tcode,
	    async_handle->as_arresp_q, &pkt->q1, size);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Read in the tlabel, destination, and rcode (response code) */
	quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q, &pkt->q1);
	ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q, &pkt->q2);
	ac_tlabel.tbi_destination = HCI1394_DESC_DESTID_GET(quadlet);
	rcode = HCI1394_DESC_RCODE_GET(quadlet);

	/* Lookup the ATREQ framework command this response goes with */
	hci1394_tlabel_lookup(async_handle->as_tlabel, &ac_tlabel, &command);

	/*
	 * If there is not a cooresponding ATREQ command, this is an error. We
	 * will ignore this response but still return success so we cleanup
	 * after it and go on with other arresp's. This could happend if a
	 * response was sent after the command has timed out or if the target
	 * device is misbehaving. (we have seen both cases)
	 */
	*hcicmd = (hci1394_async_cmd_t *)command;
	if ((*hcicmd) == NULL) {
		return (DDI_SUCCESS);
	}

	/*
	 * copy the response code into the hal private command space. Setup
	 * shortcuts to the 1394 framework command (cmd) and the HAL/SL private
	 * area (cmd_priv). A command is made up of 4 parts. There is the public
	 * part which is accessable to the target driver, there is the Services
	 * Layer private part which is only accessible to the services layer,
	 * there is the SL/HAL private area which is where the SL and HAL share
	 * information about a particular command, and there is the HAL private
	 * area where we keep track of our command specific state information.
	 */
	(*hcicmd)->ac_status = rcode;
	cmd = (*hcicmd)->ac_cmd;
	cmd_priv = (*hcicmd)->ac_priv;

	/*
	 * Calculate the address where the status of the ARRESP and timestamp is
	 * kept at.  It is the last quadlet in the response. Save away the
	 * timestamp.
	 */
	status_addr = (uint32_t *)((uintptr_t)pkt + (uintptr_t)*size -
	    (uintptr_t)IEEE1394_QUADLET);
	quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q, status_addr);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);

	/*
	 * if we did not get an ACK_COMPLETE, we will use the ack error instead
	 * of the response in the packet for our status. We use special mask to
	 * separate the reponses from the ACKs (ASYNC_ARRESP_ACK_ERROR). We will
	 * return success with hcicmd set to the command so that this error gets
	 * sent up to the Services Layer.
	 */
	ack = HCI1394_DESC_EVT_GET(quadlet);
	if (ack != OHCI_ACK_COMPLETE) {
		/* use the ack error instead of rcode for the command status */
		(*hcicmd)->ac_status = ack | ASYNC_ARRESP_ACK_ERROR;
		return (DDI_SUCCESS);
	}

	/*
	 * If we get to this point we have gotten a valid ACK on the response
	 * and have matched up the response with an ATREQ. Now we check the
	 * response code. If it is not resp_complete, we do not have anything
	 * left to look at in the response. Return successfully.
	 */
	if (rcode != IEEE1394_RESP_COMPLETE) {
		return (DDI_SUCCESS);
	}

	/*
	 * Read the rest of the response (based on which kind of response it is)
	 * into the 1394 framework command. In all of the different responses,
	 * we check to make sure the response matches the original request. We
	 * originally did not have this check but found a device or two which
	 * did not behave very well and would cause us to corrupt our commands.
	 * Now we check :-) We will return success when we get this error since
	 * we can recover from it.
	 */
	switch (*tcode) {
	case IEEE1394_TCODE_WRITE_RESP:
		/*
		 * make sure the ATREQ was a quadlet/block write. The same
		 * response is sent back for those two type of ATREQs.
		 */
		if ((cmd->cmd_type != CMD1394_ASYNCH_WR_QUAD) &&
		    (cmd->cmd_type != CMD1394_ASYNCH_WR_BLOCK)) {
			(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_READ_QUADLET_RESP:
		/* make sure the ATREQ was a quadlet read */
		if (cmd->cmd_type != CMD1394_ASYNCH_RD_QUAD) {
			(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
			return (DDI_SUCCESS);
		}

		/*
		 * read the quadlet read response in.  Data is treated as a byte
		 * stream.
		 */
		hci1394_q_ar_rep_get8(async_handle->as_arresp_q,
		    (uint8_t *)&cmd->cmd_u.q.quadlet_data,
		    (uint8_t *)&pkt->q4, IEEE1394_QUADLET);
		break;

	case IEEE1394_TCODE_READ_BLOCK_RESP:
		/* make sure the ATREQ was a block read */
		if (cmd->cmd_type != CMD1394_ASYNCH_RD_BLOCK) {
			(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
			return (DDI_SUCCESS);
		}

		/*
		 * read in the data length.  Make sure the data length is the
		 * same size as the read block request size that went out.
		 */
		quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q,
		    &pkt->q4);
		data_length = HCI1394_DESC_DATALEN_GET(quadlet);
		if (data_length != cmd_priv->mblk.length) {
			(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
			return (DDI_SUCCESS);
		}

		/* Copy the read block data into the command mblk */
		hci1394_q_ar_copy_to_mblk(async_handle->as_arresp_q,
		    (uint8_t *)&pkt->q5, &cmd_priv->mblk);
		break;

	case IEEE1394_TCODE_LOCK_RESP:
		/* read in the data length */
		quadlet = hci1394_q_ar_get32(async_handle->as_arresp_q,
		    &pkt->q4);
		data_length = HCI1394_DESC_DATALEN_GET(quadlet);

		if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
			/*
			 * read in the data length.  Make sure the data length
			 * is the valid for a lock32 response (1 quadlet)
			 */
			if (data_length != IEEE1394_QUADLET) {
				(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
				return (DDI_SUCCESS);
			}

			/*
			 * read the lock32 response in. Data is treated as a
			 * byte stream unless it is an arithmetic lock
			 * operation. In that case we treat data like a 32-bit
			 * word.
			 */
			hci1394_q_ar_rep_get8(async_handle->as_arresp_q,
			    (uint8_t *)&cmd->cmd_u.l32.old_value,
			    (uint8_t *)&pkt->q5, IEEE1394_QUADLET);
			cmd->cmd_u.l32.old_value = HCI1394_ARITH_LOCK_SWAP32(
			    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.old_value);

		} else if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) {
			/*
			 * read in the data length.  Make sure the data length
			 * is the valid for a lock64 response (1 octlet)
			 */
			if (data_length != IEEE1394_OCTLET) {
				(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
				return (DDI_SUCCESS);
			}

			/*
			 * read the lock64 response in. Data is treated as a
			 * byte stream unless it is an arithmetic lock
			 * operation. In that case we treat data like a 64-bit
			 * word.
			 */
			hci1394_q_ar_rep_get8(async_handle->as_arresp_q,
			    (uint8_t *)&cmd->cmd_u.l64.old_value,
			    (uint8_t *)&pkt->q5, IEEE1394_OCTLET);
			cmd->cmd_u.l64.old_value = HCI1394_ARITH_LOCK_SWAP64(
			    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.old_value);

		/*
		 * we sent out a request that was NOT a lock request and got
		 * back a lock response.
		 */
		} else {
			(*hcicmd)->ac_status = H1394_CMD_EDEVICE_ERROR;
			return (DDI_SUCCESS);
		}
		break;

	default:
		/* we got a tcode that we don't know about. Return error */
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read()
 *    Read ARREQ in from memory into a 1394 Framework command. Allocate a 1394
 *    framework command, read in the ARREQ, and before passing it up to the
 *    services layer, see if it was a valid broadcast request.
 *
 *    The only time this routine should return DDI_FAILURE is if it was unable
 *    to maintain a good state in the ARREQ Q (i.e. an unknown request was
 *    received and we can not cleanup after it.)  If we detect a recoverable
 *    error we should return DDI_SUCCESS with hcicmd = NULL.
 */
static int
hci1394_async_arreq_read(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, uint_t *tcode, hci1394_async_cmd_t **hcicmd,
    uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	boolean_t is_reset_token;
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(tcode != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* read in the arresp tcode */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	*tcode = HCI1394_DESC_TCODE_GET(quadlet);

	/*
	 * Allocated 1394 framework command.  The Services layer takes care of
	 * cacheing commands. This is called during interrupt processing so we
	 * do not want to sleep.
	 */
	status = h1394_alloc_cmd(async_handle->as_drvinfo->di_sl_private,
	    H1394_ALLOC_CMD_NOSLEEP, &cmd, &cmd_priv);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Initialize the HAL private command info */
	hci1394_async_hcicmd_init(async_handle, cmd, cmd_priv, hcicmd);

	/*
	 * There are two generations in the command structure, one in the public
	 * space and one in the HAL/SL private shared space. We need to fill in
	 * both.  We only use the private one internally.
	 */
	cmd_priv->bus_generation = async_handle->as_drvinfo->di_gencnt;
	cmd->bus_generation = async_handle->as_drvinfo->di_gencnt;

	/*
	 * Read the request (based on which kind of request it is) into the 1394
	 * framework command.
	 */
	switch (*tcode) {
	case IEEE1394_TCODE_READ_QUADLET:
		/*
		 * We got a ARREQ quadlet read request. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_qrd(async_handle, pkt,
		    *hcicmd, size);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_WRITE_QUADLET:
		/*
		 * We got a ARREQ quadlet write request. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_qwr(async_handle, pkt,
		    *hcicmd, size);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_READ_BLOCK:
		/*
		 * We got a ARREQ block read request. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_brd(async_handle, pkt,
		    *hcicmd, size);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_WRITE_BLOCK:
		/*
		 * We got a ARREQ block write request. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_bwr(async_handle, pkt,
		    *hcicmd, size);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_LOCK:
		/*
		 * We got a ARREQ lock request. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_lck(async_handle, pkt,
		    *hcicmd, size);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	case IEEE1394_TCODE_PHY:
		/*
		 * We got a PHY packet in the ARREQ buffer. Read in the packet.
		 * If there is a problem with the packet (i.e. we don't get
		 * DDI_SUCCESS), we will free up the command and return NULL in
		 * hcicmd to indicate that we did not get a valid ARREQ to
		 * process.
		 */
		status = hci1394_async_arreq_read_phy(async_handle, pkt,
		    *hcicmd, size, &is_reset_token);
		if (status != DDI_SUCCESS) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}

		/*
		 * If we got a bus reset token, free up the command and return
		 * NULL in hcicmd to indicate that we did not get a valid ARREQ
		 * to process.
		 */
		if (is_reset_token == B_TRUE) {
			hci1394_async_response_complete(async_handle, cmd,
			    cmd_priv);
			*hcicmd = NULL;
			return (DDI_SUCCESS);
		}
		break;

	default:
		/* we got a tcode that we don't know about. Return error */
		return (DDI_FAILURE);
	}

	/*
	 * If this command was broadcast and it was not a write, drop the
	 * command since it's an invalid request. We will free up the command
	 * and return NULL in hcicmd to indicate that we did not get a valid
	 * ARREQ to process.
	 */
	if ((((*hcicmd)->ac_dest & IEEE1394_NODE_NUM_MASK) ==
	    IEEE1394_BROADCAST_NODEID) && ((*tcode !=
	    IEEE1394_TCODE_WRITE_QUADLET) && (*tcode !=
	    IEEE1394_TCODE_WRITE_BLOCK))) {
		hci1394_async_response_complete(async_handle, cmd, cmd_priv);
		*hcicmd = NULL;
		return (DDI_SUCCESS);

	/*
	 * It is a valid broadcast command, set that field in the public
	 * command structure.
	 */
	} else if ((((*hcicmd)->ac_dest & IEEE1394_NODE_NUM_MASK) ==
	    IEEE1394_BROADCAST_NODEID)) {
		cmd->broadcast = 1;
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_qrd()
 *    Read ARREQ quadlet read into the 1394 Framework command. This routine will
 *    return DDI_FAILURE if it was not able to read the request succesfully.
 */
static int
hci1394_async_arreq_read_qrd(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* Setup shortcuts, command type, and size of request */
	cmd = hcicmd->ac_cmd;
	cmd_priv = hcicmd->ac_priv;
	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;
	*size = DESC_SZ_AR_READQUAD_REQ;

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * calculate the ATRESP timeout for when we send it.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q4);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	cmd_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_qcmd.qc_timestamp = hci1394_async_timeout_calc(async_handle,
	    cmd_priv->recv_tstamp);

	/*
	 * if the ARREQ ACK was bad, we were unable to successfully read in this
	 * request.  Return failure.
	 */
	if ((hcicmd->ac_status != OHCI_ACK_COMPLETE) &&
	    (hcicmd->ac_status != OHCI_ACK_PENDING)) {
		return (DDI_FAILURE);
	}

	/*
	 * Read in the tlabel and destination. We don't use an mblk for this
	 * request.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	hcicmd->ac_dest = HCI1394_DESC_DESTID_GET(quadlet);
	hcicmd->ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);
	hcicmd->ac_mblk_alloc = B_FALSE;

	/*
	 * Read in the sender so we know who to send the ATRESP to and read in
	 * the 1394 48-bit address for this request.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	cmd->nodeID = HCI1394_DESC_SRCID_GET(quadlet);
	cmd->cmd_addr = HCI1394_TO_ADDR_HI(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);
	cmd->cmd_addr |= HCI1394_TO_ADDR_LO(quadlet);

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_qwr()
 *    Read ARREQ quadlet write into the 1394 Framework command. This routine
 *    will return DDI_FAILURE if it was not able to read the request
 *    succesfully.
 */
static int
hci1394_async_arreq_read_qwr(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* Setup shortcuts, command type, and size of request */
	cmd = hcicmd->ac_cmd;
	cmd_priv = hcicmd->ac_priv;
	cmd->cmd_type = CMD1394_ASYNCH_WR_QUAD;
	*size = DESC_SZ_AR_WRITEQUAD_REQ;

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * calculate the ATRESP timeout for when we send it.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q5);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	cmd_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_qcmd.qc_timestamp = hci1394_async_timeout_calc(async_handle,
	    cmd_priv->recv_tstamp);

	/*
	 * if the ARREQ ACK was bad, we were unable to successfully read in this
	 * request.  Return failure.
	 */
	if ((hcicmd->ac_status != OHCI_ACK_COMPLETE) &&
	    (hcicmd->ac_status != OHCI_ACK_PENDING)) {
		return (DDI_FAILURE);
	}

	/*
	 * Read in the tlabel and destination. We don't use an mblk for this
	 * request.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	hcicmd->ac_dest = HCI1394_DESC_DESTID_GET(quadlet);
	hcicmd->ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);
	hcicmd->ac_mblk_alloc = B_FALSE;

	/*
	 * Read in the sender so we know who to send the ATRESP to. Read in
	 * the 1394 48-bit address for this request. Copy the data quadlet into
	 * the command.  The data quadlet is treated like a byte stream.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	cmd->nodeID = HCI1394_DESC_SRCID_GET(quadlet);
	cmd->cmd_addr = HCI1394_TO_ADDR_HI(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);
	cmd->cmd_addr |= HCI1394_TO_ADDR_LO(quadlet);
	hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
	    (uint8_t *)&cmd->cmd_u.q.quadlet_data, (uint8_t *)&pkt->q4,
	    IEEE1394_QUADLET);

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_brd()
 *    Read ARREQ block read into the 1394 Framework command. This routine will
 *    return DDI_FAILURE if it was not able to read the request succesfully.
 */
static int
hci1394_async_arreq_read_brd(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* Setup shortcuts, command type, and size of request */
	cmd = hcicmd->ac_cmd;
	cmd_priv = hcicmd->ac_priv;
	cmd->cmd_type = CMD1394_ASYNCH_RD_BLOCK;
	*size = DESC_SZ_AR_READBLOCK_REQ;

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * calculate the ATRESP timeout for when we send it.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q5);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	cmd_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_qcmd.qc_timestamp = hci1394_async_timeout_calc(async_handle,
	    cmd_priv->recv_tstamp);

	/*
	 * if the ARREQ ACK was bad, we were unable to successfully read in this
	 * request.  Return failure.
	 */
	if ((hcicmd->ac_status != OHCI_ACK_COMPLETE) &&
	    (hcicmd->ac_status != OHCI_ACK_PENDING)) {
		return (DDI_FAILURE);
	}

	/* Read in the tlabel and destination */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	hcicmd->ac_dest = HCI1394_DESC_DESTID_GET(quadlet);
	hcicmd->ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);

	/*
	 * Read in the sender so we know who to send the ATRESP to. Read in
	 * the 1394 48-bit address for this request. Read in the block data size
	 * and allocate an mblk of that size.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	cmd->nodeID = HCI1394_DESC_SRCID_GET(quadlet);
	cmd->cmd_addr = HCI1394_TO_ADDR_HI(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);
	cmd->cmd_addr |= HCI1394_TO_ADDR_LO(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q4);
	cmd->cmd_u.b.blk_length = HCI1394_DESC_DATALEN_GET(quadlet);
	cmd->cmd_u.b.data_block = allocb(cmd->cmd_u.b.blk_length, 0);
	if (cmd->cmd_u.b.data_block == NULL) {
		return (DDI_FAILURE);
	}
	hcicmd->ac_mblk_alloc = B_TRUE;

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_bwr()
 *    Read ARREQ block write into the 1394 Framework command. This routine will
 *    return DDI_FAILURE if it was not able to read the request succesfully.
 */
static int
hci1394_async_arreq_read_bwr(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	uint32_t *local_addr;
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/*
	 * Setup shortcuts, command type, and size of request. The size of the
	 * request is in quadlets, therefore we need to make sure we count in
	 * the padding when figureing out the size (i.e. data may be in bytes
	 * but the HW always pads to quadlets)
	 */
	cmd = hcicmd->ac_cmd;
	cmd_priv = hcicmd->ac_priv;
	cmd->cmd_type = CMD1394_ASYNCH_WR_BLOCK;
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q4);
	cmd->cmd_u.b.blk_length = HCI1394_DESC_DATALEN_GET(quadlet);
	*size = DESC_SZ_AR_WRITEBLOCK_REQ +
	    HCI1394_ALIGN_QUAD(cmd->cmd_u.b.blk_length);

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * calculate the ATRESP timeout for when we send it. The status word is
	 * the last quadlet in the packet.
	 */
	local_addr = (uint32_t *)(((uintptr_t)(&pkt->q5)) +
	    ((uintptr_t)HCI1394_ALIGN_QUAD(cmd->cmd_u.b.blk_length)));
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, local_addr);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	cmd_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_qcmd.qc_timestamp = hci1394_async_timeout_calc(async_handle,
	    cmd_priv->recv_tstamp);

	/*
	 * if the ARREQ ACK was bad, we were unable to successfully read in this
	 * request.  Return failure.
	 */
	if ((hcicmd->ac_status != OHCI_ACK_COMPLETE) &&
	    (hcicmd->ac_status != OHCI_ACK_PENDING)) {
		return (DDI_FAILURE);
	}

	/* Read in the tlabel and destination */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	hcicmd->ac_dest = HCI1394_DESC_DESTID_GET(quadlet);
	hcicmd->ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);

	/*
	 * Read in the sender so we know who to send the ATRESP to. Read in
	 * the 1394 48-bit address for this request. Read in the block data size
	 * and allocate an mblk of that size.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	cmd->nodeID = HCI1394_DESC_SRCID_GET(quadlet);
	cmd->cmd_addr = HCI1394_TO_ADDR_HI(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);
	cmd->cmd_addr |= HCI1394_TO_ADDR_LO(quadlet);
	cmd->cmd_u.b.data_block = allocb(cmd->cmd_u.b.blk_length, 0);
	if (cmd->cmd_u.b.data_block == NULL) {
		return (DDI_FAILURE);
	}
	hcicmd->ac_mblk_alloc = B_TRUE;

	/* Copy ARREQ write data into mblk_t */
	hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
	    (uint8_t *)cmd->cmd_u.b.data_block->b_wptr,
	    (uint8_t *)&pkt->q5, cmd->cmd_u.b.blk_length);

	/* Update mblk_t wptr */
	cmd->cmd_u.b.data_block->b_wptr += cmd->cmd_u.b.blk_length;

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_lck()
 *    Read ARREQ lock request into the 1394 Framework command. This routine will
 *    return DDI_FAILURE if it was not able to read the request succesfully.
 */
static int
hci1394_async_arreq_read_lck(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size)
{
	h1394_cmd_priv_t *cmd_priv;
	uint32_t *local_addr;
	cmd1394_cmd_t *cmd;
	uint8_t *data_addr;
	uint32_t quadlet;
	uint32_t length;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/*
	 * Setup shortcuts, command type, and size of request. The size of the
	 * request is in quadlets, therefore we need to make sure we count in
	 * the padding when figuring out the size (i.e. data may be in bytes
	 * but the HW always pads to quadlets)
	 */
	cmd = hcicmd->ac_cmd;
	cmd_priv = hcicmd->ac_priv;
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q4);
	length = HCI1394_DESC_DATALEN_GET(quadlet);
	*size = DESC_SZ_AR_LOCK_REQ + HCI1394_ALIGN_QUAD(length);

	/* make sure the length is a valid lock request length */
	if (length == DESC_TWO_QUADS) {
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;
		cmd->cmd_u.l32.lock_type = HCI1394_DESC_EXTTCODE_GET(quadlet);
	} else if (length == DESC_TWO_OCTLETS) {
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_64;
		cmd->cmd_u.l64.lock_type = HCI1394_DESC_EXTTCODE_GET(quadlet);
	} else {
		return (DDI_FAILURE);
	}

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * calculate the ATRESP timeout for when we send it. The status word is
	 * the last quadlet in the packet.
	 */
	local_addr = (uint32_t *)(((uintptr_t)(&pkt->q5)) +
	    ((uintptr_t)HCI1394_ALIGN_QUAD(length)));
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, local_addr);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	cmd_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	cmd_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_qcmd.qc_timestamp = hci1394_async_timeout_calc(async_handle,
	    cmd_priv->recv_tstamp);

	/*
	 * if the ARREQ ACK was bad, we were unable to successfully read in this
	 * request.  Return failure.
	 */
	if ((hcicmd->ac_status != OHCI_ACK_COMPLETE) &&
	    (hcicmd->ac_status != OHCI_ACK_PENDING)) {
		return (DDI_FAILURE);
	}

	/* Read in the tlabel and destination */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q1);
	hcicmd->ac_dest = HCI1394_DESC_DESTID_GET(quadlet);
	hcicmd->ac_tlabel.tbi_tlabel = HCI1394_DESC_TLABEL_GET(quadlet);
	hcicmd->ac_mblk_alloc = B_FALSE;

	/*
	 * Read in the sender so we know who to send the ATRESP to. Read in
	 * the 1394 48-bit address for this request.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	cmd->nodeID = HCI1394_DESC_SRCID_GET(quadlet);
	cmd->cmd_addr = HCI1394_TO_ADDR_HI(quadlet);
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);
	cmd->cmd_addr |= HCI1394_TO_ADDR_LO(quadlet);

	/* Copy ARREQ lock data into 1394 framework command */
	if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		data_addr = (uint8_t *)&pkt->q5;
		hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
		    (uint8_t *)&cmd->cmd_u.l32.arg_value, data_addr,
		    IEEE1394_QUADLET);
		data_addr = (uint8_t *)((uintptr_t)data_addr +
		    (uintptr_t)IEEE1394_QUADLET);
		hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
		    (uint8_t *)&cmd->cmd_u.l32.data_value, data_addr,
		    IEEE1394_QUADLET);
		/*
		 * swap these for our correct architecture if we are doing
		 * arithmetic lock operations
		 */
		cmd->cmd_u.l32.arg_value = HCI1394_ARITH_LOCK_SWAP32(
		    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.arg_value);
		cmd->cmd_u.l32.data_value = HCI1394_ARITH_LOCK_SWAP32(
		    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.data_value);
	} else if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) {
		data_addr = (uint8_t *)&pkt->q5;
		hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
		    (uint8_t *)&cmd->cmd_u.l64.arg_value, data_addr,
		    IEEE1394_OCTLET);
		data_addr = (uint8_t *)((uintptr_t)data_addr +
		    (uintptr_t)IEEE1394_OCTLET);
		hci1394_q_ar_rep_get8(async_handle->as_arreq_q,
		    (uint8_t *)&cmd->cmd_u.l64.data_value, data_addr,
		    IEEE1394_OCTLET);

		/*
		 * swap these for our correct architecture if we are doing
		 * arithmetic lock operations
		 */
		cmd->cmd_u.l64.arg_value = HCI1394_ARITH_LOCK_SWAP64(
		    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.arg_value);
		cmd->cmd_u.l64.data_value = HCI1394_ARITH_LOCK_SWAP64(
		    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.data_value);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_arreq_read_phy()
 *    Read ARREQ PHY quadlet into the 1394 Framework command. This routine will
 *    return DDI_FAILURE if it was not able to read the request succesfully.
 */
static int
hci1394_async_arreq_read_phy(hci1394_async_handle_t async_handle,
    hci1394_basic_pkt_t *pkt, hci1394_async_cmd_t *hcicmd, uint_t *size,
    boolean_t *bus_reset_token)
{
	cmd1394_cmd_t *cmd;
	uint32_t quadlet;
	uint32_t data1;
	uint32_t data2;


	ASSERT(async_handle != NULL);
	ASSERT(pkt != NULL);
	ASSERT(hcicmd != NULL);
	ASSERT(size != NULL);

	/* Setup shortcuts, command type, and size of request */
	cmd = hcicmd->ac_cmd;
	cmd->cmd_type = CMD1394_ASYNCH_WR_QUAD;
	*size = DESC_SZ_AR_PHY;

	/*
	 * read in the ARREQ ACK/EVT, the speed, the time we received it, and
	 * set state that we do not use an mblk for this request.
	 */
	quadlet = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q4);
	hcicmd->ac_status = HCI1394_DESC_EVT_GET(quadlet);
	hcicmd->ac_priv->speed = HCI1394_DESC_AR_SPD_GET(quadlet);
	hcicmd->ac_priv->recv_tstamp = HCI1394_DESC_TIMESTAMP_GET(quadlet);
	hcicmd->ac_mblk_alloc = B_FALSE;

	/* Read in the PHY packet quadlet and its check quadlet */
	data1 = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q2);
	data2 = hci1394_q_ar_get32(async_handle->as_arreq_q, &pkt->q3);

	/*
	 * if this is a bus reset token, save away the generation. If the bus
	 * reset token is for the current generation, we do not need to flush
	 * the ARREQ Q anymore.
	 */
	if (hcicmd->ac_status == OHCI_EVT_BUS_RESET) {
		*bus_reset_token = B_TRUE;
		async_handle->as_phy_reset = HCI1394_DESC_PHYGEN_GET(data2);
		if (async_handle->as_phy_reset == hci1394_ohci_current_busgen(
		    async_handle->as_ohci)) {
			async_handle->as_flushing_arreq = B_FALSE;
		}
		return (DDI_SUCCESS);
	}

	*bus_reset_token = B_FALSE;

	/* if there is a data error in the PHY packet, return failure */
	if (data1 != ~data2) {
		return (DDI_FAILURE);
	}

	/* Copy the PHY quadlet to the command */
	cmd->cmd_u.q.quadlet_data = data1;

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_phy()
 *    Queue up ATREQ phy packet.
 */
int
hci1394_async_phy(hci1394_async_handle_t async_handle, cmd1394_cmd_t *cmd,
    h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	hci1394_async_cmd_t *hcicmd;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/* Initialize the private HAL command structure */
	hci1394_async_hcicmd_init(async_handle, cmd, cmd_priv, &hcicmd);

	/* We do not allocate a tlabel for a PHY packet */
	hcicmd->ac_tlabel_alloc = B_FALSE;

	/*
	 * Setup the packet header information for a ATREQ PHY packet Add in
	 * the tcode, phy quadlet, and it's 1's complement.
	 */
	header.q1 = DESC_ATREQ_Q1_PHY;
	header.q2 = cmd->cmd_u.q.quadlet_data;
	header.q3 = ~header.q2;

	/* Write request into the ATREQ Q. If we fail, we're out of space */
	status = hci1394_q_at(async_handle->as_atreq_q, &hcicmd->ac_qcmd,
	    &header, DESC_PKT_HDRLEN_AT_PHY, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_write()
 *    Queue up ATREQ write. This could be either a block write or a quadlet
 *    write.
 */
int
hci1394_async_write(hci1394_async_handle_t async_handle, cmd1394_cmd_t *cmd,
    h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_async_cmd_t *hcicmd;
	hci1394_basic_pkt_t header;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/* Initialize the private HAL command structure */
	hci1394_async_hcicmd_init(async_handle, cmd, cmd_priv, &hcicmd);
	hcicmd->ac_dest = (uint_t)(cmd->cmd_addr >> IEEE1394_ADDR_PHY_ID_SHIFT);

	/* allocate a tlabel for this request */
	status = hci1394_tlabel_alloc(async_handle->as_tlabel, hcicmd->ac_dest,
	    &hcicmd->ac_tlabel);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_EMPTY_TLABEL;
		return (DDI_FAILURE);
	}

	/*
	 * Setup the packet header information for a ATREQ write packet. We
	 * will set the tcode later on since this could be a block write or
	 * a quadlet write. Set SRCBusId if this write is not a local bus
	 * access. Copy in the speed, tlabel, and destination address.
	 */
	header.q1 = 0;
	if ((hcicmd->ac_dest & IEEE1394_BUS_NUM_MASK) !=
	    IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (uint32_t)(cmd->cmd_addr >> 32);
	header.q3 = (uint32_t)(cmd->cmd_addr & DESC_PKT_DESTOFFLO_MASK);

	/* Register this command w/ its tlabel */
	hci1394_tlabel_register(async_handle->as_tlabel, &hcicmd->ac_tlabel,
	    hcicmd);

	/* If this is a quadlet write ATREQ */
	if (cmd->cmd_type == CMD1394_ASYNCH_WR_QUAD) {
		/*
		 * setup the tcode for a quadlet write request and copy in
		 * the quadlet data. Endian issues will be taken care of in
		 * hci1394_q_at().
		 */
		header.q1 |= DESC_ATREQ_Q1_QWR;
		header.q4 = cmd->cmd_u.q.quadlet_data;

		/*
		 * Write the request into the ATREQ Q. If we fail, we are out
		 * of space.
		 */
		status = hci1394_q_at(async_handle->as_atreq_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_WRITEQUAD,
		    result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

	/* This is a block write ATREQ */
	} else {
		/* setup the tcode and the length of the block write */
		header.q1 |= DESC_ATREQ_Q1_BWR;
		header.q4 = HCI1394_DESC_DATALEN_SET(cmd_priv->mblk.length);

		/*
		 * Write the request into the ATREQ Q. If we fail, we are out
		 * of space. The data is in a mblk(s). We use a special
		 * interface in the HAL/SL private command block to handle
		 * partial transfers out of the mblk due to packet size
		 * restrictions.
		 */
		status = hci1394_q_at_with_mblk(async_handle->as_atreq_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_WRITEBLOCK,
		    &cmd_priv->mblk, result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_read()
 *    Queue up ATREQ read. This could be either a block read or a quadlet
 *    read.
 */
int
hci1394_async_read(hci1394_async_handle_t async_handle, cmd1394_cmd_t *cmd,
    h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	int status;
	hci1394_async_cmd_t *hcicmd;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/* Initialize the private HAL command structure */
	hci1394_async_hcicmd_init(async_handle, cmd, cmd_priv, &hcicmd);
	hcicmd->ac_dest = (uint_t)(cmd->cmd_addr >> IEEE1394_ADDR_PHY_ID_SHIFT);

	/* allocate a tlabel for this request */
	status = hci1394_tlabel_alloc(async_handle->as_tlabel, hcicmd->ac_dest,
	    &hcicmd->ac_tlabel);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_EMPTY_TLABEL;
		return (DDI_FAILURE);
	}

	/*
	 * Setup the packet header information for a ATREQ read packet. We
	 * will set the tcode later on since this could be a block read or
	 * a quadlet read. Set SRCBusId if this read is not a local bus
	 * access. Copy in the speed, tlabel, and destination address.
	 */
	header.q1 = 0;
	if ((hcicmd->ac_dest & IEEE1394_BUS_NUM_MASK) !=
	    IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (uint32_t)(cmd->cmd_addr >> 32);
	header.q3 = (uint32_t)(cmd->cmd_addr & DESC_PKT_DESTOFFLO_MASK);

	/* Register this command w/ its tlabel */
	hci1394_tlabel_register(async_handle->as_tlabel, &hcicmd->ac_tlabel,
	    hcicmd);

	/* If this is a quadlet read ATREQ */
	if (cmd->cmd_type == CMD1394_ASYNCH_RD_QUAD) {
		/* setup the tcode for a quadlet read request */
		header.q1 |= DESC_ATREQ_Q1_QRD;
		header.q4 = 0;

		/*
		 * Write the request into the ATREQ Q. If we fail, we are out
		 * of space.
		 */
		status = hci1394_q_at(async_handle->as_atreq_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_READQUAD,
		    result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

	} else {
		/* setup the tcode and the length of the block read */
		header.q1 |= DESC_ATREQ_Q1_BRD;
		header.q4 = HCI1394_DESC_DATALEN_SET(cmd_priv->mblk.length);

		/*
		 * Write the request into the ATREQ Q. If we fail, we are out
		 * of space.
		 */
		status = hci1394_q_at(async_handle->as_atreq_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_READBLOCK,
		    result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_lock()
 *    Queue up ATREQ lock. This could be either a 32-bit or 64-bit lock
 *    request.
 */
int
hci1394_async_lock(hci1394_async_handle_t async_handle, cmd1394_cmd_t *cmd,
    h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	hci1394_async_cmd_t *hcicmd;
	uint32_t data32[2];
	uint64_t data64[2];
	uint8_t *datap;
	uint_t size;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/* Initialize the private HAL command structure */
	hci1394_async_hcicmd_init(async_handle, cmd, cmd_priv, &hcicmd);
	hcicmd->ac_dest = (uint_t)(cmd->cmd_addr >> IEEE1394_ADDR_PHY_ID_SHIFT);

	/* allocate a tlabel for this request */
	status = hci1394_tlabel_alloc(async_handle->as_tlabel, hcicmd->ac_dest,
	    &hcicmd->ac_tlabel);
	if (status != DDI_SUCCESS) {
		*result = H1394_STATUS_EMPTY_TLABEL;
		return (DDI_FAILURE);
	}

	/* Register this command w/ its tlabel */
	hci1394_tlabel_register(async_handle->as_tlabel, &hcicmd->ac_tlabel,
	    hcicmd);

	/*
	 * Setup the packet header information for a ATREQ lock packet. Set
	 * the tcode up as a lock request. Set SRCBusId if this lock is not a
	 * local bus access. Copy in the speed, tlabel, and destination
	 * address.
	 */
	header.q1 = DESC_ATREQ_Q1_LCK;
	if ((hcicmd->ac_dest & IEEE1394_BUS_NUM_MASK) !=
	    IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (uint32_t)(cmd->cmd_addr >> 32);
	header.q3 = (uint32_t)(cmd->cmd_addr & DESC_PKT_DESTOFFLO_MASK);

	/*
	 * Setup the lock length based on what size lock operation we are
	 * performing. If it isn't a lock32 or lock64, we have encountered an
	 * internal error. Copy the lock data into a local data buffer. Perform
	 * a byte swap if it is an arithmetic lock operation and we are on a
	 * little endian machine.
	 */
	if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		size = DESC_TWO_QUADS;
		header.q4 = HCI1394_DESC_DATALEN_SET(size) |
		    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l32.lock_type);
		data32[0] = HCI1394_ARITH_LOCK_SWAP32(
		    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.arg_value);
		data32[1] = HCI1394_ARITH_LOCK_SWAP32(
		    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.data_value);
		datap = (uint8_t *)data32;
	} else if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) {
		size = DESC_TWO_OCTLETS;
		header.q4 = HCI1394_DESC_DATALEN_SET(size) |
		    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l64.lock_type);
		data64[0] = HCI1394_ARITH_LOCK_SWAP64(
		    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.arg_value);
		data64[1] = HCI1394_ARITH_LOCK_SWAP64(
		    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.data_value);
		datap = (uint8_t *)data64;
	} else {
		*result = H1394_STATUS_INTERNAL_ERROR;
		return (DDI_FAILURE);
	}

	/* Write request into the ATREQ Q. If we fail, we're out of space */
	status = hci1394_q_at_with_data(async_handle->as_atreq_q,
	    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_LOCK, datap, size,
	    result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_write_response()
 *    Send a write ATRESP. This routine should be called from the Services
 *    layer to send a response to a received write request (ARREQ). The same
 *    response is sent to a quadlet and block write request.
 */
int
hci1394_async_write_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	int status;
	hci1394_async_cmd_t *hcicmd;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/*
	 * setup a shortcut to the hal private command area. Copy the generation
	 * to the Q area so that we can check the generation when the AT Q is
	 * locked. This prevents us from loosing commands due to race
	 * conditions.
	 */
	hcicmd = (hci1394_async_cmd_t *)cmd_priv->hal_overhead;
	hcicmd->ac_qcmd.qc_generation = cmd_priv->bus_generation;

	/*
	 * Setup the packet header information for a ATRESP write packet. Set
	 * the tcode for a write response. Set SRCBusId if the addr is not a
	 * local bus address. Copy in the speed, tlabel, and response code.
	 */
	header.q1 = DESC_ATRESP_Q1_WR;
	if ((cmd->nodeID & IEEE1394_BUS_NUM_MASK) != IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (HCI1394_DESC_DESTID_SET(cmd->nodeID) |
	    HCI1394_DESC_RCODE_SET(cmd->cmd_result));
	header.q3 = 0;

	/* Write response into the ATRESP Q. If we fail, we're out of space */
	status = hci1394_q_at(async_handle->as_atresp_q, &hcicmd->ac_qcmd,
	    &header, DESC_PKT_HDRLEN_AT_WRITE_RESP, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_read_response()
 *    Send a read ATRESP. This routine should be called from the Services
 *    layer to send a response to a received read request (ARREQ). The
 *    response will differ between quadlet/block read requests.
 */
int
hci1394_async_read_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	int status;
	hci1394_async_cmd_t *hcicmd;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/*
	 * setup a shortcut to the hal private command area. Copy the generation
	 * to the Q area so that we can check the generation when the AT Q is
	 * locked. This prevents us from loosing commands due to race
	 * conditions.
	 */
	hcicmd = (hci1394_async_cmd_t *)cmd_priv->hal_overhead;
	hcicmd->ac_qcmd.qc_generation = cmd_priv->bus_generation;

	/*
	 * Setup the packet header information for a ATRESP read packet. we
	 * will set the tcode later based on type of read response. Set
	 * SRCBusId if the addr is not a local bus address. Copy in the
	 * speed, tlabel, and response code.
	 */
	header.q1 = 0;
	if ((cmd->nodeID & IEEE1394_BUS_NUM_MASK) != IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (uint32_t)(HCI1394_DESC_DESTID_SET(cmd->nodeID) |
	    HCI1394_DESC_RCODE_SET(cmd->cmd_result));
	header.q3 = 0;

	/* if the response is a read quadlet response */
	if (cmd->cmd_type == CMD1394_ASYNCH_RD_QUAD) {
		/*
		 * setup the tcode for a quadlet read response, If the
		 * response code is not resp complete.
		 */
		header.q1 |= DESC_ATRESP_Q1_QRD;
		if (cmd->cmd_result == IEEE1394_RESP_COMPLETE) {
			header.q4 = cmd->cmd_u.q.quadlet_data;
		} else {
			header.q4 = 0x0;
		}

		/*
		 * Write response into the ATRESP Q. If we fail, we're out of
		 * space.
		 */
		status = hci1394_q_at(async_handle->as_atresp_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_READQUAD_RESP,
		    result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

	/*
	 * the response is a block read response. If the result is not a
	 * resp complete, we are not going to send any data back.
	 */
	} else if ((cmd->cmd_type == CMD1394_ASYNCH_RD_BLOCK) &&
	    (cmd->cmd_result != IEEE1394_RESP_COMPLETE)) {
		/*
		 * Setup the tcode for a block read response, set the data
		 * length to zero since we had an error.
		 */
		header.q1 |= DESC_ATRESP_Q1_BRD;
		header.q4 = 0x0;

		/*
		 * Write response into the ATRESP Q. If we fail, we're out of
		 * space.
		 */
		status = hci1394_q_at(async_handle->as_atresp_q,
		    &hcicmd->ac_qcmd, &header,
		    DESC_PKT_HDRLEN_AT_READBLOCK_RESP, result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

	/*
	 * the response is a block read response with a resp complete for the
	 * response code. Send back the read data.
	 */
	} else {
		/*
		 * Setup the tcode for a block read response, setup the data
		 * length.
		 */
		header.q1 |= DESC_ATRESP_Q1_BRD;
		header.q4 = HCI1394_DESC_DATALEN_SET(cmd->cmd_u.b.blk_length);

		/*
		 * Write response into the ATRESP Q. If we fail, we're out of
		 * space. Use the data in the mblk.
		 */
		status = hci1394_q_at_with_mblk(async_handle->as_atresp_q,
		    &hcicmd->ac_qcmd, &header,
		    DESC_PKT_HDRLEN_AT_READBLOCK_RESP, &cmd_priv->mblk, result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_lock_response()
 *    Send a lock ATRESP. This routine should be called from the Services
 *    layer to send a response to a received lock request (ARREQ). The
 *    response will differ between 32-bit/64-bit lock requests.
 */
int
hci1394_async_lock_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result)
{
	hci1394_basic_pkt_t header;
	hci1394_async_cmd_t *hcicmd;
	uint32_t data32;
	uint64_t data64;
	uint8_t *datap;
	uint_t size;
	int status;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);
	ASSERT(result != NULL);

	/*
	 * make sure this call is during the current bus generation (i.e. no
	 * bus resets have occured since this request was made.
	 */
	if (cmd_priv->bus_generation != hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		*result = H1394_STATUS_INVALID_BUSGEN;
		return (DDI_FAILURE);
	}

	/*
	 * setup a shortcut to the hal private command area. Copy the generation
	 * to the Q area so that we can check the generation when the AT Q is
	 * locked. This prevents us from loosing commands due to race
	 * conditions.
	 */
	hcicmd = (hci1394_async_cmd_t *)cmd_priv->hal_overhead;
	hcicmd->ac_qcmd.qc_generation = cmd_priv->bus_generation;

	/*
	 * Setup the packet header information for a ATRESP lock packet. Set
	 * the tcode for a lock response. Set SRCBusId if the addr is not a
	 * local bus address. Copy in the speed, tlabel, and response code.
	 */
	header.q1 = DESC_ATRESP_Q1_LCK;
	if ((cmd->nodeID & IEEE1394_BUS_NUM_MASK) != IEEE1394_BUS_NUM_MASK) {
		header.q1 |= DESC_AT_SRCBUSID;
	}
	header.q1 |= HCI1394_DESC_AT_SPD_SET(cmd_priv->speed) |
	    HCI1394_DESC_TLABEL_SET(hcicmd->ac_tlabel.tbi_tlabel);
	header.q2 = (uint32_t)(HCI1394_DESC_DESTID_SET(cmd->nodeID) |
	    HCI1394_DESC_RCODE_SET(cmd->cmd_result));
	header.q3 = 0;

	/*
	 * If the lock result is not a resp complete, we are not going to send
	 * any data back.with the response.
	 */
	if (cmd->cmd_result != IEEE1394_RESP_COMPLETE) {
		/* set response size to 0 for error. Set the extended tcode */
		size = 0;
		if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
			header.q4 = HCI1394_DESC_DATALEN_SET(size) |
			    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l32.lock_type);
		} else {
			header.q4 = HCI1394_DESC_DATALEN_SET(size) |
			    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l64.lock_type);
		}

		/*
		 * Write response into the ATRESP Q. If we fail, we're out of
		 * space.
		 */
		status = hci1394_q_at(async_handle->as_atresp_q,
		    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_LOCK_RESP,
		    result);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}

	/*
	 * if the lock result is resp complete, setup the size of the response
	 * depending on the lock size and copy the lock response data into a
	 * local buffer. If the lock response is an arithmetic operation, swap
	 * the data on little endian machines. If we don't know what type of
	 * lock operation it is, someone has corrupted the command since we
	 * had received the ARREQ.
	 */
	if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		size = IEEE1394_QUADLET;
		header.q4 = HCI1394_DESC_DATALEN_SET(size) |
		    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l32.lock_type);
		data32 = HCI1394_ARITH_LOCK_SWAP32(
		    cmd->cmd_u.l32.lock_type, cmd->cmd_u.l32.old_value);
		datap = (uint8_t *)&data32;
	} else if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) {
		size = IEEE1394_OCTLET;
		header.q4 = HCI1394_DESC_DATALEN_SET(size) |
		    HCI1394_DESC_EXTTCODE_SET(cmd->cmd_u.l64.lock_type);
		data64 = HCI1394_ARITH_LOCK_SWAP64(
		    cmd->cmd_u.l64.lock_type, cmd->cmd_u.l64.old_value);
		datap = (uint8_t *)&data64;
	} else {
		*result = H1394_STATUS_INTERNAL_ERROR;
		return (DDI_FAILURE);
	}

	/*
	 * Write response into the ATRESP Q. If we fail, we're out of space.
	 * Use the local data buffer that we copied the data to above.
	 */
	status = hci1394_q_at_with_data(async_handle->as_atresp_q,
	    &hcicmd->ac_qcmd, &header, DESC_PKT_HDRLEN_AT_LOCK_RESP, datap,
	    size, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_response_complete()
 *    Free up space allocted during an ARREQ.  This is called when the target
 *    driver and Services Layer are done with a command which was by the HAL
 *    during ARREQ processing.  This routine will also free up any allocated
 *    mblks.
 *
 *    NOTE: a target driver can hold on to a block write ARREQ mblk by setting
 *    the mblk pointer to NULL.  This ONLY applies to block write ARREQs. The
 *    HAL will no longer track the mblk for this case.
 */
void
hci1394_async_response_complete(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv)
{
	hci1394_async_cmd_t *hcicmd;


	ASSERT(async_handle != NULL);
	ASSERT(cmd != NULL);
	ASSERT(cmd_priv != NULL);

	hcicmd = (hci1394_async_cmd_t *)cmd_priv->hal_overhead;

	/* If we allocated an mblk for this command */
	if (hcicmd->ac_mblk_alloc == B_TRUE) {
		/*
		 * Don't free mblk if it is set to NULL. This allows a target
		 * driver to hold on to it in the case of a block write ARREQ.
		 */
		if (cmd->cmd_u.b.data_block != NULL) {
			freeb(cmd->cmd_u.b.data_block);
		}
	}

	/* free up the 1394 framework command */
	(void) h1394_free_cmd((void *)async_handle->as_drvinfo->di_sl_private,
	    &cmd);
}


/*
 * hci1394_async_pending_timeout()
 *    This is the ARREQ Pending timeout callback routine.  It is called from
 *    the tlist code. There is a race condition with the ARRESP interrupt
 *    handler (hci1394_async_arresp_process) which requires a mutex to
 *    lock around the mark of the bad tlabel.
 *
 *    Once we enter this routine, the command has timed out. If the command is
 *    in both the ARRESP handler and here, we will consider it to have timed
 *    out. That code path handles the race condition more easily.
 */
static void
hci1394_async_pending_timeout(hci1394_tlist_node_t *node, void *arg)
{
	hci1394_async_handle_t async_handle;
	hci1394_async_cmd_t *hcicmd;


	async_handle = (hci1394_async_handle_t)arg;
	ASSERT(async_handle != NULL);
	ASSERT(node != NULL);

	hcicmd = (hci1394_async_cmd_t *)node->tln_addr;

	/*
	 * We do NOT want to set the command state here. That should only be
	 * done in the ISR. The state does nothing for us here.
	 */

	/*
	 * We want a lock around tlabel_lookup/reading data into the cmd in the
	 * ARRESP ISR processing and a lock around the tlabel_bad in this
	 * routine. This ensures that we will not be touching the command
	 * structure after we pass it up to the Services Layer. If we mark it as
	 * bad first, the lookup will fail. If we get to the lookup first, the
	 * pending list delete will fail in arresp_process() which will tell
	 * that guy that we are in the middle of doing the timeout processing
	 * for this command.  The ARRESP logic will just drop the response and
	 * continue on.
	 */
	mutex_enter(&hcicmd->ac_async->as_atomic_lookup);
	hci1394_tlabel_bad(async_handle->as_tlabel, &hcicmd->ac_tlabel);
	mutex_exit(&hcicmd->ac_async->as_atomic_lookup);

	/* Tell the Services Layer that the command has timed out */
	h1394_cmd_is_complete(async_handle->as_drvinfo->di_sl_private,
	    hcicmd->ac_cmd, H1394_AT_REQ, H1394_CMD_ETIMEOUT);
}


/*
 * hci1394_async_timeout_calc()
 *    Calculate the timeout for an ATRESP. When an ARREQ is received, this
 *    routine is called with the time the ARREQ was received. It returns the
 *    time when the ATRESP is considered to have timed out. We timeout after
 *    split_timeout has gone by. Split timeout and the returned value are in bus
 *    cycles.
 */
static uint_t
hci1394_async_timeout_calc(hci1394_async_handle_t async_handle,
    uint_t current_time)
{
	uint_t split_timeout;
	uint_t temp;
	uint_t carry;
	uint_t z;

	/* Get the current split timeout */
	split_timeout = hci1394_csr_split_timeout_get(async_handle->as_csr);

	/*
	 * The cycle count is broken up into two sections, the 3-bit seconds
	 * field and the 13-bit cycle count. The cycle count is in 125uS
	 * increments.  The maximum value of cycle count is 7999 (8000 is one
	 * second). With 13-bits, we could store up to 8191. Therefore, we don't
	 * have a simple 16-bit addition. Hence, the code we see below.
	 */

	/*
	 * calculate the new cycle count based on the cycle count from current
	 * time and the split timeout. If this new value is not greater than the
	 * maximum cycle count, we don't have a carry. Go to the next step.
	 */
	temp = (current_time & OHCI_CYCLE_CNT_MASK) + (split_timeout &
	    OHCI_CYCLE_CNT_MASK);
	if (temp < OHCI_MAX_CYCLE_CNT) {
		carry = 0;

	/*
	 * the new cycle count adds up to more than the maximum cycle count,
	 * set the carry state and adjust the total accordingly.
	 */
	} else {
		temp = temp - OHCI_MAX_CYCLE_CNT;
		carry = 1;
	}

	/*
	 * The timeout time equals the seconds added with the carry (1 or 0
	 * seconds), added with the adjusted (if necessary) cycle count.
	 * Mask the final value to get rid of any second rollovers.
	 */
	z = (current_time & OHCI_CYCLE_SEC_MASK) + (split_timeout &
	    OHCI_CYCLE_SEC_MASK) + (carry << OHCI_CYCLE_SEC_SHIFT) + temp;
	z = z & OHCI_TIMESTAMP_MASK;

	return (z);
}


/*
 * hci1394_async_arresp_size_get()
 *    Return the size of the arresp that was received in q_handle at addr.
 */
static int
hci1394_async_arresp_size_get(uint_t tcode, hci1394_q_handle_t q_handle,
    uint32_t *addr, uint_t *size)
{
	uint_t data_length;
	uint32_t quadlet;


	ASSERT(q_handle != NULL);
	ASSERT(addr != NULL);
	ASSERT(size != NULL);

	if (tcode == IEEE1394_TCODE_WRITE_RESP) {
		*size = DESC_PKT_HDRLEN_AT_WRITE_RESP + IEEE1394_QUADLET;
	} else if (tcode == IEEE1394_TCODE_READ_QUADLET_RESP) {
		*size = DESC_PKT_HDRLEN_AT_READQUAD_RESP + IEEE1394_QUADLET;
	} else if (tcode == IEEE1394_TCODE_READ_BLOCK_RESP) {
		quadlet = hci1394_q_ar_get32(q_handle, &addr[3]);
		data_length = HCI1394_DESC_DATALEN_GET(quadlet);
		/*
		 * response size is in quadlets, therefore we need to
		 * make sure we count in the padding when figuring out
		 * the size used up for this response
		 */
		*size = DESC_PKT_HDRLEN_AT_READBLOCK_RESP +
		    HCI1394_ALIGN_QUAD(data_length) + IEEE1394_QUADLET;
	} else if (tcode == IEEE1394_TCODE_LOCK_RESP) {
		quadlet = hci1394_q_ar_get32(q_handle, &addr[3]);
		data_length = HCI1394_DESC_DATALEN_GET(quadlet);
		/*
		 * response size is in quadlets, therefore we need to
		 * make sure we count in the padding when figuring out
		 * the size used up for this response
		 */
		*size = DESC_PKT_HDRLEN_AT_LOCK_RESP +
		    HCI1394_ALIGN_QUAD(data_length) + IEEE1394_QUADLET;
	} else {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_async_pending_list_flush()
 *    Flush out the ATREQ pending list. All commands still on the ATREQ pending
 *    list are considered to be completed due to a bus reset. The ATREQ and
 *    ARRESP Q's should be flushed before the pending Q is flushed. The ATREQ
 *    could have more ACK pendings and the ARRESP could have valid responses to
 *    pended requests.
 */
void
hci1394_async_pending_list_flush(hci1394_async_handle_t async_handle)
{
	hci1394_tlist_node_t *node;
	hci1394_async_cmd_t *hcicmd;


	ASSERT(async_handle != NULL);

	do {
		/*
		 * get the first node on the pending list. This routine also
		 * removes the node from the list.
		 */
		hci1394_tlist_get(async_handle->as_pending_list, &node);
		if (node != NULL) {
			/* set the command state to completed */
			hcicmd = (hci1394_async_cmd_t *)node->tln_addr;
			hcicmd->ac_state = HCI1394_CMD_STATE_COMPLETED;

			/*
			 * Send the command up to the Services Layer with
			 * completed due to the bus reset for status.
			 */
			h1394_cmd_is_complete(
			    async_handle->as_drvinfo->di_sl_private,
			    hcicmd->ac_cmd, H1394_AT_REQ,
			    H1394_CMD_EBUSRESET);
		}
	} while (node != NULL);
}


/*
 * hci1394_async_atreq_start()
 *    Setup the command pointer for the first descriptor to be fetched and
 *    then set the run bit. This routine will be called the first time
 *    a descriptor is added to the Q.
 */
static void
hci1394_async_atreq_start(void *async, uint32_t command_ptr)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_atreq_start(async_handle->as_ohci, command_ptr);
}


/*
 * hci1394_async_atreq_wake()
 *    Set the wake bit for the ATREQ DMA engine. This routine will be called
 *    from the Q logic after placing a descriptor on the Q.
 */
static void
hci1394_async_atreq_wake(void *async)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_atreq_wake(async_handle->as_ohci);
}


/*
 * hci1394_async_atreq_reset()
 *    Reset the atreq Q.  The AT DMA engines must be stopped every bus reset.
 *    They will restart when the next descriptor is added to the Q. We will stop
 *    the DMA engine and then notify the Q logic that it has been stopped so it
 *    knows to do a start next time it puts a descriptor on the Q.
 */
void
hci1394_async_atreq_reset(hci1394_async_handle_t async_handle)
{
	ASSERT(async_handle != NULL);
	hci1394_ohci_atreq_stop(async_handle->as_ohci);
	hci1394_q_stop(async_handle->as_atreq_q);
}


/*
 * hci1394_async_atreq_flush()
 *    Flush out the atreq Q. This routine is called during bus reset processing.
 *    it should be called before arresp_flush() and pending_list_flush().
 */
static void
hci1394_async_atreq_flush(hci1394_async_handle_t async_handle)
{
	boolean_t request_available;

	ASSERT(async_handle != NULL);

	/* Clear reqTxComplete interrupt */
	hci1394_ohci_intr_clear(async_handle->as_ohci, OHCI_INTR_REQ_TX_CMPLT);

	/*
	 * Processes all Q'd AT requests.  If the request is pended, it is
	 * considered complete relative the the atreq engine.
	 * flush_pending_list() will finish up the required processing for
	 * pended requests.
	 */
	do {
		/* Flush the atreq Q. Process all Q'd commands */
		(void) hci1394_async_atreq_process(async_handle,
		    B_TRUE, &request_available);
	} while (request_available == B_TRUE);
}


/*
 * hci1394_async_arresp_start()
 *    Setup the command pointer for the first descriptor to be fetched and
 *    then set the run bit. This routine will be called the first time
 *    a descriptor is added to the Q.
 */
static void
hci1394_async_arresp_start(void *async, uint32_t command_ptr)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_arresp_start(async_handle->as_ohci, command_ptr);
}


/*
 * hci1394_async_arresp_wake()
 *    Set the wake bit for the ARRESP DMA engine. This routine will be called
 *    from the Q logic after placing a descriptor on the Q.
 */
static void
hci1394_async_arresp_wake(void *async)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_arresp_wake(async_handle->as_ohci);
}


/*
 * hci1394_async_arresp_flush()
 *    Flush out the arresp Q. This routine is called during bus reset
 *    processing. This should be called before pending_list_flush(). All
 *    receive responses will be processed normally. The tlabels should
 *    not be reset until after the ARRESP Q has been flushed. Otherwise
 *    we would reject valid responses.
 */
static void
hci1394_async_arresp_flush(hci1394_async_handle_t async_handle)
{
	boolean_t response_available;

	ASSERT(async_handle != NULL);

	/* Clear reqTxComplete interrupt */
	hci1394_ohci_intr_clear(async_handle->as_ohci, OHCI_INTR_RSPKT);

	do {
		/* Flush the arresp Q. Process all received commands */
		(void) hci1394_async_arresp_process(async_handle,
		    &response_available);
	} while (response_available == B_TRUE);
}


/*
 * hci1394_async_arreq_start()
 *    Setup the command pointer for the first descriptor to be fetched and
 *    then set the run bit. This routine will be called the first time
 *    a descriptor is added to the Q.
 */
static void
hci1394_async_arreq_start(void *async, uint32_t command_ptr)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_arreq_start(async_handle->as_ohci, command_ptr);
}


/*
 * hci1394_async_arreq_wake()
 *    Set the wake bit for the ARREQ DMA engine. This routine will be called
 *    from the Q logic after placing a descriptor on the Q.
 */
static void
hci1394_async_arreq_wake(void *async)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_arreq_wake(async_handle->as_ohci);
}


/*
 * hci1394_async_arreq_flush()
 *    Flush the ARREQ Q. This will flush up to the bus reset token in the
 *    ARREQ. There is no order dependency for when routine should get called
 *    (relative to the other Q flushing routines)
 */
static void
hci1394_async_arreq_flush(hci1394_async_handle_t async_handle)
{
	boolean_t request_available;

	ASSERT(async_handle != NULL);

	/*
	 * If the last bus reset token we have seen in
	 * hci1394_async_arreq_read_phy() matches the current generation, the
	 * ARREQ is already flushed.  We have nothing further to do here so
	 * return. This can happen if we are processing ARREQ's and a bus reset
	 * occurs. Since we are already in the ISR, we will see the token before
	 * the bus reset handler gets to run.
	 */
	if (async_handle->as_phy_reset == hci1394_ohci_current_busgen(
	    async_handle->as_ohci)) {
		return;
	}

	/*
	 * set flag to tell hci1394_async_arreq_process() that we should not
	 * pass ARREQ's up to the Services Layer.  This will be set to B_FALSE
	 * in hci1394_async_arreq_read_phy() when a bus reset token matching
	 * the current generation is found.
	 */
	async_handle->as_flushing_arreq = B_TRUE;

	/*
	 * Process all requests that have been received or until we find the
	 * correct bus reset token.
	 */
	do {
		(void) hci1394_async_arreq_process(async_handle,
		    &request_available);
	} while ((request_available == B_TRUE) &&
	    (async_handle->as_flushing_arreq == B_TRUE));

	/*
	 * Clear the asserted interrupt if there are no more ARREQ's to process.
	 * We could have ARREQ's in the Q after the bus reset token since we
	 * will set as_flushing_arreq to FALSE when we see the correct bus reset
	 * token in hci1394_async_arreq_read_phy(). If there are more ARREQ's,
	 * we will process them later after finishing the reset of bus reset
	 * processing.  That is why we will leave the interrupt asserted.
	 */
	if (request_available == B_FALSE) {
		hci1394_ohci_intr_clear(async_handle->as_ohci, OHCI_INTR_RQPKT);
	}
}


/*
 * hci1394_async_atresp_start()
 *    Setup the command pointer for the first descriptor to be fetched and
 *    then set the run bit. This routine will be called the first time
 *    a descriptor is added to the Q.
 */
static void
hci1394_async_atresp_start(void *async, uint32_t command_ptr)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_atresp_start(async_handle->as_ohci, command_ptr);
}


/*
 * hci1394_async_atresp_wake()
 *    Set the wake bit for the ATRESP DMA engine. This routine will be called
 *    from the Q logic after placing a descriptor on the Q.
 */
static void
hci1394_async_atresp_wake(void *async)
{
	hci1394_async_handle_t async_handle;
	ASSERT(async != NULL);
	async_handle = (hci1394_async_handle_t)async;
	hci1394_ohci_atresp_wake(async_handle->as_ohci);
}


/*
 * hci1394_async_atresp_reset()
 *    Reset the atresp Q.  The AT DMA engines must be stopped every bus reset.
 *    They will restart when the next descriptor is added to the Q. We will stop
 *    the DMA engine and then notify the Q logic that it has been stopped so it
 *    knows to do a start next time it puts a descriptor on the Q.
 */
void
hci1394_async_atresp_reset(hci1394_async_handle_t async_handle)
{
	ASSERT(async_handle != NULL);
	hci1394_ohci_atresp_stop(async_handle->as_ohci);
	hci1394_q_stop(async_handle->as_atresp_q);
}


/*
 * hci1394_async_atresp_flush()
 *    Flush all commands out of the atresp Q. This routine will be called
 *    during bus reset processing. There is no order dependency for when
 *    routine should get called (relative to the other Q flushing routines)
 */
static void
hci1394_async_atresp_flush(hci1394_async_handle_t async_handle)
{
	boolean_t response_available;

	ASSERT(async_handle != NULL);

	/* Clear respTxComplete interrupt */
	hci1394_ohci_intr_clear(async_handle->as_ohci, OHCI_INTR_RESP_TX_CMPLT);

	/* Processes all AT responses */
	do {
		/* Flush the atresp Q. Process all Q'd commands */
		(void) hci1394_async_atresp_process(async_handle,
		    B_TRUE, &response_available);
	} while (response_available == B_TRUE);
}

/*
 * hci1394_async_hcicmd_init()
 *    Initialize the private HAL command structure. This should be called from
 *    ATREQ and ARREQ routines.
 */
static void
hci1394_async_hcicmd_init(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv,
    hci1394_async_cmd_t **hcicmd)
{
	*hcicmd = (hci1394_async_cmd_t *)cmd_priv->hal_overhead;
	(*hcicmd)->ac_cmd = cmd;
	(*hcicmd)->ac_priv = cmd_priv;
	(*hcicmd)->ac_async = async_handle;
	(*hcicmd)->ac_state = HCI1394_CMD_STATE_IN_PROGRESS;
	(*hcicmd)->ac_dest = 0;
	(*hcicmd)->ac_tlabel_alloc = B_TRUE;
	(*hcicmd)->ac_tlabel.tbi_tlabel = 0;
	(*hcicmd)->ac_tlabel.tbi_destination = 0;
	(*hcicmd)->ac_status = 0;
	(*hcicmd)->ac_qcmd.qc_timestamp = 0;
	(*hcicmd)->ac_qcmd.qc_arg = *hcicmd;
	(*hcicmd)->ac_qcmd.qc_generation = cmd_priv->bus_generation;
	(*hcicmd)->ac_mblk_alloc = B_FALSE;
}
