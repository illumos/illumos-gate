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

#ifndef _SYS_1394_ADAPTERS_HCI1394_ASYNC_H
#define	_SYS_1394_ADAPTERS_HCI1394_ASYNC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_async.h
 *   These routines the 1394 asynchronous dma engines.  These include incoming
 *   and outgoing reads, writes, and lock and their associated responses.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>

#include <sys/1394/h1394.h>

#include <sys/1394/adapters/hci1394_def.h>
#include <sys/1394/adapters/hci1394_tlist.h>
#include <sys/1394/adapters/hci1394_q.h>


/*
 * Async descriptor and data buffer sizes. The AR descriptor buffers do not need
 * to be very big.  There will be 1 16 byte IM for every AR data buffer.  If we
 * alloc a 16KByte ARRESP data buffer on X86, we could get 4 4KByte cookies.
 * This would use up 64 bytes in the descriptor buffer. We will never need more
 * space than that.  A 256 byte descriptor should handle a 64K buffer on x86
 * if it is broken into 16 cookies.
 */
#define	ASYNC_ATREQ_DESC_SIZE		16384
#define	ASYNC_ATREQ_DATA_SIZE		16384
#define	ASYNC_ARRESP_DESC_SIZE		256
#define	ASYNC_ARRESP_DATA_SIZE		16384
#define	ASYNC_ARREQ_DESC_SIZE		256
#define	ASYNC_ARREQ_DATA_SIZE		16384
#define	ASYNC_ATRESP_DESC_SIZE		16384
#define	ASYNC_ATRESP_DATA_SIZE		16384


/* handle passed back from init() and used for rest of functions */
typedef struct hci1394_async_s	*hci1394_async_handle_t;

/*
 * Async Command State. This state is used to catch a race condition between
 * the ATREQ complete interrupt handler and the ARRESP interrupt handler. The
 * ATREQ will always complete before the ARRESP arrives, but SW may not see it
 * that way. See hci1394_async_atreq_process() for more information on this.
 */
typedef enum {
	HCI1394_CMD_STATE_IN_PROGRESS,
	HCI1394_CMD_STATE_PENDING,
	HCI1394_CMD_STATE_COMPLETED
} hci1394_async_cstate_t;


typedef struct hci1394_async_cmd_s {
	/* Pointer to framework command allocted by services layer */
	cmd1394_cmd_t 		*ac_cmd;

	/*
	 * Pointer to HAL/SL private area in the command. This is private info
	 * shared between the HAL and Services Layer on a per command basis.
	 */
	h1394_cmd_priv_t	*ac_priv;

	/*
	 * Status on if we allocated a tlabel for an ATREQ. Normally we will
	 * allocate a tlabel with every ATREQ. But, we will not allocate a
	 * tlabel for a PHY packet. When we initialize the command, we will
	 * assume that we are going to allocate a tlabel.  The async phy command
	 * will "override" this setting and set ac_tlabel_alloc to b_false.
	 */
	boolean_t		ac_tlabel_alloc;

	/* handle for tlabel logic */
	hci1394_tlabel_info_t	ac_tlabel;

	/*
	 * This is used for ARREQs. When we get a block read or write request,
	 * we allocate a mblk to put the data into. After the ATRESP has been
	 * sent out and has completed, hci1394_async_response_complete() is
	 * called to free up the ARREQ resources which were allocated. This
	 * routine will free the mblk if we allocated it in ARREQ. If an ARREQ
	 * block write is received and the target driver wishes to keep the
	 * mblk w/ the data (to pass it up a stream), but releases the command,
	 * it can set the mblk pointer in the command to null.  We will check
	 * for mblk being == to NULL even if ac_mblk_alloc is set to true.
	 */
	boolean_t		ac_mblk_alloc;

	/*
	 * ac_status contains the 1394 RESP for an ARRESP or the ACK for ARREQ.
	 * This status is set in either hci1394_async_arresp_read() or
	 * hci1394_arreq_read()
	 */
	int			ac_status;

	/*
	 * Destination packet was sent to. This is used to determine if the
	 * packet was broadcast or not in hci1394_async_arreq_read().
	 */
	uint_t			ac_dest;

	/*
	 * Async command state. See comments above for more information. Other
	 * than initialization, this field is only accessed in the ISR. State
	 * is only used in ATREQ/ARRESP processing.
	 */
	hci1394_async_cstate_t	ac_state;

	/*
	 * Pointer back to the Async private state. This allows us to access
	 * the async state structures if all we have is a pointer to the async
	 * command.
	 */
	struct hci1394_async_s	*ac_async;

	/*
	 * pending list node structure.  If a command is pended, this node is
	 * what's passed to the tlist code to add the node to the pending list.
	 * It contains all the pointers the linked list needs so that we do not
	 * need to allocate any space every time we add something to the list.
	 */
	hci1394_tlist_node_t	ac_plist_node;

	/*
	 * hci1394_q information about this command.  This is used for AT
	 * commands.  It contains information passed down to the hci1394_q_at*()
	 * routines like qc_timestamp which is used to tell the HW when an
	 * ATRESP has timed out out.  The status of the AT command is returned
	 * in qc_status after calling hci1394_q_at_next(). The rest of the
	 * structure members are private members used to track the descriptor
	 * and data buffer usage.
	 */
	hci1394_q_cmd_t		ac_qcmd;
} hci1394_async_cmd_t;

_NOTE(SCHEME_PROTECTS_DATA("Used only by one thread", hci1394_async_cmd_s \
	hci1394_async_cmd_s::ac_qcmd.qc_arg \
	hci1394_async_cmd_s::ac_qcmd.qc_generation \
	hci1394_async_cmd_s::ac_qcmd.qc_timestamp \
	hci1394_async_cmd_s::ac_tlabel_alloc \
	hci1394_async_cmd_s::ac_tlabel.tbi_destination \
	hci1394_async_cmd_s::ac_tlabel.tbi_tlabel))

/*
 * async private state information.  It contains handles for the various modules
 * that async uses.
 */
typedef struct hci1394_async_s {
	hci1394_tlist_handle_t	as_pending_list;
	hci1394_ohci_handle_t	as_ohci;
	hci1394_tlabel_handle_t	as_tlabel;
	hci1394_csr_handle_t	as_csr;
	hci1394_q_handle_t	as_atreq_q;
	hci1394_q_handle_t	as_arresp_q;
	hci1394_q_handle_t	as_arreq_q;
	hci1394_q_handle_t	as_atresp_q;
	hci1394_drvinfo_t	*as_drvinfo;

	/*
	 * as_flushing_arreq is used in bus reset processing. It is set by
	 * hci1394_async_arreq_flush() and tells hci1394_async_arreq_process()
	 * not to send the ARREQ up to the Services Layer. It will be set to
	 * FALSE by hci1394_async_arreq_read_phy() when a bus reset token with
	 * the current bus generation is found. as_phy_reset is used to store
	 * the last PHY packet generation seen in the ARREQ Q. The HW puts a
	 * token in the ARREQ Q so that the SW can flush the Q up to and
	 * including the token.
	 */
	boolean_t		as_flushing_arreq;
	uint_t			as_phy_reset;

	/*
	 * as_atomic_lookup is used to protect the cmd from a race condition
	 * between the ARRESP and the Pending Timeout callback. This is
	 * explained in more detail in hci1394_async_atreq_process().
	 */
	kmutex_t		as_atomic_lookup;
} hci1394_async_t;

_NOTE(SCHEME_PROTECTS_DATA("Used only by one thread", \
	hci1394_async_s::as_flushing_arreq hci1394_async_s::as_phy_reset))

int hci1394_async_init(hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t ohci_handle, hci1394_csr_handle_t csr_handle,
    hci1394_async_handle_t *async_handle);
void hci1394_async_fini(hci1394_async_handle_t *async_handle);
void hci1394_async_suspend(hci1394_async_handle_t async_handle);
int hci1394_async_resume(hci1394_async_handle_t async_handle);
uint_t hci1394_async_cmd_overhead();

void hci1394_async_flush(hci1394_async_handle_t async_handle);
void hci1394_async_atreq_reset(hci1394_async_handle_t async_handle);
void hci1394_async_atresp_reset(hci1394_async_handle_t async_handle);
void hci1394_async_pending_timeout_update(hci1394_async_handle_t async_handle,
    hrtime_t timeout);

int hci1394_async_atreq_process(hci1394_async_handle_t async_handle,
    boolean_t flush_q, boolean_t *request_available);
int hci1394_async_arresp_process(hci1394_async_handle_t async_handle,
    boolean_t *response_available);
int hci1394_async_arreq_process(hci1394_async_handle_t async_handle,
    boolean_t *request_available);
int hci1394_async_atresp_process(hci1394_async_handle_t async_handle,
    boolean_t flush_q, boolean_t *response_available);

int hci1394_async_phy(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_write(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_read(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_lock(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_write_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_read_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
int hci1394_async_lock_response(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv, int *result);
void hci1394_async_response_complete(hci1394_async_handle_t async_handle,
    cmd1394_cmd_t *cmd, h1394_cmd_priv_t *cmd_priv);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_ASYNC_H */
