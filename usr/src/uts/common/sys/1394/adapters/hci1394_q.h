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

#ifndef _SYS_1394_ADAPTERS_HCI1394_Q_H
#define	_SYS_1394_ADAPTERS_HCI1394_Q_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_q.h
 *    This code decouples some of the OpenHCI async descriptor logic/structures
 *    from the async processing.  The goal was to combine as much of the
 *    duplicate code as possible for the different type of async transfers
 *    without going too overboard.
 *
 *    There are two parts to the Q, the descriptor buffer and the data buffer.
 *    for the most part, data to be transmitted and data which is received go
 *    in the data buffers.  The information of where to get the data and put
 *    the data reside in the descriptor buffers. There are exceptions to this.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/note.h>

#include <sys/1394/adapters/hci1394_def.h>
#include <sys/1394/adapters/hci1394_tlist.h>
#include <sys/1394/adapters/hci1394_buf.h>
#include <sys/1394/adapters/hci1394_descriptors.h>


/*
 * Part of q_info passed in during q_init(). This tells us if this is an async
 * transmit or async receive Q. This makes a big difference inside of q. For
 * the transmit Q we will just setup an empty Q ready for TX calls into us. For
 * receive Q's we have to make sure we get multiple data buffers and then setup
 * the buffers so they are ready to receive data (by adding in the IM
 * descriptors).
 */
typedef enum {
	HCI1394_ARQ,
	HCI1394_ATQ
} hci1394_q_mode_t;

/*
 * Part of q_info passed in during q_init().  These are the callbacks for
 * starting and waking up the async Q's.  When the first descriptor is placed
 * on the Q, the async DMA engine is started with an address of where to find
 * the descriptor on the Q.  That descriptor will be changed to point to the
 * next descriptor when the next descriptor is added (i.e. a chained dma).
 * Whenever an additional descriptor is added, wake is called.
 */
typedef void (*hci1394_q_start_t)(void *arg, uint32_t io_addr);
typedef void (*hci1394_q_wake_t)(void *arg);

/*
 * Passed in during q_init().  This contains the size of the descriptor Q, the
 * size of the data Q, what kind of Q it is (AT or AR), the callbacks for start
 * and wake, and the argument to pass during start and wake.
 */
typedef struct hci1394_q_info_s {
	uint_t			qi_desc_size;
	uint_t			qi_data_size;
	hci1394_q_mode_t	qi_mode;
	hci1394_q_start_t	qi_start;
	hci1394_q_wake_t	qi_wake;
	void			*qi_callback_arg;
} hci1394_q_info_t;

/*
 * Per command tracking information for the AT Q's.  This is not used on the AR
 * side.  This structure has two parts to it, the public data and the private
 * data.  The public data is shared between async.c and q.c.  The private data
 * is for internal q.c access only.  It is only put in this structure so that
 * we do not have to dynamically alloc space for each transfer.
 */
typedef struct hci1394_q_cmd_s {

	/* PUBLIC DATA STRUCTURES */
	/*
	 * qc_arg is an input paramter to hci1394_q_at() (along with the data
	 * versions). It is an opaque address pointer which is used by async.c
	 * to determine the commands address after a call to
	 * hci1394_q_at_next().
	 */
	void			*qc_arg;

	/*
	 * qc_generation is an input parameter to hci1394_q_at() (along with the
	 * data versions). It is the generation count for which this command is
	 * valid. If qc_generation does not match the current bus generation,
	 * hci1394_q_at*() will return failure.
	 */
	uint_t			qc_generation;

	/*
	 * qc_timestamp is used when sending an atresp to set the time when the
	 * response is to have timed out.  It is also use on at_next to tell
	 * when the AT command completed.
	 */
	uint_t			qc_timestamp;

	/*
	 * qc_status is an output of hci1394_q_at_next().  It contains the
	 * command status after completion.
	 */
	uint32_t		qc_status;


	/* PRIVATE DATA STRUCTURES */
	/*
	 * This is the memory address of where the status of this command
	 * resides.
	 */
	uint32_t		*qc_status_addr;

	/*
	 * qc_descriptor_end and qc_descriptor_buf are used to track where the
	 * descriptor q pointers should be set to when this command has
	 * completed (i.e. free up the space used by this command)
	 */
	caddr_t			qc_descriptor_end;
	uint_t			qc_descriptor_buf;

	/*
	 * qc_data_end and qc_data_buf are used to track where the data q
	 * pointers should be set to when this command has completed (i.e. free
	 * up the space used by this command).  Not all commands use the data
	 * q so qc_data_used give us state on if this command uses the data q.
	 */
	boolean_t		qc_data_used;
	caddr_t			qc_data_end;
	uint_t			qc_data_buf;

	/*
	 * This is the node for the queued list.  Since AT requests finish in
	 * the order that they were submitted, we queue these up in a linked
	 * list so that it is easy to figure out which command has finished.
	 * Just look at the head of the list.
	 */
	hci1394_tlist_node_t	qc_node;
} hci1394_q_cmd_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_q_cmd_s::qc_status \
	hci1394_q_cmd_s::qc_timestamp))

typedef struct hci1394_q_bufptr_s {
	/*
	 * kernel virtual addresses.  The q may be broken down into multiple
	 * cookies.  The q is contiguous relative to the driver, but segmented
	 * relative to the 1394 HW DMA engines.
	 *
	 * qp_top is the top the q. qp_bottom is the bottom of the q. These
	 * never change after initial setup. qp_bottom is inclusive (i.e. for a
	 * q size of 16 bytes where top was = to 0, qp_bottom would be = to 15).
	 *
	 * qp_current and qp_free are pointers within top and bottom. qp_current
	 * refers to the next free space to write and free refers to the end of
	 * free space (i.e. used memory within q). qp_free is inclusive (see
	 * qp_bottom).
	 */
	caddr_t		qp_top;
	caddr_t		qp_bottom;
	caddr_t		qp_current;
	caddr_t		qp_free;

	/*
	 * qp_begin and qp_end are also kernel virtual addresses.  They are the
	 * beginning and ending address of the current_buf (cookie) within the
	 * q.  qp_offset is (qp_current - qp_begin). This is used to determine
	 * the 32 bit PCI address to put into the OpenHCI descriptor. We know
	 * the base PCI address from the cookie structure, we add offset to that
	 * to determine the correct PCI address.
	 */
	caddr_t		qp_begin;
	caddr_t		qp_end;
	uint32_t	qp_offset;

	/*
	 * As stated above, the q may be broken into multiple cookies.
	 * qp_current_buf is the cookie qp_current is in and qp_free_buf is the
	 * cookie qp_free is in.  NOTE: The cookie's are numbered 0, 1, 2, ...,
	 * (i.e. if we have 4 cookies, qp_current_buf can be 0, 1, 2, or 3)
	 */
	uint_t		qp_current_buf;
	uint_t		qp_free_buf;

	/*
	 * qp_resv_size is only used for the AT Q's.
	 * How much space has been reserved.  This value is set on the call to
	 * hci1394_q_reserve() and decremented each time a data is written.  It
	 * is used to check for overrun conditions. This extra check is in there
	 * as an added sanity check due to the complexity of this code.
	 */
	uint_t		qp_resv_size;
} hci1394_q_bufptr_t;


typedef struct hci1394_q_buf_s {
	/* pointers to track used/free space/cookies in the buffer */
	hci1394_q_bufptr_t	qb_ptrs;

	/*
	 * a backup of qb_ptrs. If we fail while setting up an AT Q, we need to
	 * cleanup by putting things back the way that they were.
	 */
	hci1394_q_bufptr_t	qb_backup_ptrs;

	/* copy of all of the cookie's structures for this buffer */
	ddi_dma_cookie_t	qb_cookie[OHCI_MAX_COOKIE];

	/* Buffer handle used for calls into hci1394_buf_* routines */
	hci1394_buf_handle_t	qb_buf_handle;

	/* Buffer info (i.e. cookie count, kaddr, ddi handles, etc.) */
	hci1394_buf_info_t	qb_buf;
} hci1394_q_buf_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_q_buf_s::qb_ptrs.qp_begin \
	hci1394_q_buf_s::qb_ptrs.qp_bottom \
	hci1394_q_buf_s::qb_ptrs.qp_current \
	hci1394_q_buf_s::qb_ptrs.qp_current_buf \
	hci1394_q_buf_s::qb_ptrs.qp_end \
	hci1394_q_buf_s::qb_ptrs.qp_offset \
	hci1394_q_buf_s::qb_ptrs.qp_top))

typedef struct hci1394_q_s {
	/*
	 * q_queued_list is only used in the AT descriptor Qs. AT commands
	 * complete in the order they were issued. We Q these commands up with
	 * each new command being added to the end of the list.  When a command
	 * completes, we look at the top of this list to determine which command
	 * completed.
	 */
	hci1394_tlist_handle_t	q_queued_list;

	/*
	 * pointer to general driver information (dip, instance, etc) and to
	 * handle for access to openHCI routines.
	 */
	hci1394_drvinfo_t	*q_drvinfo;
	hci1394_ohci_handle_t 	q_ohci;

	/*
	 * The OpenHCI DMA engines are basically just chained DMA engines. Each
	 * "link" in the chain is called a descriptor in OpenHCI.  When you want
	 * to add a new descriptor, you init the descriptor, setup its "next"
	 * pointer to "NULL", update the previous descriptor to point to the
	 * new descriptor, and tell the HW you added a new descriptor by setting
	 * its wake bit. q_previous is a pointer to the previous descriptor.
	 * When adding a new descriptor, we just de-reference q_previous to
	 * update its "next" pointer.
	 */
	hci1394_desc_t		*q_previous;

	/*
	 * When updating the "next" pointer in the previous descriptor block
	 * (as described above in q_previous), one of the things you need to
	 * tell the HW is how many 16 byte blocks the next descriptor block
	 * uses. This is what q_block_cnt is used for.  This is only used in the
	 * AT descriptor Q's.  Since the IM's used in the AR Q's are the only
	 * descriptor types used in AR, the block count is always the same for
	 * an AR descriptor Q.
	 */
	uint_t			q_block_cnt;

	/*
	 * q_head is only used in the AR descriptor Qs. It contains the location
	 * of the first descriptor on the Q.  This is used to look at the
	 * residual count in the AR data Q.  The residual count tells us if we
	 * have received any new packets to process. When a descriptor's data
	 * buffer is empty (q_space_left = 0), we move q_head to the next
	 * descriptor in the descriptor buffer.
	 */
	caddr_t			q_head;

	/*
	 * q_space_left is only used in the AR descriptor Qs. Each AR
	 * descriptor has residual count embedded in the descriptor which says
	 * how much free space is left in the descriptors associated data
	 * buffer. q_space_left is how much SW thinks is left in the data
	 * buffer.  When they do not match, we have a new packet(s) in the data
	 * buffer to process.  Since the residual count is not updated by the
	 * HW until the entire packet has been written to memory, we don't have
	 * to worry about any partial packet RX problems.
	 */
	uint_t			q_space_left;

	/*
	 * status of the dma controller.  This tells us if we should do a start
	 * or a wake.  If the dma engine is not running, we should start it. If
	 * it is running, we should wake it. When the DMA engine is started, it
	 * expects to have a valid descriptor to process.  Since we don't have
	 * anything to send in the beginning (AT), we have to wait until the
	 * first AT packet comes down before we can start the DMA engine.
	 */
	boolean_t		q_dma_running;

	/* The descriptor buffer for this Q */
	hci1394_q_buf_t		q_desc;

	/* The data buffer for this Q */
	hci1394_q_buf_t		q_data;

	/* copy of qinfo passed in during hci1394_q_init() */
	hci1394_q_info_t	q_info;

	kmutex_t		q_mutex;
} hci1394_q_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
        hci1394_q_s::q_dma_running \
	hci1394_q_s::q_head \
	hci1394_q_s::q_previous \
	hci1394_q_s::q_space_left))

/* handle passed back from init() and used for rest of functions */
typedef struct hci1394_q_s	*hci1394_q_handle_t;


int hci1394_q_init(hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t ohci_handle, hci1394_q_info_t *qinfo,
    hci1394_q_handle_t *q_handle);
void hci1394_q_fini(hci1394_q_handle_t *q_handle);
void hci1394_q_resume(hci1394_q_handle_t q_handle);
void hci1394_q_stop(hci1394_q_handle_t q_handle);

int hci1394_q_at(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, int *result);
int hci1394_q_at_with_data(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, uint8_t *data, uint_t datasize,
    int *result);
int hci1394_q_at_with_mblk(hci1394_q_handle_t q_handle, hci1394_q_cmd_t *cmd,
    hci1394_basic_pkt_t *hdr, uint_t hdrsize, h1394_mblk_t *mblk, int *result);
void hci1394_q_at_next(hci1394_q_handle_t q_handle, boolean_t flush_q,
    hci1394_q_cmd_t **cmd);

void hci1394_q_ar_next(hci1394_q_handle_t q_handle, uint32_t **q_addr);
void hci1394_q_ar_free(hci1394_q_handle_t q_handle, uint_t size);
uint32_t hci1394_q_ar_get32(hci1394_q_handle_t q_handle, uint32_t *addr);
void hci1394_q_ar_rep_get8(hci1394_q_handle_t q_handle, uint8_t *dest,
    uint8_t *q_addr, uint_t size);
void hci1394_q_ar_copy_to_mblk(hci1394_q_handle_t q_handle, uint8_t *addr,
    h1394_mblk_t *mblk);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_Q_H */
