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

#ifndef	_SYS_1394_ID1394_H
#define	_SYS_1394_ID1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * id1394.h
 *    Contains enums and structures used for managing a local isochronous
 *    DMA resource.
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/ixl1394.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * t1394_alloc_isoch_dma() is used to allocate a local isochronous
 * DMA resource for receiving or for transmitting isochronous data.
 * Upon successful allocation, the 1394 Framework returns a handle
 * of the type shown below. The target driver passes this handle back to
 * the 1394 Framework for all subsequent t1394_*_isoch_dma() calls
 * used to control the allocated resource.
 */
typedef struct isoch_dma_handle	*t1394_isoch_dma_handle_t;

/*
 * Target drivers use the id1394_isoch_dma_options_t enumerated type to
 * specify to t1394_alloc_isoch_dma() the desired characteristics of
 * the requested local isochronous DMA resource.
 * ID1394_TALK specifies an isochronous transmit DMA resource.
 * ID1394_LISTEN_PKT_MODE specifies an isochronous receive DMA resource in
 *    which each packet is received into its own (set of) buffer(s).
 * ID1394_LISTEN_BUF_MODE specifies an isochronous receive DMA resource in
 *    which packets may be concatenated into a single buffer.
 * ID1394_RECV_HEADERS specifies that isochronous packet header data for
 *    received isochronous packets are stored into the data buffers along
 *    with the packet data (otherwise the packet header is removed).
 */
typedef enum {
	ID1394_TALK			= (1 << 0),
	ID1394_LISTEN_PKT_MODE		= (1 << 1),
	ID1394_LISTEN_BUF_MODE		= (1 << 2),
	ID1394_RECV_HEADERS		= (1 << 3)
} id1394_isoch_dma_options_t;

/*
 * Enumerated type id1394_isoch_dma_stopped_t is a return argument to
 * the target's isoch_dma_stopped() callback.
 * Under a variety of circumstances, the local DMA resource may stop running.
 * If this occurs (independently of a target driver`s direct call to
 * t1394_stop_isoch_dma()), the target driver's isoch_dma_stopped callback is
 * invoked.  In this callback, the reason for the stop is indicated in the
 * id1394_isoch_dma_stopped_t enumerated type.  ID1394_DONE indicates the
 * isochronous DMA resource stopped because it reached the "end."
 * ID1394_FAIL indicates the isochronous DMA resource encountered an error.
 */
typedef enum {
	ID1394_DONE			= 1,
	ID1394_FAIL			= 2
} id1394_isoch_dma_stopped_t;

/*
 * Targets use id1394_isoch_dmainfo_t with t1394_alloc_isoch_dma() to specify
 * the desired characteristics of the local isochronous DMA resource.
 *
 * ixlp
 *	is the kernel virtual address of the first IXL program command.
 *	For IXL program command structures, see ixl1394.h.
 * channel_num
 *	is the isochronous channel number (0-63) for the allocated local
 *	isochronous DMA resource.  For an isochronous receive DMA resource,
 *	only packets with the specified channel number are received into the
 *	provided buffers.  For an isochronous transmit DMA resource, the
 *	1394 Framework constructs isochronous transmit packet headers using the
 *	specified channel number.
 * default_tag
 *	are the tag bits for the local isochronous DMA resource.
 *	For an isochronous receive DMA resource, only packets with the specified
 *	tag bits are received into the provided buffers.  For an isochronous
 *	transmit DMA resource, the 1394 Framework constructs isochronous
 *	transmit packet headers using the specified tag bits.
 * default_sync
 *	are the sync bits for the local isochronous DMA resource.  Usage is
 *	similar to that of default_tag above.
 * it_speed
 *	is used only for an isochronous transmit resource and indicates the
 *	speed at which the 1394 Framework shall transmit packets.  For valid
 *	speeds, see ieee1394.h.
 * global_callback_arg
 *	is the argument the 1394 Framework provides to the target when invoking
 *	a callback specified in an ixl1394_callback_t IXL command or an IXL
 *	program. Target drivers can use this to track state or any other
 *	information.  See ixl1394.h for IXL command info.
 * it_default_skip
 *	is used for isochronous transmit DMA resources only and specifies the
 *	default skip mode for the resource.  See ixl1394.h for valid skip modes.
 * it_default_skiplabel
 *	is used for isochronous transmit DMA resources only, and when
 *	it_default_skip is IXL1394_SKIP_TO_LABEL.  It contains a pointer to
 *	the targetted IXL Label command.
 * idma_options
 *	is used to specify the overall transmit or receive characteristics
 *	of the requested local isochronous DMA resource.
 * isoch_dma_stopped
 *	is the target driver's callback routine the 1394 Framework is to
 *	invoke if the local isochronous DMA resource stops.
 * idma_evt_arg
 *	is the target driver's callback argument to be handed back to the target
 *	driver when the 1394 Framework invokes the isoch_dma_stopped() callback.
 */
typedef struct id1394_isoch_dmainfo_s {
	ixl1394_command_t		*ixlp;		/* 1st IXL command */
	uint_t				channel_num;	/* isoch channel */
	uint_t				default_tag;	/* tag */
	uint_t				default_sync;	/* sync */
	uint_t				it_speed;	/* speed - xmit only */
	void				*global_callback_arg;
	ixl1394_skip_t			it_default_skip; /* skip - xmit only */
	ixl1394_command_t		*it_default_skiplabel;
	id1394_isoch_dma_options_t	idma_options;	/* I/O type */

	void	(*isoch_dma_stopped)(t1394_isoch_dma_handle_t t1394_idma_hdl,
		    opaque_t idma_evt_arg,
		    id1394_isoch_dma_stopped_t idma_stop_args);
	opaque_t			idma_evt_arg;
} id1394_isoch_dmainfo_t;

/*
 * Target drivers supply the id1394_isoch_dma_ctrlinfo_t structure to the
 * t1394_start_isoch_dma() call to indicate the cycle at which the local
 * isochronous DMA resource is to start receiving or transmitting packets.
 */
typedef struct id1394_isoch_dma_ctrlinfo_s {
	uint_t				start_cycle;
} id1394_isoch_dma_ctrlinfo_t;

/*
 * t1394_start_isoch_dma() flags.
 * ID1394_START_ON_CYCLE - if specified, this flag indicates that the local
 *    isochronous DMA resource is to start receiving or transmitting packets
 *    at the cycle time specified in id1394_isoch_dma_ctrlinfo_t.
 *    If not specified, the isochronous DMA resource starts receiving or
 *    transmitting packets as soon as possible.
 */
#define	ID1394_START_ON_CYCLE	    0x00000001	/* start on specified cycle */

/*
 * Target drivers use the id1394_isoch_dma_updateinfo_t structure to provide
 * information to t1394_update_isoch_dma(), which dynamically updates an IXL
 * program for an allocated local isochronous DMA resource.  See ixl1394.h
 * for information on IXL program commands.
 * temp_ixlp
 *	points to the first new IXL command used to update an existing IXL
 *	command.
 * orig_ixlp
 *	points to the original IXL command to be updated.
 * ixl_count
 *	is the number of IXL commands to be updated.
 */
typedef struct id1394_isoch_dma_updateinfo_s {
	ixl1394_command_t		*temp_ixlp; /* first new IXL cmd */
	ixl1394_command_t		*orig_ixlp; /* first updated IXL cmd */
	uint_t				ixl_count;  /* length of update chain */
} id1394_isoch_dma_updateinfo_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ID1394_H */
