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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_ISOCH_H
#define	_SYS_1394_ADAPTERS_HCI1394_ISOCH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_isoch.h
 *    Function declarations for front-end functions for hci1394 isochronous
 *    support.  Also all isochronous related soft_state structures and defs.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/1394/adapters/hci1394_def.h>


/* handle passed back from init() and used for rest of functions */
typedef	struct hci1394_isoch_s	*hci1394_isoch_handle_t;

/*
 * Isochronous structures and defs used in the hci1394 soft state.
 * (see hci1394_state.h).
 */

/*
 * control structure for allocated isochronous dma descriptor memory.
 * when attempting to bind memory, if ddi_addr_bind_handle indicates multiple
 * cookies, each cookie will be tracked within a separate copy of this
 * structure. Only the last cookie's idma_desc_mem structure will contain
 * a valid mem_handle and mem, to be used when freeing all the memory.
 *
 * 'used' specifies the number of bytes used for descriptors in this cookie.
 * 'offset' is this cookie's offset relative to the beginning of the buffer.
 */
typedef struct hci1394_idma_desc_mem_s {
	struct hci1394_idma_desc_mem_s	*dma_nextp;
	hci1394_buf_handle_t		mem_handle;
	hci1394_buf_info_t		mem;
	uint32_t			used;
	uint32_t			offset;
} hci1394_idma_desc_mem_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_idma_desc_mem_s))

/* structure to track one isochronous context */
/* XXX if IR Multichan mode support is added, this must be modified */
typedef struct hci1394_iso_ctxt_s {
	int	    ctxt_index;		/* 0-31 -- which context this is */
	int	    ctxt_io_mode;	/* xmit, recv pkt or buf, hdrs, multi */
	uint32_t    ctxt_flags;		/* general context info */
	volatile uint32_t    intr_flags; /* flags while context is running */
	kmutex_t    intrprocmutex;	/* interrupt/update coordination */
	kcondvar_t  intr_cv;		/* interrupt completion cv */
	uint16_t    isospd;		/* speed of packets for context */
	uint16_t    isochan;		/* isochronous channel for contxt */

	hci1394_ctxt_regs_t *ctxt_regsp; /* ctxt regs within hci1394_regs_t */

	void	    *xcs_firstp;	/* first alloc xfer_ctl_t struct */
	hci1394_idma_desc_mem_t *dma_firstp; /* 1st alloc dma descriptor mem */
	uint32_t    dma_mem_execp;	/* exec start(bound mem w/Z bits) */
	uint32_t    reserved;

	ixl1394_command_t *ixl_firstp;	/* 1st ixl cmmand in linked list */
	ixl1394_command_t *ixl_execp;	/* currently executing ixl cmmand */
	uint_t	    ixl_exec_depth;	/* curr exec ixl cmd xfer_ctl idx */

	uint_t	    max_dma_skips;	/* max skips allowed before xmit */
					/* recovery required (16 => 2ms) */
	uint_t	    max_noadv_intrs;	/* max intrs with no dma descriptor */
					/* block advances (8) */
	uint_t	    rem_noadv_intrs;	/* remaining intrs allowed with no */
					/* dma advances (i.e. no status set) */

	uint16_t    dma_last_time;	/* last completd desc blk tmestmp */

	uint16_t    default_tag;	/* default tag value  */
	uint16_t    default_sync;	/* default sync value */
	uint16_t    default_skipmode;	/* default skip mode  */

	ixl1394_command_t *default_skiplabelp; /* set if needed */
	ixl1394_command_t *default_skipxferp; /* xfercmd for default skiplabl */

	void	    *global_callback_arg;   /* provided to IXLcallbacks */
	opaque_t    idma_evt_arg;	    /* provided to "stopped" callback */

	/* target callback if dma stops */
	void (*isoch_dma_stopped)(struct isoch_dma_handle *idma_hdl,
	    opaque_t idma_evt_arg, id1394_isoch_dma_stopped_t idma_stop_args);

} hci1394_iso_ctxt_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_iso_ctxt_s))

/*
 * defs for hci1394_iso_ctxt_t.ctxt_io_mode.
 * overall io characteristics of the contexts, initialized during isoch init
 * and never changed.
 */
/*
 * defs for hci1394_iso_ctxt_t.ctxt_flags
 * These flags are protected by the context list mutex in the isoch handle
 * (see hci1394_isoch.c for mutex definition)
 */
#define	HCI1394_ISO_CTXT_INUSE	    0x00000001 /* context is in use */
#define	HCI1394_ISO_CTXT_RUNNING    0x00000002 /* context is running */
#define	HCI1394_ISO_CTXT_RECV	    0x00000004 /* isoch receive context */
#define	HCI1394_ISO_CTXT_CMDREG	    0x00000008 /* dev has readable dma cmdptr */
#define	HCI1394_ISO_CTXT_BFFILL	    0x00000010 /* on=BufFill off=Pkt IR only */
#define	HCI1394_ISO_CTXT_RHDRS	    0x00000020 /* recv packet hdrs into mem */
#define	HCI1394_ISO_CTXT_MULTI	    0x00000040 /* in multichan mode - IR only */

/*
 * defs for hci1394_iso_ctxt_t.intr_flags
 * These flags are protected by the per-context mutex "intrprocmutex"
 */
#define	HCI1394_ISO_CTXT_STOP	    0x00000010 /* context stopped */
#define	HCI1394_ISO_CTXT_INTRSET    0x00000020 /* intr flagged, not processed */
#define	HCI1394_ISO_CTXT_ININTR	    0x00000040 /* in intrproc, not due to int */
#define	HCI1394_ISO_CTXT_INUPDATE   0x00000080 /* in intrproc, not due to int */
#define	HCI1394_ISO_CTXT_INCALL	    0x00000100 /* intrproc is doing callback */

/*
 * structure used to do accounting for interrupt usage.  Specifically,
 * used to determine when CYCLE_LOST or CYCLE_INCONSISTENT storms
 * should cause us to disable those interrupts.
 */
typedef struct hci1394_intr_thresh_s {
	hrtime_t	last_intr_time;
	hrtime_t	delta_t_thresh;
	int		delta_t_counter;
	int		counter_thresh;
} hci1394_intr_thresh_t;

/* defs for the hci1394_intr_thresh_t struct */
#define	HCI1394_CYC_LOST_DELTA		400000;		/* 400ms */
#define	HCI1394_CYC_LOST_COUNT		25;
#define	HCI1394_CYC_INCON_DELTA		400000;		/* 400ms */
#define	HCI1394_CYC_INCON_COUNT		25;

/*
 * Structure used for tracking all transmit and receive isochronous contexts
 * Also contains the information necessary for tracking CYCLE_LOST and
 * CYCLE_INCONSISTENT interrupt usage.
 * The ctxt_list mutex protects the in-use status of the contexts while
 * searching for a free isoch context to use in hci1394_alloc_isoch_dma(),
 * during interrupt processing, and during free_isoch_dma processing.
 * An openHCI 1.0 hardware implementation may support up to 32 separate DMA
 * engines each for transmit and receive, referred to as "contexts".
 * The number of supported contexts is determined during ohci board
 * initialization, and can be different for transmit vs. receive.
 */
typedef struct hci1394_isoch_s {
	hci1394_intr_thresh_t	cycle_lost_thresh;
	hci1394_intr_thresh_t	cycle_incon_thresh;
	int			isoch_dma_alloc_cnt;
	int			unused;
	int			ctxt_xmit_count;
	int			ctxt_recv_count;
	hci1394_iso_ctxt_t	ctxt_xmit[HCI1394_MAX_ISOCH_CONTEXTS];
	hci1394_iso_ctxt_t	ctxt_recv[HCI1394_MAX_ISOCH_CONTEXTS];
	kmutex_t		ctxt_list_mutex;
} hci1394_isoch_t;


void hci1394_isoch_init(hci1394_drvinfo_t *drvinfo,  hci1394_ohci_handle_t ohci,
    hci1394_isoch_handle_t *isoch_hdl);
void hci1394_isoch_fini(hci1394_isoch_handle_t *isoch_hdl);
void hci1394_isoch_cycle_inconsistent(hci1394_state_t *soft_statep);
void hci1394_isoch_cycle_lost(hci1394_state_t *soft_statep);
int hci1394_isoch_resume(hci1394_state_t *soft_statep);
void hci1394_isoch_error_ints_enable(hci1394_state_t *soft_statep);

int hci1394_isoch_recv_count_get(hci1394_isoch_handle_t isoch_hdl);
hci1394_iso_ctxt_t *hci1394_isoch_recv_ctxt_get(hci1394_isoch_handle_t
    isoch_hdl, int num);
int hci1394_isoch_xmit_count_get(hci1394_isoch_handle_t isoch_hdl);
hci1394_iso_ctxt_t *hci1394_isoch_xmit_ctxt_get(hci1394_isoch_handle_t
    isoch_hdl, int num);


int hci1394_alloc_isoch_dma(void *hal_private, id1394_isoch_dmainfo_t *idi,
    void **hal_idma_handle, int	*resultp);
void hci1394_free_isoch_dma(void *hal_private, void *hal_isoch_dma_handle);
int hci1394_start_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    id1394_isoch_dma_ctrlinfo_t *idma_ctrlinfo, uint_t flags, int *resultp);
int hci1394_update_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    id1394_isoch_dma_updateinfo_t *idma_updateinfop, uint_t flags,
    int *resultp);
void hci1394_stop_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    int *resultp);
void hci1394_do_stop(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    boolean_t do_callback, id1394_isoch_dma_stopped_t stop_args);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_ISOCH_H */
